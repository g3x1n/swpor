#!/usr/bin/env python3
"""
swpor 本机 Web 控制台后端（SPEC 9.5）。只用 Python 标准库。

后端以子进程方式调用 porctl / porta / pord（参数列表，不经过 shell），一律加 --json，
porctl 另加 --trace -，把程序的实际输出转发给浏览器；不链接 libswpor，也不实现任何算法。

用法：
  python3 ui/server.py --bin build/debug/apps --workspace ~/swpor-ws [--port 8787]
                       [--max-upload 1024] [--open]

安全（SPEC 9.5）：
  - 只监听 127.0.0.1；
  - 每个 /api/ 请求必须带 X-Swpor-Token 头（启动时随机生成，常数时间比较）；
  - Host 头必须是 127.0.0.1:<port> 或 localhost:<port>，带 Origin 头时必须同源；
  - 只能访问工作区固定子目录中的文件，拒绝路径穿越；私钥文件内容不会发送给浏览器。
"""

import argparse
import hmac
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(HERE, "web")

SUBDIRS = ("keys", "data", "tags", "store", "srv", "out", "logs")
MAX_RUNNING_JOBS = 4
MAX_KEPT_JOBS = 200
MAX_EVENTS = 4000
MAX_LINES = 2000
MAX_JSON_BODY = 64 * 1024

# 退出码含义（SPEC 9.2）
EXIT_MEANING = {
    0: "成功",
    1: "审计 FAIL",
    2: "参数错误",
    3: "I/O 错误",
    4: "网络错误",
    5: "密码学 / 格式错误",
}

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}

# 文件名：允许中文和空格（T-26）；拒绝路径分隔符、控制字符与 Windows 不允许的字符
_BAD_NAME = re.compile(r'[\x00-\x1f\x7f/\\:*?"<>|]')
_ADDR = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.\-]{1,253}):([0-9]{1,5})$")
_RS = re.compile(r"^([0-9]{1,3}):([0-9]{1,3})$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ApiError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status
        self.msg = msg


def valid_name(name):
    return (isinstance(name, str) and 0 < len(name) <= 200 and name not in (".", "..")
            and not _BAD_NAME.search(name) and name == name.strip() and not name.startswith("."))


def find_exe(bindir, name):
    for cand in (name, name + ".exe", os.path.join("Debug", name + ".exe"),
                 os.path.join("Release", name + ".exe")):
        p = os.path.join(bindir, cand)
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def tail_lines(path, n):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 64 * 1024))
            data = f.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    return data.splitlines()[-n:]


# ===================================================================== #
# 工作区                                                                 #
# ===================================================================== #

class Workspace:
    def __init__(self, root):
        os.makedirs(root, exist_ok=True)
        self.root = os.path.realpath(root)
        for d in SUBDIRS:
            os.makedirs(os.path.join(self.root, d), exist_ok=True)
        self.meta_path = os.path.join(self.root, "logs", "console.json")
        self.lock = threading.Lock()
        self.reserved = set()
        try:
            with open(self.meta_path, "r", encoding="utf-8") as f:
                self.meta = json.load(f)
            if not isinstance(self.meta, dict):
                self.meta = {}
        except (OSError, ValueError):
            self.meta = {}

    def abs(self, rel):
        return os.path.join(self.root, *rel.split("/"))

    def resolve(self, rel, subdirs, depth=(1,), must_exist=True):
        """把 "子目录/名称[/名称]" 解析为工作区内的绝对路径；任何不合规的输入都拒绝"""
        if not isinstance(rel, str):
            raise ApiError(400, "路径必须是字符串")
        parts = rel.split("/")
        if parts[0] not in subdirs or len(parts) - 1 not in depth:
            raise ApiError(400, f"不允许的路径：{rel}")
        for p in parts[1:]:
            if not valid_name(p):
                raise ApiError(400, f"非法名称：{p!r}")
        path = self.abs(rel)
        real = os.path.realpath(path)
        if not real.startswith(self.root + os.sep):
            raise ApiError(400, f"路径逃出工作区：{rel}")
        if must_exist and not os.path.exists(real):
            raise ApiError(404, f"不存在：{rel}")
        return real

    def unique(self, subdir, base, suffix=""):
        """在子目录中选一个不存在、也未被并发任务预留的名称"""
        with self.lock:
            for i in range(1, 1000):
                name = f"{base}{suffix}" if i == 1 else f"{base}-{i}{suffix}"
                rel = f"{subdir}/{name}"
                if not os.path.exists(self.abs(rel)) and rel not in self.reserved:
                    self.reserved.add(rel)
                    return rel
        raise ApiError(409, "无法选择不重复的文件名")

    def release(self, rel):
        with self.lock:
            self.reserved.discard(rel)

    def set_meta(self, tag_rel, value):
        with self.lock:
            if value is None:
                self.meta.pop(tag_rel, None)
            else:
                self.meta[tag_rel] = value
            tmp = self.meta_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.meta, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self.meta_path)

    def get_meta(self, tag_rel):
        with self.lock:
            return dict(self.meta.get(tag_rel, {}))

    def list_files(self, subdir):
        out = []
        d = os.path.join(self.root, subdir)
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if valid_name(name) and os.path.isfile(p) and not os.path.islink(p):
                st = os.stat(p)
                out.append({"name": name, "path": f"{subdir}/{name}", "size": st.st_size,
                            "mtime": int(st.st_mtime)})
        return out


KEY_KINDS = {"priv.key": "priv", "pub.sk": "pub_sk", "pub.pk": "pub_pk"}


# ===================================================================== #
# 任务：一个子进程及其输出                                               #
# ===================================================================== #

class Job:
    _next = 1
    _id_lock = threading.Lock()

    def __init__(self, kind, title, argv, display, cwd, on_exit=None):
        with Job._id_lock:
            self.id = Job._next
            Job._next += 1
        self.kind = kind
        self.title = title
        self.argv = argv
        self.display = display
        self.cwd = cwd
        self.on_exit = on_exit
        self.lock = threading.Lock()
        self.status = "running"
        self.exit_code = None
        self.started = time.time()
        self.ended = None
        self.outputs = []   # stdout 中的 JSON 行（--json 结果）
        self.events = []    # stderr 中的 trace 事件（SPEC 9.4）
        self.log = []       # 其他输出行（错误信息等）
        self.extra = {}     # 任务结束后补充的信息（如下载路径）
        self.proc = None
        self._tag_n = 0
        self._tag_seen = 0

    # trace 中 tag_block 每块一个事件；只保留约 50 个进度点，避免大文件撑爆内存
    def _add_event(self, ev):
        t = ev.get("type")
        if t == "file_split":
            self._tag_n = int(ev.get("n", 0) or 0)
        if t == "tag_block":
            self._tag_seen += 1
            step = max(1, self._tag_n // 50)
            i = int(ev.get("i", 0) or 0)
            if self._tag_n and (i + 1) % step != 0 and i + 1 != self._tag_n:
                return
        if len(self.events) < MAX_EVENTS:
            ev["t_ms"] = round((time.time() - self.started) * 1000, 1)
            self.events.append(ev)

    def _reader(self, stream, is_stdout):
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if not line:
                continue
            obj = None
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except ValueError:
                    obj = None
            with self.lock:
                if is_stdout and isinstance(obj, dict):
                    if len(self.outputs) < MAX_LINES:
                        self.outputs.append(obj)
                elif not is_stdout and isinstance(obj, dict) and "type" in obj:
                    self._add_event(obj)
                elif len(self.log) < MAX_LINES:
                    self.log.append(line)
        stream.close()

    def start(self):
        kw = {}
        if os.name == "nt":
            kw["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            self.proc = subprocess.Popen(self.argv, cwd=self.cwd, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
        except OSError as e:
            self.status = "error"
            self.log.append(f"无法启动：{e}")
            self.ended = time.time()
            if self.on_exit:
                self.on_exit(self)
            return
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        proc = self.proc
        assert proc is not None and proc.stdout is not None and proc.stderr is not None
        t1 = threading.Thread(target=self._reader, args=(proc.stdout, True), daemon=True)
        t2 = threading.Thread(target=self._reader, args=(proc.stderr, False), daemon=True)
        t1.start()
        t2.start()
        code = proc.wait()
        t1.join()
        t2.join()
        with self.lock:
            self.exit_code = code
            if self.status == "running":
                self.status = "exited"
        if self.on_exit:
            try:
                self.on_exit(self)
            except Exception as e:  # 回调失败不影响任务记录
                with self.lock:
                    self.log.append(f"后处理失败：{e}")
        with self.lock:
            self.ended = time.time()

    def cancel(self):
        with self.lock:
            if self.status != "running" or self.proc is None:
                return False
            self.status = "cancelled"
        self.proc.terminate()
        return True

    def snapshot(self, full=True):
        with self.lock:
            done = self.ended is not None
            d = {
                "id": self.id, "kind": self.kind, "title": self.title,
                "status": self.status if done or self.status != "exited" else "running",
                "exit_code": self.exit_code if done else None,
                "exit_meaning": EXIT_MEANING.get(self.exit_code, "未知错误") if done
                and self.exit_code is not None else None,
                "started": self.started, "ended": self.ended,
                "elapsed_ms": round(((self.ended or time.time()) - self.started) * 1000, 1),
                "result": self._result(),
            }
            if full:
                d.update(command=self.display, outputs=list(self.outputs),
                         events=list(self.events), log=list(self.log), extra=dict(self.extra),
                         tag_blocks=self._tag_seen)
            return d

    def _result(self):
        rs = [o.get("result") for o in self.outputs if isinstance(o.get("result"), str)]
        if not rs:
            return None
        if "FAIL" in rs:
            return "FAIL"
        if "ERROR" in rs:
            return "ERROR"
        return rs[-1]


# ===================================================================== #
# 应用：任务调度、pord 管理、API 实现                                    #
# ===================================================================== #

class Console:
    def __init__(self, bindir, ws, max_upload):
        self.ws = ws
        self.max_upload = max_upload
        self.exe = {n: find_exe(bindir, n) for n in ("porctl", "porta", "pord")}
        porctl = self.exe["porctl"]
        if porctl is None:
            raise SystemExit(f"在 {bindir} 下找不到 porctl")
        self.porctl_exe = porctl
        self.jobs = []
        self.jobs_lock = threading.Lock()
        self.pord = None
        self.pord_info = {}
        self.pord_lock = threading.Lock()
        self.info_cache = {}
        self.version = self._version()

    def _version(self):
        try:
            p = subprocess.run([self.porctl_exe, "version"], capture_output=True, timeout=10)
            first = p.stdout.decode("utf-8", errors="replace").splitlines()[0]
            return first.split()[-1]
        except (OSError, IndexError, subprocess.SubprocessError):
            return "?"

    # ---- 任务 ----

    def _display(self, argv):
        """展示用的命令行：可执行文件只留名字，工作区路径改为相对路径"""
        out = []
        for i, a in enumerate(argv):
            if i == 0:
                a = os.path.splitext(os.path.basename(a))[0]
            elif a.startswith(self.ws.root + os.sep):
                a = os.path.relpath(a, self.ws.root).replace(os.sep, "/")
            out.append(a)
        return out

    def submit(self, kind, title, argv, on_exit=None):
        with self.jobs_lock:
            running = sum(1 for j in self.jobs if j.ended is None)
            if running >= MAX_RUNNING_JOBS:
                raise ApiError(429, f"同时运行的任务已达上限（{MAX_RUNNING_JOBS}）")
            job = Job(kind, title, argv, self._display(argv), self.ws.root, on_exit)
            self.jobs.append(job)
            if len(self.jobs) > MAX_KEPT_JOBS:
                self.jobs = [j for j in self.jobs if j.ended is None] + \
                    [j for j in self.jobs if j.ended is not None][-MAX_KEPT_JOBS:]
        job.start()
        return job

    def get_job(self, jid):
        with self.jobs_lock:
            for j in self.jobs:
                if j.id == jid:
                    return j
        raise ApiError(404, "没有这个任务")

    def shutdown(self):
        with self.jobs_lock:
            jobs = list(self.jobs)
        for j in jobs:
            j.cancel()
        self.stop_pord()

    # ---- 参数辅助 ----

    def porctl(self, *args, trace=True):
        """porctl 命令行；store / audit / retrieve / tamper 支持 --trace（写到 stderr）"""
        argv = [self.porctl_exe, *args, "--json"]
        return argv + ["--trace", "-"] if trace else argv

    def target_args(self, body, local_dir="store"):
        target = body.get("target", "local")
        if target == "local":
            return ["--local", self.ws.abs(local_dir)], {"target": "local"}
        if target == "remote":
            addr = body.get("server", "")
            m = _ADDR.match(addr) if isinstance(addr, str) else None
            if not m or not 1 <= int(m.group(2)) <= 65535:
                raise ApiError(400, "服务端地址格式应为 host:port")
            args = ["--server", addr]
            if "timeout" in body:
                args += ["--timeout", str(int_arg(body, "timeout", 100, 600000))]
            return args, {"target": "remote", "server": addr}
        raise ApiError(400, "target 只能是 local 或 remote")

    def key_path(self, rel, kinds):
        path = self.ws.resolve(rel, ("keys",), depth=(2,))
        kind = KEY_KINDS.get(os.path.basename(path))
        if kind not in kinds:
            raise ApiError(400, "这里不能使用该类型的密钥文件")
        return path

    # ---- 状态 ----

    def tag_info(self, path):
        st = os.stat(path)
        key = (path, st.st_mtime_ns, st.st_size)
        hit = self.info_cache.get(path)
        if hit and hit[0] == key:
            return hit[1]
        try:
            p = subprocess.run([self.porctl_exe, "info", "--tag", path, "--json"],
                               capture_output=True, timeout=20)
            info = json.loads(p.stdout.decode("utf-8", errors="replace").strip().splitlines()[-1])
        except (OSError, ValueError, IndexError, subprocess.SubprocessError):
            info = {"error": "无法解析标签"}
        self.info_cache[path] = (key, info)
        return info

    def state(self):
        ws = self.ws
        keys = []
        kdir = os.path.join(ws.root, "keys")
        for d in sorted(os.listdir(kdir)):
            full = os.path.join(kdir, d)
            if not valid_name(d) or not os.path.isdir(full) or os.path.islink(full):
                continue
            files = [{"name": f, "path": f"keys/{d}/{f}", "kind": KEY_KINDS[f]}
                     for f in sorted(os.listdir(full)) if f in KEY_KINDS]
            if files:
                scheme = "priv" if any(f["kind"] == "priv" for f in files) else "pub"
                keys.append({"name": d, "scheme": scheme, "files": files})
        tags = []
        for f in ws.list_files("tags"):
            if not f["name"].endswith(".tag"):
                continue
            f["info"] = self.tag_info(ws.abs(f["path"]))
            f["meta"] = ws.get_meta(f["path"])
            fid = f["info"].get("file_id", "")
            f["local_stored"] = bool(_HEX64.match(fid)) and os.path.isdir(
                os.path.join(ws.root, "store", fid))
            tags.append(f)
        return {
            "version": self.version,
            "platform": sys.platform,
            "workspace": ws.root,
            "programs": {k: v is not None for k, v in self.exe.items()},
            "max_upload": self.max_upload,
            "keys": keys,
            "data": ws.list_files("data"),
            "tags": tags,
            "out": ws.list_files("out"),
            "server": self.pord_status(),
        }

    # ---- pord ----

    def pord_status(self):
        with self.pord_lock:
            p = self.pord
            info = dict(self.pord_info)
        running = p is not None and p.poll() is None
        st: dict = {"available": self.exe["pord"] is not None, "running": running}
        if info:
            st.update(info)
            if p is not None and not running:
                st["exit_code"] = p.returncode
        st["log"] = tail_lines(self.ws.abs("logs/pord.log"), 40)
        evs = []
        for line in tail_lines(self.ws.abs("logs/pord.trace.ndjson"), 40):
            try:
                evs.append(json.loads(line))
            except ValueError:
                pass
        st["events"] = evs
        srv = os.path.join(self.ws.root, "srv")
        st["files"] = sorted(d for d in os.listdir(srv) if _HEX64.match(d))
        return st

    def start_pord(self, body):
        pord_exe = self.exe["pord"]
        if pord_exe is None:
            raise ApiError(400, "本平台没有 pord（Windows 只做客户端，SPEC 2.1）")
        with self.pord_lock:
            if self.pord is not None and self.pord.poll() is None:
                raise ApiError(409, "pord 已在运行")
            port = int_arg(body, "port", 0, 65535, default=0) or free_port()
            threads = int_arg(body, "threads", 1, 64, default=4)
            addr = f"127.0.0.1:{port}"
            argv = [pord_exe, "--listen", addr, "--data-dir", self.ws.abs("srv"),
                    "--threads", str(threads), "--log", self.ws.abs("logs/pord.log"),
                    "--trace", self.ws.abs("logs/pord.trace.ndjson")]
            errlog = open(self.ws.abs("logs/pord.stderr.log"), "ab")
            try:
                self.pord = subprocess.Popen(argv, cwd=self.ws.root, stdin=subprocess.DEVNULL,
                                             stdout=errlog, stderr=errlog)
            finally:
                errlog.close()
            self.pord_info = {"address": addr, "threads": threads, "pid": self.pord.pid,
                              "started": time.time(), "command": self._display(argv)}
            proc = self.pord
        for _ in range(50):
            if proc.poll() is not None:
                raise ApiError(500, "pord 启动失败，见 logs/pord.stderr.log")
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        return self.pord_status()

    def stop_pord(self):
        with self.pord_lock:
            p = self.pord
        if p is not None and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        return self.pord_status()

    # ---- 各操作 ----

    def api_keygen(self, b):
        scheme = b.get("scheme")
        if scheme not in ("priv", "pub"):
            raise ApiError(400, "scheme 只能是 priv 或 pub")
        name = b.get("name") or f"{scheme}-key"
        if not valid_name(name):
            raise ApiError(400, "非法名称")
        rel = self.ws.unique("keys", name)
        argv = self.porctl("keygen", "--scheme", scheme, "--out", self.ws.abs(rel), trace=False)
        return self.submit("keygen", f"生成 {scheme} 密钥 {rel}", argv,
                           lambda j: self.ws.release(rel))

    def api_store(self, b):
        key = self.key_path(b.get("key"), ("priv", "pub_sk"))
        inp = self.ws.resolve(b.get("input"), ("data",))
        tgt, meta = self.target_args(b)
        args = ["store", "--key", key, "--in", inp]
        if "s" in b:
            args += ["--s", str(int_arg(b, "s", 1, 65535))]
        rs = b.get("rs", "")
        if rs == "none":
            args.append("--no-rs")
        elif rs:
            if not isinstance(rs, str) or not _RS.match(rs):
                raise ApiError(400, "RS 参数格式应为 k:m")
            args += ["--rs", rs]
        for flag in ("perm", "encrypt"):
            if b.get(flag):
                args.append("--" + flag)
        tag_rel = self.ws.unique("tags", os.path.basename(inp), ".tag")
        args += ["--tag-out", self.ws.abs(tag_rel)] + tgt
        meta.update(key=b.get("key"), input=b.get("input"), stored=int(time.time()))

        def done(job):
            self.ws.release(tag_rel)
            if job.exit_code == 0 and os.path.exists(self.ws.abs(tag_rel)):
                self.ws.set_meta(tag_rel, meta)
                job.extra["tag"] = tag_rel

        return self.submit("store", f"存储 {b.get('input')}", self.porctl(*args), done)

    def api_audit(self, b):
        key = self.key_path(b.get("key"), ("priv", "pub_sk", "pub_pk"))
        tag = self.ws.resolve(b.get("tag"), ("tags",))
        tgt, _ = self.target_args(b)
        args = ["audit", "--key", key, "--tag", tag] + tgt
        if "l" in b:
            args += ["--l", str(int_arg(b, "l", 1, 1_000_000))]
        if b.get("seed_mode"):
            args.append("--seed-mode")
        return self.submit("audit", f"审计 {b.get('tag')}", self.porctl(*args))

    def api_porta(self, b):
        porta_exe = self.exe["porta"]
        if porta_exe is None:
            raise ApiError(400, "没有构建 porta")
        pk = self.key_path(b.get("pk"), ("pub_pk",))
        tags = b.get("tags")
        if not isinstance(tags, list) or not 1 <= len(tags) <= 64:
            raise ApiError(400, "请选择 1～64 个标签")
        paths = []
        for t in tags:
            p = self.ws.resolve(t, ("tags",))
            if "," in p:
                raise ApiError(400, "porta 的标签路径不能含逗号")
            paths.append(p)
        tgt, _ = self.target_args(b)
        argv = [porta_exe, "--pk", pk, "--tag", ",".join(paths)] + tgt + [
            "--json", "--log", self.ws.abs("logs/porta.log"),
            "--count", str(int_arg(b, "count", 0, 100000, default=1)),
            "--interval", str(int_arg(b, "interval", 0, 86400, default=0))]
        if "l" in b:
            argv += ["--l", str(int_arg(b, "l", 1, 1_000_000))]
        if b.get("explicit"):
            argv.append("--explicit")
        return self.submit("porta", f"第三方审计 {len(paths)} 个文件", argv)

    def api_retrieve(self, b):
        key = self.key_path(b.get("key"), ("priv", "pub_sk", "pub_pk"))
        tag_rel = b.get("tag")
        tag = self.ws.resolve(tag_rel, ("tags",))
        tgt, _ = self.target_args(b)
        meta = self.ws.get_meta(tag_rel)
        base = os.path.basename(meta.get("input", "")) or os.path.basename(tag)[:-4]
        out_rel = self.ws.unique("out", "恢复-" + base)
        argv = self.porctl("retrieve", "--key", key, "--tag", tag, "--out", self.ws.abs(out_rel),
                           *tgt)

        def done(job):
            self.ws.release(out_rel)
            if job.exit_code == 0 and os.path.exists(self.ws.abs(out_rel)):
                job.extra["out"] = out_rel

        return self.submit("retrieve", f"恢复 {tag_rel}", argv, done)

    def api_delete(self, b):
        tag_rel = b.get("tag")
        tag = self.ws.resolve(tag_rel, ("tags",))
        tgt, _ = self.target_args(b)
        return self.submit("delete", f"删除存储 {tag_rel}",
                           self.porctl("delete", "--tag", tag, *tgt, trace=False))

    def api_tamper(self, b):
        tag = self.ws.resolve(b.get("tag"), ("tags",))
        fid = self.tag_info(tag).get("file_id", "")
        if not _HEX64.match(fid) or not os.path.isdir(os.path.join(self.ws.root, "store", fid)):
            raise ApiError(400, "该文件不在本地存储中，只能篡改本地存储（SPEC 9.2）")
        mode = b.get("mode")
        if mode not in ("flip", "zero", "delete"):
            raise ApiError(400, "mode 只能是 flip、zero 或 delete")
        ratio = b.get("ratio")
        if not isinstance(ratio, (int, float)) or isinstance(ratio, bool) or not 0 <= ratio <= 1:
            raise ApiError(400, "ratio 应在 0～1 之间")
        args = ["tamper", "--local", self.ws.abs("store"), "--file-id", fid, "--mode", mode,
                "--ratio", repr(float(ratio))]
        if b.get("seed") not in (None, ""):
            args += ["--seed", str(int_arg(b, "seed", 0, 2**63 - 1))]
        return self.submit("tamper", f"篡改 {b.get('tag')}（{mode}，{ratio}）", self.porctl(*args))

    def api_doctor(self, b):
        return self.submit("doctor", "自检 porctl doctor", self.porctl("doctor", trace=False))

    def api_remove(self, b):
        rel = b.get("path")
        if isinstance(rel, str) and rel.startswith("keys/"):
            path = self.ws.resolve(rel, ("keys",), depth=(1,))
            shutil.rmtree(path)
        else:
            path = self.ws.resolve(rel, ("data", "tags", "out"))
            if not os.path.isfile(path):
                raise ApiError(400, "只能删除文件")
            os.remove(path)
            if rel.startswith("tags/"):
                self.ws.set_meta(rel, None)
        return {"removed": rel}

    def upload(self, name, length, rfile):
        if not valid_name(name):
            raise ApiError(400, "非法文件名")
        if length > self.max_upload:
            raise ApiError(413, f"文件超过上传上限（{self.max_upload // (1024 * 1024)} MiB）")
        rel = f"data/{name}"
        path = self.ws.resolve(rel, ("data",), must_exist=False)
        if os.path.exists(path):
            raise ApiError(409, f"已存在：{rel}")
        fd, tmp = tempfile.mkstemp(dir=os.path.join(self.ws.root, "data"), prefix=".upload-")
        try:
            with os.fdopen(fd, "wb") as f:
                left = length
                while left > 0:
                    chunk = rfile.read(min(left, 1 << 20))
                    if not chunk:
                        raise ApiError(400, "上传数据不完整")
                    f.write(chunk)
                    left -= len(chunk)
            if os.path.exists(path):
                raise ApiError(409, f"已存在：{rel}")
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        return {"path": rel, "size": length}


def int_arg(b, name, lo, hi, default=None):
    v = b.get(name, default)
    if v is None:
        raise ApiError(400, f"缺少参数 {name}")
    if isinstance(v, str) and re.fullmatch(r"[0-9]{1,20}", v):
        v = int(v)
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ApiError(400, f"参数 {name} 应为 {lo}～{hi} 的整数")
    return v


# ===================================================================== #
# HTTP                                                                   #
# ===================================================================== #

POST_ROUTES = {
    "/api/keygen": "api_keygen",
    "/api/store": "api_store",
    "/api/audit": "api_audit",
    "/api/porta": "api_porta",
    "/api/retrieve": "api_retrieve",
    "/api/delete": "api_delete",
    "/api/tamper": "api_tamper",
    "/api/doctor": "api_doctor",
}


def make_handler(console, token, port):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    token_b = token.encode()

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "swpor-console"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            # 只记录方法和路径（不含查询串）；令牌在 URL 片段中，本来就不会发到服务端
            path = self.path.split("?", 1)[0] if hasattr(self, "path") else "-"
            sys.stderr.write(f"[{time.strftime('%H:%M:%S')}] {self.command} {path} "
                             f"{args[1] if len(args) > 1 else ''}\n")

        # ---- 响应 ----

        def _headers(self, status, ctype, length, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; object-src 'none'; "
                             "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()

        def send_json(self, status, obj):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(body))
            self.wfile.write(body)

        def fail(self, status, msg):
            self.close_connection = True
            self.send_json(status, {"error": msg})

        # ---- 校验 ----

        def check_host(self):
            if self.headers.get("Host", "") not in allowed_hosts:
                self.fail(403, "非法 Host")
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin not in allowed_origins:
                self.fail(403, "不允许跨源请求")
                return False
            return True

        def check_token(self):
            got = self.headers.get("X-Swpor-Token", "").encode()
            if not hmac.compare_digest(got, token_b):
                self.fail(403, "缺少或错误的令牌")
                return False
            return True

        def read_json(self):
            length = self.content_length()
            if length > MAX_JSON_BODY:
                raise ApiError(413, "请求体过大")
            raw = self.rfile.read(length) if length else b"{}"
            try:
                obj = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise ApiError(400, "请求体不是合法 JSON")
            if not isinstance(obj, dict):
                raise ApiError(400, "请求体必须是 JSON 对象")
            return obj

        def content_length(self):
            v = self.headers.get("Content-Length", "0")
            if not re.fullmatch(r"[0-9]{1,15}", v):
                raise ApiError(400, "Content-Length 非法")
            return int(v)

        # ---- 路由 ----

        def do_GET(self):
            if not self.check_host():
                return
            url = urllib.parse.urlsplit(self.path)
            path = url.path
            try:
                if not path.startswith("/api/"):
                    return self.static(path)
                if not self.check_token():
                    return
                q = urllib.parse.parse_qs(url.query)
                if path == "/api/state":
                    return self.send_json(200, console.state())
                if path == "/api/jobs":
                    with console.jobs_lock:
                        jobs = list(console.jobs)
                    return self.send_json(200, [j.snapshot(full=False) for j in reversed(jobs)])
                m = re.fullmatch(r"/api/jobs/([0-9]{1,9})", path)
                if m:
                    return self.send_json(200, console.get_job(int(m.group(1))).snapshot())
                if path == "/api/download":
                    return self.download(q.get("path", [""])[0])
                raise ApiError(404, "没有这个接口")
            except ApiError as e:
                self.fail(e.status, e.msg)

        def do_POST(self):
            if not self.check_host() or not self.check_token():
                return
            url = urllib.parse.urlsplit(self.path)
            path = url.path
            try:
                if path == "/api/upload":
                    q = urllib.parse.parse_qs(url.query)
                    name = q.get("name", [""])[0]
                    return self.send_json(200, console.upload(name, self.content_length(),
                                                              self.rfile))
                body = self.read_json()
                if path in POST_ROUTES:
                    job = getattr(console, POST_ROUTES[path])(body)
                    return self.send_json(200, job.snapshot())
                if path == "/api/remove":
                    return self.send_json(200, console.api_remove(body))
                if path == "/api/server/start":
                    return self.send_json(200, console.start_pord(body))
                if path == "/api/server/stop":
                    return self.send_json(200, console.stop_pord())
                m = re.fullmatch(r"/api/jobs/([0-9]{1,9})/cancel", path)
                if m:
                    job = console.get_job(int(m.group(1)))
                    return self.send_json(200, {"cancelled": job.cancel()})
                raise ApiError(404, "没有这个接口")
            except ApiError as e:
                self.fail(e.status, e.msg)
            except OSError as e:
                self.fail(500, f"I/O 错误：{e.strerror or e}")

        def static(self, path):
            name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
            # 只提供 web/ 目录下直接存在的文件，不解析子路径
            if "/" in name or name not in os.listdir(WEB_DIR):
                raise ApiError(404, "not found")
            ext = os.path.splitext(name)[1]
            if ext not in STATIC_TYPES:
                raise ApiError(404, "not found")
            with open(os.path.join(WEB_DIR, name), "rb") as f:
                body = f.read()
            self._headers(200, STATIC_TYPES[ext], len(body))
            self.wfile.write(body)

        def download(self, rel):
            path = console.ws.resolve(rel, ("out", "data"))
            if not os.path.isfile(path):
                raise ApiError(400, "只能下载文件")
            size = os.path.getsize(path)
            fname = urllib.parse.quote(os.path.basename(path))
            self._headers(200, "application/octet-stream", size,
                          {"Content-Disposition": f"attachment; filename*=UTF-8''{fname}"})
            with open(path, "rb") as f:
                shutil.copyfileobj(f, self.wfile, 1 << 20)

    return Handler


def main():
    ap = argparse.ArgumentParser(description="swpor 本机 Web 控制台（SPEC 9.5）")
    ap.add_argument("--bin", required=True, help="porctl / porta / pord 所在目录，如 build/debug/apps")
    ap.add_argument("--workspace", required=True, help="工作区目录（密钥、数据、标签、存储）")
    ap.add_argument("--port", type=int, default=8787, help="监听端口（0 表示随机），只监听 127.0.0.1")
    ap.add_argument("--max-upload", type=int, default=1024, help="上传大小上限（MiB）")
    ap.add_argument("--open", action="store_true", help="启动后用默认浏览器打开")
    args = ap.parse_args()
    if not 0 <= args.port <= 65535 or args.max_upload <= 0:
        ap.error("参数超出范围")

    ws = Workspace(os.path.expanduser(args.workspace))
    console = Console(args.bin, ws, args.max_upload * 1024 * 1024)
    token = secrets.token_hex(32)

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        allow_reuse_address = os.name != "nt"

    # 先绑定端口（--port 0 时由系统分配），再按实际端口构造 Host 白名单
    httpd = Server(("127.0.0.1", args.port), http.server.BaseHTTPRequestHandler)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(console, token, port)
    url = f"http://127.0.0.1:{port}/#token={token}"
    print(f"swpor console {console.version}  workspace: {ws.root}", flush=True)
    print(f"swpor console listening: {url}", flush=True)
    if args.open:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        console.shutdown()


if __name__ == "__main__":
    main()
