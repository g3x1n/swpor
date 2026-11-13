#!/usr/bin/env python3
"""
T-27 Web 控制台（SPEC 9.5）端到端测试，只用 Python 标准库：
  - 通过 HTTP API 完成 keygen → 上传 → store → audit PASS → tamper → audit FAIL → retrieve 并下载比对；
  - 公开审计默认关闭，从 .env 读取配置，进程环境优先；
  - Pub 文件经 porta 审计；有 pord 的平台上启动本机 pord 并完成远程 store / 审计；
  - 缺少或错误的令牌、非法 Host、跨源请求返回 403；路径穿越与非法名称被拒绝；
  - API 响应中不出现私钥内容。

用法：python3 tests/integration/test_ui.py <构建目录，如 build/debug>
"""

import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FAILURES = []


def check(cond, msg):
    if not cond:
        FAILURES.append(msg)
    return cond


class Client:
    def __init__(self, port, token):
        self.port = port
        self.token = token

    def request(self, method, path, body=None, headers=None, raw=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        hdrs = {"Host": f"127.0.0.1:{self.port}", "X-Swpor-Token": self.token}
        hdrs.update(headers or {})
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
        conn.request(method, path, body=data, headers={k: v for k, v in hdrs.items() if v is not None})
        r = conn.getresponse()
        payload = r.read()
        conn.close()
        if raw:
            return r.status, payload
        try:
            return r.status, json.loads(payload.decode("utf-8"))
        except ValueError:
            return r.status, payload

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body if body is not None else {}, **kw)

    def job(self, path, body, expect_exit=0, timeout=120):
        """提交任务并等待结束；返回任务快照"""
        st, j = self.post(path, body)
        if not check(st == 200, f"{path} {body}: HTTP {st} {j}"):
            return {}
        deadline = time.time() + timeout
        while time.time() < deadline:
            st, d = self.get(f"/api/jobs/{j['id']}")
            if d.get("ended"):
                check(d.get("exit_code") == expect_exit,
                      f"{path}: exit {d.get('exit_code')}, expected {expect_exit}; log={d.get('log')}")
                return d
            time.sleep(0.1)
        FAILURES.append(f"{path}: job did not finish")
        return {}


def start_console(build, ws, public_audit=None, script=None):
    bindir = os.path.join(build, "apps")
    env = os.environ.copy()
    env.pop("SWPOR_WEB_PUBLIC_AUDIT", None)
    if public_audit is not None:
        env["SWPOR_WEB_PUBLIC_AUDIT"] = public_audit
    script = script or os.path.join(ROOT, "ui", "server.py")
    p = subprocess.Popen([sys.executable, script, "--bin", bindir,
                          "--workspace", ws, "--port", "0", "--max-upload", "4"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    for _ in range(2):
        line = p.stdout.readline().decode("utf-8", errors="replace")
        if "listening:" in line:
            url = line.split("listening:", 1)[1].strip()
            u = urllib.parse.urlsplit(url)
            return p, u.port, u.fragment.split("token=", 1)[1]
    p.kill()
    raise SystemExit("console did not start")


def test_T27_public_audit_config(build):
    with tempfile.TemporaryDirectory(prefix="swpor_ui_config_") as root:
        ui = os.path.join(root, "ui")
        os.mkdir(ui)
        script = shutil.copy(os.path.join(ROOT, "ui", "server.py"), ui)
        env_file = os.path.join(root, ".env")
        for file_value, process_value, expected in (
            (None, None, False),
            ("true", None, True),
            ("true", "false", False),
            ("false", "true", True),
        ):
            if file_value is not None:
                with open(env_file, "w", encoding="utf-8") as f:
                    f.write("# Web console\n")
                    f.write(f'SWPOR_WEB_PUBLIC_AUDIT = "{file_value}" # classroom demo\n')
            proc, port, token = start_console(build, os.path.join(root, "ws"), process_value, script)
            try:
                st, state = Client(port, token).get("/api/state")
                check(st == 200 and state.get("public_audit") is expected,
                      f"public audit config: file={file_value}, env={process_value}, expected={expected}")
            finally:
                stop_console(proc)


def main():
    build = os.path.abspath(sys.argv[1])
    test_T27_public_audit_config(build)
    ws = tempfile.mkdtemp(prefix="swpor_ui_")
    proc, port, token = start_console(build, ws, "false")
    c = Client(port, token)
    secrets_seen = []
    try:
        # ---- 安全检查 ----
        st, _ = c.get("/", headers={"X-Swpor-Token": None})
        check(st == 200, f"static index: HTTP {st}")
        st, _ = c.get("/api/state", headers={"X-Swpor-Token": None})
        check(st == 403, f"missing token: HTTP {st}")
        st, _ = c.get("/api/state", headers={"X-Swpor-Token": "0" * 64})
        check(st == 403, f"wrong token: HTTP {st}")
        st, _ = c.get("/api/state", headers={"Host": f"evil.example:{port}"})
        check(st == 403, f"bad Host: HTTP {st}")
        st, _ = c.get("/", headers={"Host": "attacker.test"})
        check(st == 403, f"bad Host on static: HTTP {st}")
        st, _ = c.post("/api/keygen", {"scheme": "priv"}, headers={"Origin": "http://evil.example"})
        check(st == 403, f"cross-origin POST: HTTP {st}")
        st, _ = c.get("/../SPEC.md", headers={"X-Swpor-Token": None})
        check(st == 404, f"static traversal: HTTP {st}")

        # ---- keygen ----
        d = c.job("/api/keygen", {"scheme": "priv", "name": "所有者 密钥"})
        check(d.get("command", [None])[0] == "porctl", f"keygen command: {d.get('command')}")
        c.job("/api/keygen", {"scheme": "pub", "name": "pub"})
        priv = "keys/所有者 密钥/priv.key"
        with open(os.path.join(ws, "keys", "所有者 密钥", "priv.key"), "rb") as f:
            secrets_seen.append(f.read())
        with open(os.path.join(ws, "keys", "pub", "pub.sk"), "rb") as f:
            secrets_seen.append(f.read())

        # ---- 上传：非法名称、路径穿越、超限、重复 ----
        data = os.urandom(150_000)
        name = "报告 数据.bin"
        q = urllib.parse.quote(name)
        st, j = c.post(f"/api/upload?name={q}", data)
        check(st == 200 and j.get("path") == f"data/{name}", f"upload: {st} {j}")
        # 重复名称在读取请求体前就会被拒绝，只发送一个字节以避免发送与断开连接竞争。
        st, _ = c.post(f"/api/upload?name={q}", b"x")
        check(st == 409, f"duplicate upload: HTTP {st}")
        for bad in ("../x.bin", "a/b", "..", ".hidden", "x\\y", ""):
            st, _ = c.post("/api/upload?name=" + urllib.parse.quote(bad), b"x")
            check(st == 400, f"bad upload name {bad!r}: HTTP {st}")
        # 声明的长度超过上限时，服务端不读请求体就返回 413
        st, _ = c.post("/api/upload?name=big.bin", b"x",
                       headers={"Content-Length": str(5 * 1024 * 1024)})
        check(st == 413, f"oversized upload: HTTP {st}")

        for body in ({"key": "keys/../../etc/passwd", "input": f"data/{name}"},
                     {"key": priv, "input": "data/../../x"},
                     {"key": priv, "input": "/etc/passwd"},
                     {"key": "data/" + name, "input": f"data/{name}"},
                     {"key": priv, "input": f"data/{name}", "target": "remote", "server": "a b"},
                     {"key": priv, "input": f"data/{name}", "rs": "1;rm"}):
            st, _ = c.post("/api/store", body)
            check(st == 400, f"bad store args {body}: HTTP {st}")
        st, _ = c.get("/api/download?path=" + urllib.parse.quote("keys/pub/pub.sk"))
        check(st == 400, f"download of key file: HTTP {st}")

        # ---- Priv：store → audit PASS → tamper → audit FAIL ----
        d = c.job("/api/store", {"key": priv, "input": f"data/{name}", "s": 32, "rs": "8:8",
                                 "perm": True, "encrypt": True, "target": "local"})
        tag = d.get("extra", {}).get("tag", "")
        check(tag == f"tags/{name}.tag", f"store tag: {tag!r}")
        types = [e["type"] for e in d.get("events", [])]
        for t in ("file_split", "ec_stripe", "tag_block", "tag_done"):
            check(t in types, f"store trace missing {t}: {types}")
        st, state = c.get("/api/state")
        tinfo = next((t for t in state.get("tags", []) if t["path"] == tag), {})
        check(tinfo.get("local_stored") and tinfo.get("info", {}).get("flags", {}).get("perm"),
              f"state tag: {tinfo}")

        d = c.job("/api/audit", {"key": priv, "tag": tag, "l": 40, "target": "local"})
        check(d.get("result") == "PASS", f"audit: {d.get('result')}")
        check(any(e["type"] == "verify" and e["result"] == "PASS" for e in d.get("events", [])),
              "audit trace has no verify PASS event")

        d = c.job("/api/retrieve", {"key": priv, "tag": tag, "target": "local"})
        out = d.get("extra", {}).get("out", "")
        st, got = c.get("/api/download?path=" + urllib.parse.quote(out), raw=True)
        check(st == 200 and got == data, f"downloaded retrieve result differs ({out!r}, HTTP {st})")

        d = c.job("/api/tamper", {"tag": tag, "mode": "flip", "ratio": 0.5, "seed": 7})
        check(d.get("outputs", [{}])[-1].get("modified", 0) > 0, f"tamper: {d.get('outputs')}")
        d = c.job("/api/audit", {"key": priv, "tag": tag, "l": 100, "target": "local"},
                  expect_exit=1)
        check(d.get("result") == "FAIL", f"audit after tamper: {d.get('result')}")
        st, _ = c.post("/api/tamper", {"tag": tag, "mode": "flip", "ratio": 2})
        check(st == 400, f"tamper ratio out of range: HTTP {st}")

        # ---- Pub：porta 本地审计 ----
        d = c.job("/api/store", {"key": "keys/pub/pub.sk", "input": f"data/{name}", "s": 16,
                                 "target": "local"})
        ptag = d.get("extra", {}).get("tag", "")
        d = c.job("/api/porta", {"pk": "keys/pub/pub.pk", "tags": [ptag], "l": 20, "count": 2,
                                 "interval": 0, "target": "local"})
        check([o.get("result") for o in d.get("outputs", [])] == ["PASS", "PASS"],
              f"porta local: {d.get('outputs')}")
        st, _ = c.post("/api/porta", {"pk": "keys/pub/pub.sk", "tags": [ptag], "target": "local"})
        check(st == 400, f"porta with secret key: HTTP {st}")

        # ---- 远程：本机 pord ----
        st, state = c.get("/api/state")
        if state.get("server", {}).get("available"):
            st, s = c.post("/api/server/start", {"threads": 2})
            check(st == 200 and s.get("running"), f"pord start: {st} {s}")
            addr = s.get("address", "")
            check(addr.startswith("127.0.0.1:"), f"pord address {addr}")
            d = c.job("/api/store", {"key": "keys/pub/pub.sk", "input": f"data/{name}",
                                     "target": "remote", "server": addr})
            rtag = d.get("extra", {}).get("tag", "")
            d = c.job("/api/porta", {"pk": "keys/pub/pub.pk", "tags": [rtag], "count": 1,
                                     "target": "remote", "server": addr})
            check(d.get("result") == "PASS", f"porta remote: {d.get('outputs')} {d.get('log')}")
            d = c.job("/api/retrieve", {"key": "keys/pub/pub.pk", "tag": rtag, "target": "remote",
                                        "server": addr})
            st, got = c.get("/api/download?path=" +
                            urllib.parse.quote(d.get("extra", {}).get("out", "")), raw=True)
            check(st == 200 and got == data, "remote retrieve differs")
            st, s = c.get("/api/state")
            check(any(e.get("type") == "prove_done" for e in s["server"]["events"]),
                  "pord trace has no prove_done event")
            st, s = c.post("/api/server/stop")
            check(st == 200 and not s.get("running"), f"pord stop: {s}")

        # ---- 删除工作区文件 ----
        st, _ = c.post("/api/remove", {"path": "store"})
        check(st == 400, f"remove store dir: HTTP {st}")
        st, _ = c.post("/api/remove", {"path": out})
        check(st == 200 and not os.path.exists(os.path.join(ws, *out.split("/"))),
              f"remove {out}: HTTP {st}")

        # ---- 私钥内容不出现在任何 API 响应中 ----
        st, raw_state = c.get("/api/state", raw=True)
        st, raw_jobs = c.get("/api/jobs", raw=True)
        blobs = [raw_state, raw_jobs]
        st, jobs = c.get("/api/jobs")
        for j in jobs:
            blobs.append(c.get(f"/api/jobs/{j['id']}", raw=True)[1])
        for sk in secrets_seen:
            for b in blobs:
                tail = sk[-32:]  # 密钥文件末尾为秘密值
                check(tail not in b and tail.hex().encode() not in b,
                      "secret key material in API response")
    finally:
        stop_console(proc)
        shutil.rmtree(ws, ignore_errors=True)

    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed:")
        for f in FAILURES:
            print("  - " + f)
        return 1
    print("Web console tests (T-27): all checks passed")
    return 0


def stop_console(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    proc.stdout.close()


if __name__ == "__main__":
    sys.exit(main())
