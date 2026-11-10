#!/usr/bin/env python3
"""
命令行端到端测试（只用 Python 标准库）：
  T-14  porctl 退出码与 --json 输出格式（SPEC 9.2）
  T-21  porta 只用 pk 和 t 完成审计
  T-26  非 ASCII 路径（中文文件名、带空格的路径）的存储与恢复（CLI 层面）
  以及本地模式完整流程、篡改后审计失败、远程模式（有 pord 时）。

用法：python3 tests/integration/test_cli.py <构建目录，如 build/debug>
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

FAILURES = []


def exe(build, name):
    for cand in (f"apps/{name}", f"apps/{name}.exe", f"apps/Debug/{name}.exe",
                 f"apps/Release/{name}.exe"):
        p = os.path.join(build, cand)
        if os.path.exists(p):
            return os.path.abspath(p)
    return None


def run(args, cwd, expect=None):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8")
    if expect is not None and p.returncode != expect:
        FAILURES.append(f"{' '.join(args[1:3])}: exit {p.returncode}, expected {expect}\n"
                        f"  stdout: {p.stdout.strip()}\n  stderr: {p.stderr.strip()}")
    return p


def run_json(args, cwd, expect):
    p = run(args + ["--json"], cwd, expect)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        FAILURES.append(f"{' '.join(args[1:3])}: --json output is not JSON: {p.stdout!r}")
        return {}


def check(cond, msg):
    if not cond:
        FAILURES.append(msg)


def check_file_equals(path, data, msg):
    """检查输出文件存在且内容等于 data；不存在时记为失败而不是抛异常，以便报告所有失败项"""
    if not os.path.exists(path):
        FAILURES.append(f"{msg}: output file {path!r} was not created")
        return
    with open(path, "rb") as f:
        check(f.read() == data, msg)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    build = sys.argv[1]
    porctl, porta, pord = exe(build, "porctl"), exe(build, "porta"), exe(build, "pord")
    if porctl is None or porta is None:
        sys.exit("porctl / porta not built")
    work = tempfile.mkdtemp(prefix="swpor_cli_")
    try:
        data = os.urandom(200_000)
        name = "数据 文件.bin"
        with open(os.path.join(work, name), "wb") as f:
            f.write(data)

        # ---- keygen ----
        j = run_json([porctl, "keygen", "--scheme", "priv", "--out", "k"], work, 0)
        check(j.get("scheme") == "priv" and len(j.get("files", [])) == 1, f"keygen json: {j}")
        run([porctl, "keygen", "--scheme", "priv", "--out", "k"], work, 3)  # 已存在：I/O 错误
        run_json([porctl, "keygen", "--scheme", "pub", "--out", "k"], work, 0)
        if os.name != "nt":
            mode = os.stat(os.path.join(work, "k", "priv.key")).st_mode & 0o777
            check(mode == 0o600, f"priv.key permissions {oct(mode)}")

        # ---- 参数错误：退出码 2 ----
        run([porctl, "store", "--key", "k/priv.key"], work, 2)
        run([porctl, "store", "--key", "k/priv.key", "--in", name, "--bogus"], work, 2)
        run([porctl, "store", "--key", "k/priv.key", "--in", name, "--local", "a",
             "--server", "b:1"], work, 2)
        run([porctl, "store", "--key", "k/priv.key", "--in", name, "--local", "s",
             "--rs", "300:2"], work, 2)
        run([porctl, "nosuchcmd"], work, 2)
        run([porctl, "store", "--key", "k/pub.sk", "--in", name, "--local", "s", "--perm"],
            work, 2)
        # 不存在的输入文件：I/O 错误
        run([porctl, "store", "--key", "k/priv.key", "--in", "missing.bin", "--local", "s"],
            work, 3)

        # ---- 本地模式完整流程（Priv，含置乱与加密） ----
        j = run_json([porctl, "store", "--key", "k/priv.key", "--in", name, "--local", "存储 目录",
                      "--perm", "--encrypt", "--s", "32", "--rs", "8:8", "--tag-out", "p.tag"],
                     work, 0)
        for key in ("file_id", "tag", "n", "s", "L", "elapsed_ms"):
            check(key in j, f"store json missing {key}: {j}")
        check(j.get("L") == len(data) and j.get("s") == 32, f"store json values: {j}")
        fid = j.get("file_id", "")
        info = run_json([porctl, "info", "--tag", "p.tag"], work, 0)
        check(info.get("file_id") == fid and info["flags"]["perm"] and info["flags"]["encrypt"],
              f"info json: {info}")
        a = run_json([porctl, "audit", "--key", "k/priv.key", "--tag", "p.tag", "--local",
                      "存储 目录", "--l", "40"], work, 0)
        check(a.get("result") == "PASS" and a.get("l") == 40, f"audit json: {a}")
        for key in ("elapsed_ms", "challenge_bytes", "proof_bytes"):
            check(key in a, f"audit json missing {key}")
        r = run_json([porctl, "retrieve", "--key", "k/priv.key", "--tag", "p.tag", "--local",
                      "存储 目录", "--out", "恢复 结果.bin"], work, 0)
        check(r.get("result") == "OK", f"retrieve json: {r}")
        check_file_equals(os.path.join(work, "恢复 结果.bin"), data,
                          "retrieved file differs (T-10/T-26)")

        # 错误的密钥：标签认证失败 → 退出码 5
        run([porctl, "keygen", "--scheme", "priv", "--out", "k2"], work, 0)
        run([porctl, "audit", "--key", "k2/priv.key", "--tag", "p.tag", "--local", "存储 目录"],
            work, 5)

        # 篡改后审计 FAIL（退出码 1），全部块被删除后检索失败（退出码 5，不留下输出文件）
        t = run_json([porctl, "tamper", "--local", "存储 目录", "--file-id", fid, "--mode", "flip",
                      "--ratio", "0.5", "--seed", "1"], work, 0)
        check(t.get("modified", 0) > 0, f"tamper json: {t}")
        a = run_json([porctl, "audit", "--key", "k/priv.key", "--tag", "p.tag", "--local",
                      "存储 目录", "--l", "100"], work, 1)
        check(a.get("result") == "FAIL", f"audit after tamper: {a}")
        run([porctl, "tamper", "--local", "存储 目录", "--file-id", fid, "--mode", "delete",
             "--ratio", "1"], work, 0)
        run([porctl, "retrieve", "--key", "k/priv.key", "--tag", "p.tag", "--local", "存储 目录",
             "--out", "bad.bin"], work, 5)
        check(not os.path.exists(os.path.join(work, "bad.bin")),
              "failed retrieve left an output file (T-12)")

        # ---- porta：本地模式（只用 pk 与 t） ----
        run_json([porctl, "store", "--key", "k/pub.sk", "--in", name, "--local", "ps",
                  "--s", "16", "--tag-out", "u.tag"], work, 0)
        p = run([porta, "--pk", "k/pub.pk", "--tag", "u.tag", "--local", "ps", "--l", "20",
                 "--json", "--log", "audit.log"], work, 0)
        check('"result":"PASS"' in p.stdout, f"porta json: {p.stdout}")
        run([porta, "--pk", "k/pub.sk", "--tag", "u.tag", "--local", "ps"], work, 2)
        run([porta, "--pk", "k/priv.key", "--tag", "u.tag", "--local", "ps"], work, 2)

        # ---- 远程模式（需要 pord） ----
        if pord is not None:
            port = free_port()
            log = open(os.path.join(work, "pord.log"), "wb")
            srv = subprocess.Popen([pord, "--listen", f"127.0.0.1:{port}", "--data-dir", "srv",
                                    "--threads", "2"], cwd=work, stdout=log, stderr=log)
            try:
                for _ in range(50):
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                        break
                    except OSError:
                        time.sleep(0.1)
                addr = f"127.0.0.1:{port}"
                j = run_json([porctl, "store", "--key", "k/pub.sk", "--in", name, "--server", addr,
                              "--tag-out", "r.tag"], work, 0)
                check(j.get("mode") == "remote", f"remote store: {j}")
                p = run([porta, "--pk", "k/pub.pk", "--tag", "r.tag", "--server", addr,
                         "--count", "2", "--interval", "0", "--json"], work, 0)
                check(p.stdout.count('"result":"PASS"') == 2, f"porta remote (T-21): {p.stdout}")
                run([porctl, "audit", "--key", "k/pub.pk", "--tag", "r.tag", "--server", addr,
                     "--seed-mode"], work, 0)
                r = run_json([porctl, "retrieve", "--key", "k/pub.pk", "--tag", "r.tag",
                              "--server", addr, "--out", "remote.bin"], work, 0)
                check_file_equals(os.path.join(work, "remote.bin"), data,
                                  "remote retrieve differs")
                run([porctl, "delete", "--tag", "r.tag", "--server", addr], work, 0)
                run([porctl, "audit", "--key", "k/pub.pk", "--tag", "r.tag", "--server", addr],
                    work, 3)
            finally:
                srv.terminate()
                srv.wait(timeout=10)
                log.close()
            # 连不上服务端：网络错误
            run([porctl, "audit", "--key", "k/pub.pk", "--tag", "r.tag", "--server",
                 f"127.0.0.1:{port}"], work, 4)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if FAILURES:
        print(f"{len(FAILURES)} check(s) failed:")
        for f in FAILURES:
            print("  - " + f)
        return 1
    print("CLI integration tests (T-14, T-21, T-26): all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
