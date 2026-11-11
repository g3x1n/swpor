# ui — 本机 Web 控制台（M-UI，选做）

见 SPEC 9.5。后端 `server.py` 只用 Python 标准库，前端 `web/` 为 HTML、CSS、原生 JavaScript，无需构建。
后端以子进程调用 `porctl` / `porta` / `pord`，不链接 `libswpor`。

桌面封装暂不做（SPEC OPEN-6）。
