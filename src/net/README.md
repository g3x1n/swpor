# src/net — 网络协议（M3）

编译为独立的 `swpor_net` 库（libswpor 本身不含网络代码，SPEC 9.1）。

- `frame.c`：SPEC 8.2 帧格式、`host:port` 解析、CHALLENGE 消息解析（`swpor_chal_decode_wire`，也是 fuzz 目标）
- `client.c`：SPEC 8.3 全部请求的客户端
- `server.c`：SPEC 8.4 固定线程池服务端（有界队列、BUSY、每文件读写锁、读写超时）
- `remote.c`：把 `swpor/pipeline.h` 的回调映射到网络（批量上传、远程证明、下载到本地目录）

套接字收发通过 `src/platform/` 的 `swpor_sock_*` 接口完成。对应测试：T-15～T-18（`tests/unit/test_net.c`）。
