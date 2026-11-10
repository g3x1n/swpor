# src/net — 网络协议编解码（M3）

实现 SPEC 8.2 帧格式与 8.3 消息类型的编码和解码（纯函数，不直接收发套接字）。
套接字收发通过 `src/platform/` 的 `swpor_sock_*` 接口完成；服务端线程池见 SPEC 8.4（只在 `pord` 中使用）。
对应测试：T-15～T-18，以及 libFuzzer 模糊测试（SPEC 10.4）。
