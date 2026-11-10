# src/pub — Pub 公开验证方案（M4）

实现 SPEC 4.2：基于 BLS12-381 的 Pub.Kg / Pub.St / Pub.V / Pub.P，以及 SPEC 4.3 中 Pub 方案的标签尾部（Ed25519 签名）。
所有群元素输入必须做曲线检查与子群检查（SPEC 11）。对应测试：T-19～T-21。
