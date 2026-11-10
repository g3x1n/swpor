# src/store — 磁盘格式读写（M2）

实现 SPEC 6（服务端存储布局：`blocks.dat`、`sigma.dat`、`tag.bin`）与 SPEC 7（密钥文件格式）。
所有文件操作通过 `src/platform/` 的接口完成。证明生成时按需随机读块，不得把整个文件读入内存。
