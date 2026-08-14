# dsh-profile-lock-proof

这是一个面向 DeepSeek Harness profile 的只读供应链证据插件：它把 profile 依赖声明、`pnpm-lock.yaml` importer、实际安装包 `package.json` 与 `dsh.bundle.patch` 串成内容寻址闭环。

它不是 SBOM、CVE 扫描、签名验证或安装器。它不联网、不执行被检包、不改 profile，也不返回清单、锁文件、patch、脚本命令或秘密正文。

判据包括：输入 SHA-256 固定；依赖必须是精确版本或 GitHub 40 位提交；声明与锁定 specifier 一致；安装包名字/版本/清单哈希一致；bundle patch 路径/哈希一致；不存在安装生命周期脚本。缺失、陈旧、可变引用、错配和生命周期脚本一律失败闭合。

```bash
dsh-profile-lock-proof verify --workspace . --manifest proof.json --artifactDir artifacts
```

DSH 工具：`dsh_profile_lock_inspect`、`dsh_profile_lock_verify`。
