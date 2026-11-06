# dsh-profile-lock-proof

作者 / 维护者：He Fangsheng (贺方升 / 贺去病; also known as Dosen)· [hequbing.com](https://www.hequbing.com)

v0.2.0 删除了会让 stock Cordis Loader 丢失 `inject` 元数据的 default export，也不再捆绑第二套 `@deepseek-ai/dsh-tools` 运行时。插件入口只暴露宿主中立的工具定义，并用真实 Web profile 回归安装与启动。

MCP 面刻意降权：只接收有大小上限的内联证据，不读写文件；DSH/CLI 只有在显式、workspace 相对的 `artifactDir` 下才可原子写入报告，并做写后回读验证。

[![CI](https://github.com/dongsheng123132/dsh-profile-lock-proof/actions/workflows/ci.yml/badge.svg)](https://github.com/dongsheng123132/dsh-profile-lock-proof/actions/workflows/ci.yml)
[![MIT 许可证](https://img.shields.io/github/license/dongsheng123132/dsh-profile-lock-proof)](LICENSE)
[![Node.js 22+](https://img.shields.io/badge/Node.js-%E2%89%A522-339933?logo=nodedotjs&logoColor=white)](package.json)
[![Awesome DSH Plugins](https://img.shields.io/badge/Awesome_DSH-%E5%B7%B2%E9%AA%8C%E8%AF%81%E5%AE%9E%E9%AA%8C-0969da)](https://github.com/dongsheng123132/awesome-dsh-plugins/blob/main/README.zh-CN.md#2origin-%E6%8F%92%E4%BB%B6%E5%AE%9E%E9%AA%8C%E5%AE%A4)

这是一个面向 DeepSeek Harness profile 的只读供应链证据插件：它把 profile 依赖声明、`pnpm-lock.yaml` importer、实际安装包 `package.json` 与 `dsh.bundle.patch` 串成内容寻址闭环。

它不是 SBOM、CVE 扫描、签名验证或安装器。它不联网、不执行被检包、不改 profile，也不返回清单、锁文件、patch、脚本命令或秘密正文。

判据包括：输入 SHA-256 固定；依赖必须是精确版本或 GitHub 40 位提交；声明与锁定 specifier 一致；安装包名字/版本/清单哈希一致；bundle patch 路径/哈希一致；不存在安装生命周期脚本。缺失、陈旧、可变引用、错配和生命周期脚本一律失败闭合。

```bash
dsh-profile-lock-proof verify --workspace . --manifest proof.json --artifactDir artifacts
```

DSH 工具：`dsh_profile_lock_inspect`、`dsh_profile_lock_verify`。
