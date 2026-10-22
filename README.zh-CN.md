# xdev_ext

**通过 Linux 内核扩展、有界 eBPF 程序和设备 provider，组合跨设备 I/O。**

[English](README.md) | **简体中文**

xdev_ext 是一个跨设备 I/O 研究系统，通过统一的执行与所有权模型连接存储、网络和 GPU。内核管理注册内存、描述符准入、generation、背压与完成状态；eBPF 程序构造有界的传输与协议计划；设备 provider 提供映射、原生提交和完成回调。

[开始使用](docs/getting-started.md) · [系统架构](docs/architecture.md) · [支持路径](docs/supported-paths.md) · [文档索引](docs/README.md)

## 主要功能

- **内核管理内存与所有权：**注册页池、有界窗口、generation 和描述符准入检查。
- **可编程 I/O 计划：**eBPF 在内核约束内构造请求、拷贝计划和协议决策。
- **可组合 provider：**驱动通过公共契约提供映射、原生提交、同步与完成能力。
- **流水线执行：**用户态配置并启动 session，内核推进正常批次并报告最终或异常结果。
- **明确的故障处理：**跟踪已接受的原生命令；无法确认完成或 DMA 停止时，保留相关资源。

跨设备组合需要各 stage 的缓冲区所有权、设备映射、队列接受状态与完成结果保持一致。xdev_ext 通过公共内核/provider 契约组织这些职责，让同一项设备能力参与不同流水线。

## 快速开始

在 Linux 上安装 Python 3 以及支持 C11、pthread 和 UndefinedBehaviorSanitizer 的 C 编译器，运行：

```bash
git clone https://github.com/shtusist/xdev_ext.git
cd xdev_ext
python3 scripts/test_host.py
```

主机检查直接使用项目源码，无需准备或启动完整内核。它们验证软件行为，不能证明物理 DMA 执行或硬件性能。

构建内核或可选 NVIDIA 组件前，准备固定版本的公共上游源码：

```bash
python3 scripts/prepare_sources.py --component linux
python3 scripts/prepare_sources.py --component nvidia
```

该步骤向 `kernel/` 和 `gpu/` 补齐缺失的上游文件，保留仓库中的项目改动。依赖、配置、BTF 与构建命令见[构建指南](docs/build.md)。

## 架构与目录

用户态负责资源注册、stage 配置、启动与结果观察；eBPF 负责有界计划及允许的完成解释；内核负责准入、所有权、generation、背压及 drain/quarantine；provider 负责设备映射、原生提交、DMA 同步和完成通知。

| 路径 | 内容 |
|---|---|
| `kernel/` | Linux 改动、UAPI、BPF 程序、用户态工具与 selftests |
| `gpu/` | NVIDIA 开放内核模块改动与主机测试 |
| `scripts/` | 主机测试与固定上游源码准备入口 |
| `docs/` | 构建、架构、支持路径、测试及接口参考 |
| `sources.lock.json` | 完整源码树所需的公共上游版本 |

仓库跟踪项目源码覆盖层；源码准备步骤提供完整构建需要的未修改上游文件。每条路径的内存路线与设备条件见[支持路径](docs/supported-paths.md)。

## 文档与参与

[文档索引](docs/README.md)提供使用任务导航。[测试指南](docs/testing.md)区分主机、虚拟机软件设备和物理设备的证据范围；[故障排查](docs/troubleshooting.md)说明配置与运行问题；[贡献指南](CONTRIBUTING.md)列出提交与问题报告要求。

## 许可与来源

许可按组件和文件适用。Linux 派生改动保留相应的 Linux 许可与 SPDX 标识；NVIDIA 派生改动保留相应的上游 NVIDIA 许可声明。组件许可范围与来源见 [LICENSE.md](LICENSE.md)。
