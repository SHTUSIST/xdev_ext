# xdev_ext

**通过 Linux 内核扩展、有界 eBPF 程序和设备 provider，协调多种 DMA 设备使用共享、钉住的主机页。**

[English](README.md) | **简体中文**

xdev_ext 是一个研究存储、网络与 GPU 如何在同一组共享、钉住的主机页上进行 DMA 协同的系统。它抓住几类设备的共同基础：注册主机页面、原生描述符、DMA 完成和所有权交接。NVMe、NIC、GPU 各自使用自身原生描述符访问这些页面。内核管理页池、描述符准入、generation、背压与所有权；eBPF 程序构造有界的传输与协议计划；设备 provider 提供各设备的映射、原生提交、同步和完成回调。

[开始使用](docs/getting-started.md) · [系统架构](docs/architecture.md) · [支持路径](docs/supported-paths.md) · [文档索引](docs/README.md)

## 为什么需要 xdev_ext？

存储、网络与 GPU 各自管理缓冲区和完成语义，妨碍同一组主机页面跨设备复用与操作组合。xdev_ext 通过公共内核/provider 契约协调注册主机页面、原生描述符、DMA 完成和所有权交接，让同一项受支持的设备能力参与不同流水线。

主路径使用共享主机内存，并不要求数据在两个设备本地内存之间直接完成 P2P DMA。逻辑页池注册一次，建立的是页面注册与生命周期，并不意味着所有设备共享一个 DMA mapping 或 DMA 地址。各设备/provider 仍须按设备及其 IOMMU domain 建立适用的映射，分别满足 DMA 地址、可达性、传输方向、同步和完成生命周期的要求。

## 主要功能

- **共享主机页上的 DMA 协同：**NVMe、NIC、GPU 各自使用原生描述符访问注册、钉住的主机页，并明确完成状态与所有权交接。
- **内核管理内存与所有权：**注册页池、有界窗口、generation、描述符准入检查和资源生命周期。
- **可编程 I/O 计划：**eBPF 在内核约束内构造请求、拷贝计划和协议决策。
- **可组合 provider：**驱动通过公共契约提供各设备的 DMA 映射、原生提交、同步与完成能力。
- **流水线执行：**用户态配置并启动 session，内核推进正常批次并报告最终或异常结果。
- **明确的故障处理：**跟踪已接受的原生命令；无法确认完成或 DMA 停止时，保留相关资源。

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

## 工作方式

| 组件 | 职责 |
|---|---|
| 用户态控制 | 注册共享主机页等资源，配置 stage、启动 session 并观察结果 |
| eBPF 程序 | 构造有界设备与协议计划，解释允许的完成信息 |
| 内核核心 | 管理共享页池，执行描述符准入、所有权与 generation 检查、背压及 drain/quarantine |
| 设备 provider | 按设备及其 IOMMU domain 映射页面，提交原生描述符，执行 DMA 同步并报告完成或失效 |

各 stage 通过 DMA 完成与所有权交接决定下一设备何时可使用同一组主机页。GPU copy engine 仍在主机内存与 VRAM 之间传输数据；能否避免 CPU payload 复制取决于受支持的路径。普通 socket sink 会执行原生 socket 复制。可选 peer-memory 路径采用独立的设备内存分配与映射契约。

[系统架构](docs/architecture.md)说明 stage 组合方式；[支持路径](docs/supported-paths.md)列出内存路线、设备条件与兼容范围。

## 目录导航

| 路径 | 内容 |
|---|---|
| `kernel/` | Linux 改动、UAPI、BPF 程序、用户态工具与 selftests |
| [`kernel/io_uring/iaa/`](kernel/io_uring/iaa/) | IAA io_uring 操作、准入与生命周期核心、机制变换适配器 |
| [`tests/iaa/`](tests/iaa/) | IAA 系统调用合同门禁与独立主机检查 |
| `gpu/` | NVIDIA 开放内核模块改动与主机测试 |
| `scripts/` | 主机测试与固定上游源码准备入口 |
| `tests/eval/` | 可复现对照负载与透明前端调用形状核对 |
| `docs/` | 构建、架构、支持路径、测试及接口参考 |
| `sources.lock.json` | 完整源码树所需的公共上游版本 |

仓库跟踪项目源码覆盖层；源码准备步骤提供完整构建需要的未修改上游文件。每条路径的内存路线与设备条件见[支持路径](docs/supported-paths.md)。

## 文档与参与

[文档索引](docs/README.md)提供使用任务导航。[测试指南](docs/testing.md)区分主机、虚拟机软件设备和物理设备的证据范围；[故障排查](docs/troubleshooting.md)说明配置与运行问题；[贡献指南](CONTRIBUTING.md)列出提交与问题报告要求。

## 许可与来源

许可按组件和文件适用。Linux 派生改动保留相应的 Linux 许可与 SPDX 标识；NVIDIA 派生改动保留相应的上游 NVIDIA 许可声明。组件许可范围与来源见 [LICENSE.md](LICENSE.md)。
