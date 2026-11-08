# D2H follow-up 审查与独立补充

新版建议中有价值的部分是补足 D2H 的独立数据观测。原 a/d 回环复用同一 Host payload，H2D 后 Host 与设备都已有相同数据，省略 D2H 仍可能通过。新增软件诊断在全部 H2D 读取结束后取反 Host payload，让正常 D2H 必须恢复 Host 数据。候选分支已独立重建这部分最小实现和 Host 回归；生产 `src/`、BPF plan、真实 NVIDIA backend 均未修改。

外部完整答复已落盘，但公开分享没有给出新版附件的可读下载标识，外部补丁字节尚未取得。因此本次接受的是经过独立复现的机制，不能声称已审查或认证外部 `5c6f731` 的具体实现。候选分支尚无 kernel module build、KVM 或物理 GPU DMA 结果；原始 a/d PASS 的证明范围保持原状。

## 待取得或待运行

**外部原补丁可靠性尚未核实。** 分享正文展示了普通 `.patch/.txt/.sh` 链接，但公开 React 数据仅保留其他环境的 sandbox 路径。附件上传输出由源站标为已删减，无法据此恢复新版文件 ID；GitHub 对已知外部提交返回 `not our ref`。后续取得原件后，需要逐字对照独立实现，不能用报告里的自述代替补丁审查。

**KVM 四个诊断 case 尚未接线。** 本候选只补默认关闭的 simulator 能力和实际引擎的 Host 回归。完整 guest 接线仍须单独生命周期：a/d × 正常/skip_d2h，固定一个 group、depth 1，逐 case 核实独立数据、精确 completion、模块计数及卸载。chain a 的原 CLI exit 0 不足以检出 D2H 缺失，必须独立比对 source/sink。未实现完整接线前不得打印诊断 PASS。外部建议的重复 normal strict 运行也不能覆盖项目已裁定的 debug strict 规则。

**物理路径仍须独立目的缓冲区证据。** 软件取反的同步点属于 CPU simulator，不能直接移植到异步 DMA 的用户态改写。现有 `single-d2h`、分离设备窗口 probe 适合后续真实设备验证，本轮没有执行设备命令。

## 已核实与已补充

D2H alias 观测缺口准确，影响测试证据强度；缺口本身不能证明生产 D2H 搬运损坏。独立回归保留关闭取反时 skip_d2h 仍不可区分的负对照，开启取反后要求 Host 数据不再伪装成正确。

当前 simulator 原本就对全部 SGL 做完 bounds/overflow 预检后再复制。外部的“最后一项非法不能先复制前缀”属于值得补充的负向回归，并非本基线仍缺少预检。本次保留现有预检，新增两方向的 Host/GPU 越界及 overflow 断言，并用逐项预检 mutant 确认前缀破坏会被检出。

当前 guest 的相关 `role_evidence` 已显式使用 `/bin/busybox awk`。外部所述裸 awk 失败发生在外部新增代码中，不能据此再次改写当前已有的 BusyBox 调用。四 case console validator 同样是新增诊断的配套要求；当前 main 没有这套新增诊断，无法把外部配套 parser 的缺失说成当前 main 接受了这套诊断的伪证据。

本候选只增加默认关闭、逐 request 捕获的取反开关，以及仍报完整字节数的 skip_h2d/skip_d2h 故障模式。取反发生在全部 H2D 读取之后、completion 之前；只支持隔离、串行、Host payload 不重叠的诊断。共享 frame、fan-out、并发 session、多次取反抵消与任意瞬态丢失不在证明范围内。新 Host 检查已接入现有 roundtrip CI 入口。

## 附录：依据与准确验收

审查基线：`df2b4390aa368c7072a1b2e68608cb7ac57a39f1`，候选分支 `codex/d2h-followup-review-20261108`。

原件及引用核验：

- [分享原 HTML](/root/xdev_ext/tmp/external-review-d2h-followup/raw/desktop.html)，artifact `189c1b703f4d`；使用 HTMLParser 切分 script，再以 JSON 解码 React 引用表，没有执行网页 JavaScript。
- [完整最终答复](/root/xdev_ext/tmp/external-review-d2h-followup/text/part-001.txt)与[原有答复](/root/xdev_ext/tmp/external-review-d2h-followup/text/part-014.txt)。
- [manifest](/root/xdev_ext/tmp/external-review-d2h-followup/manifest.tsv)、[主张清单](/root/xdev_ext/tmp/external-review-d2h-followup/claims.jsonl)、[核验输出](/root/xdev_ext/tmp/external-review-d2h-followup/claims-check.log)：5 条引文全部在落盘原件中找到。
- [外部提交抓取结果](/root/xdev_ext/tmp/external-review-d2h-followup/raw/github-patch-fetch.log)。

当前代码依据：

- `tests/support/ce_sim/xdev_ext_ce_sim.c`：`xdev_ext_ce_sim_copy()` 原有完整预检；新开关只在 copy helper 末尾修改 Host payload；`xdev_ext_ce_sim_submit()` 在入队前捕获 mode 和开关。
- `tests/integration/cli/xdev_ext_mech_ce_roundtrip_test.c`：原 `SKIP_D2H` 可通过的断言保留。
- `tests/integration/session/native/xdev_ext_mech_zc_kvm.sh`：现有 `role_evidence` 使用 `/bin/busybox awk`；原普通 campaign 没有四 case D2H 诊断。
- `tests/integration/session/native/xdev_ext_mech_zc_validate.py`：现有 `ce_sim` 验收是普通 campaign 的计数和完成合同，未虚构新增诊断的原始证据。

本轮实际执行：

```sh
python3 tests/support/ce_sim/copy_contract.py --output build/d2h-red
python3 tests/support/ce_sim/copy_contract.py --output build/d2h-green --mutations
XDEV_EXT_CE_COPY_LOG_DIR="$PWD/build/d2h-entry" python3 tools/run.py tests/integration/cli/xdev_ext_mech_ce_roundtrip_test.py
python3 tools/run.py --view build/ce-source-view tests/compute/ce/xdev_ext_mech_ce_source_test.py
python3 tools/run.py --view build/ce-positive-view tests/compute/ce/xdev_ext_mech_ce_positive_test.py
python3 tools/layout.py check
git diff --check
```

- 修补前 RED：ASan/UBSan 各编译成功并退出 1，各有 11/84 个数据断言失败；并非编译错误或 sanitizer crash。
- 修补后 GREEN：ASan/UBSan 各 84 个断言通过，包含 6 个 roundtrip 与 8 个最后一项非法的请求。
- 隔离生成 C mutant：去掉取反、过早取反、逐项预检，在两种 sanitizer 下均由 `D2H_ASSERT` 检出，分别失败 5、6、16 个断言，均退出 1。
- 现有 roundtrip 入口：3 个 unittest 通过；相邻 CE source 19 个、positive fixture 2 个通过。
- 源码布局检查通过，diff 空白检查通过。没有运行完整 Host CI，也没有把抽取 copy helper 的执行提升为 module/kernel runtime。

统一登记：[独立 Host 结果账本](/root/xdev_ext/test-results/correctness/local/ce-d2h-independent-diagnostic-host-20261108/result.json)。共享 `STATUS.md` 和索引由主代理汇总。
