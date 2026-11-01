# Independent DMA-BUF test boundary

The harness compiles the actual peer and importer as separate translation units. It supplies kernel services at their Linux interfaces and uses the production public headers. No fake importer, fake geometry converter or fake region implementation is linked. Before the component exists, only the test fixture is compiled; the runner records NOT_IMPLEMENTED with exit 3, not a behavioral RED.

The test owner derives expectations from the root-approved dmabuf-contract.md and root's later drainable requirement. The implementation owner must not read importer_cases.c or receive individual expected assertions. Root may use this file to resolve interface-only compiler disagreements.

## Public component interfaces

The frozen prototypes are in contract.h for pre-implementation fixture compilation and in the production public headers for actual execution:

```c
int xdev_ext_peer_dmabuf_desc_register(const struct xdev_ext_peer_dmabuf_desc_ops *);
int xdev_ext_peer_dmabuf_desc_unregister(const struct xdev_ext_peer_dmabuf_desc_ops *);
int xdev_ext_peer_dmabuf_import(struct dma_buf *, u64 len, struct xdev_ext_peer_region **);
int xdev_ext_peer_dmabuf_geometry(const struct sg_table *, u64 len, u64 **addresses, u32 *entries);
int xdev_ext_peer_drainable(struct xdev_ext_peer_region *);
```

The existing peer generation, info, describe, map, acquire, release, unmap and unpin APIs remain the observed lifecycle. `is_stale()==true` means invalid. drainable returns 0 for no-active/nonquarantined regions even when stale or invalid; active returns -EBUSY and quarantined returns -EIO.

## Linux boundary signatures

These are declared in kernel_shim.h, checked against fixed Linux 89be saved primary headers:

```c
struct dma_buf_attachment *dma_buf_dynamic_attach(struct dma_buf *, struct device *,
    const struct dma_buf_attach_ops *, void *importer_priv);
void dma_buf_detach(struct dma_buf *, struct dma_buf_attachment *);
int dma_buf_pin(struct dma_buf_attachment *);
void dma_buf_unpin(struct dma_buf_attachment *);
struct sg_table *dma_buf_map_attachment(struct dma_buf_attachment *, enum dma_data_direction);
void dma_buf_unmap_attachment(struct dma_buf_attachment *, struct sg_table *, enum dma_data_direction);
struct dma_buf *dma_buf_get(int fd);
void dma_buf_put(struct dma_buf *);
long dma_resv_wait_timeout(struct dma_resv *, enum dma_resv_usage, bool intr, unsigned long timeout);
bool dma_need_sync(struct device *, dma_addr_t);
bool dev_is_dma_coherent(struct device *);
struct user_struct *get_current_user(void);
```

The minimal struct fields retain their public roles and types: user_struct.locked_vm is atomic_long_t; mm_struct.pinned_vm is atomic64_t; dma_buf.size is size_t; dma_buf.ops/file/resv/priv and attachment.dmabuf/dev/importer_ops/importer_priv are typed pointers. SG DMA address is dma_addr_t; mapped length and nents are unsigned int. The adapter deliberately omits unrelated Linux fields rather than asserting a fake binary kernel ABI. Cases never inspect the importer's private allocation layout.

The fake exporter can fail attach/pin/map/readiness and invoke move_notify while resv is held. It requires pin/map/unmap/unpin under resv; attach/detach/put require resv unlocked. Its SG table already contains device DMA addresses and must be returned unchanged on unmap. BIDIRECTIONAL direction is checked at both boundaries. The source file's exporter module reference lives until its final fput. Descriptor, user, mm and PCI references are separately recorded.

The mutex adapter rejects recursive acquisition immediately, making resv -> region inversion visible without a long hang. Each move callback must acquire no mutex. The allocation adapter supports deterministic failure at each actual production allocation; it implements checked array multiplication and records outstanding objects. Near-overflow counters are synthetic arithmetic inputs, not a physical-memory claim.

## Actual close adapters

The runner copies xdev_ext_peer_fd_close and xdev_ext_peer_authority_close verbatim into an isolated test TU from the requested source root. A comment/string-aware brace scanner extracts exactly those entries. Their baseline private fd shapes are declared in fd_boundary.h; a setup helper creates authority/allocation references, while fput invokes the actual allocation release. No close algorithm is supplied by the test. Missing entries or incompatible shapes are SETUP_ERROR, never behavioral FAIL/PASS.

## Running and evidence

Both runners accept `--source-root` (default: the runner's own checkout). Receipts record HEAD, repository dirty state, selected-input Git status, and whether the source inputs include uncommitted changes. HEAD alone never identifies a dirty tested tree. Each run saves the key production files and all fixture files in its evidence directory, then compiles those snapshots; `compile_source_root` identifies the exact saved inputs. Root can bind the saved bytes to a later commit without assuming an earlier HEAD contained working-tree fixes. Snapshots do not include upstream trees or build caches.

```sh
python3 -I tests/core/peer_dmabuf/run.py --source-root /path/to/accepted-candidate --output /root/xdev_ext/staging/recovery-20261031/dmabuf-results/admission-candidate
python3 -I tests/core/peer_dmabuf/importer_run.py --fixture-only --output /root/xdev_ext/staging/recovery-20261031/dmabuf-results/fixture-compile
python3 -I tests/core/peer_dmabuf/importer_run.py --compile-only --source-root /path/to/accepted-candidate --output /root/xdev_ext/staging/recovery-20261031/dmabuf-results/api-compile-only
python3 -I tests/core/peer_dmabuf/importer_run.py --source-root /path/to/accepted-candidate --output /root/xdev_ext/staging/recovery-20261031/dmabuf-results/importer-candidate
```

Exit 0 with FIXTURE_COMPILES means only the independent fixture compiled. Exit 0 with PRODUCTION_COMPILES means the production source linked against the boundary adapters, without running any behavior cases. Exit 3/NOT_IMPLEMENTED means the component or public header is absent. Exit 2/SETUP_ERROR means compiler, interface, extraction or tool setup failed. Only actual linked production execution can yield PASS (0) or FAIL (1). Each behavior runs in its own process so permanent UNKNOWN retention is preserved rather than forcibly freed between tests. This is host software correctness, not physical DMA or performance. Root registers final results in /root/xdev_ext/test-results; this test owner does not update catalog or commit.
