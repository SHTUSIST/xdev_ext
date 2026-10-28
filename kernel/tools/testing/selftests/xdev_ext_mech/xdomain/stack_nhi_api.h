/* SPDX-License-Identifier: GPL-2.0 */
/* Recording adapters around the real NHI API, used only by the host fixture. */
#ifndef XDEV_EXT_STACK_NHI_API_H
#define XDEV_EXT_STACK_NHI_API_H
struct tb_ring *stack_ring_alloc_tx(struct tb_nhi *, int, int, unsigned);
struct tb_ring *stack_ring_alloc_rx(struct tb_nhi *, int, int, unsigned, int,
				   u16, u16, void (*)(void *), void *);
void stack_ring_start(struct tb_ring *);
void stack_ring_stop(struct tb_ring *);
void stack_ring_free(struct tb_ring *);
void stack_ring_free_quarantined(struct tb_ring *);
int stack_ring_tx(struct tb_ring *, struct ring_frame *);
int stack_ring_rx(struct tb_ring *, struct ring_frame *);
#endif
