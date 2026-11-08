PYTHON ?= python3

.PHONY: check
# Host checks only: framing, reassembly, arguments, build and hugepage plans.
# Building the program needs DPDK (build.py); running it needs net_af_xdp.
check:
	$(PYTHON) -B test_contract.py -v
