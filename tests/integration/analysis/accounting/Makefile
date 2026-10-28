# SPDX-License-Identifier: GPL-2.0
# Host tests of the shared evaluation accounting tools; no counter is opened.
PYTHON ?= python3

.PHONY: check
check:
	$(PYTHON) test_cpu_account.py
	$(PYTHON) test_iommu_receipt.py
	$(PYTHON) test_check_eval_data_provenance.py
