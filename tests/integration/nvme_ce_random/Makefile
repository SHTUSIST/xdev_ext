# SPDX-License-Identifier: GPL-2.0
PYTHON ?= python3
CANONICAL_ROOT ?= $(if $(XDEV_EXT_CANONICAL_ROOT),$(XDEV_EXT_CANONICAL_ROOT),$(abspath ../../..))
.DEFAULT_GOAL := check
.PHONY: check build
check:
	@test -f "$(CANONICAL_ROOT)/source-layout.json"
	$(PYTHON) "$(CANONICAL_ROOT)/tests/integration/nvme_ce_random/control_test.py"
	$(PYTHON) "$(CANONICAL_ROOT)/tests/integration/nvme_ce_random/control_test.py" --case key-end
	$(PYTHON) "$(CANONICAL_ROOT)/tests/integration/nvme_ce_random/test_expected.py"
	$(PYTHON) "$(CANONICAL_ROOT)/tests/integration/nvme_ce_random/test_native_bounds.py"
	$(PYTHON) "$(CANONICAL_ROOT)/tests/integration/nvme_ce_random/test_generator.py"
build:
	@test -f "$(CANONICAL_ROOT)/source-layout.json"
	$(PYTHON) "$(CANONICAL_ROOT)/tests/integration/nvme_ce_random/build.py" $(ARGS)
