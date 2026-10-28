# SPDX-License-Identifier: GPL-2.0-only
.DEFAULT_GOAL := help
PYTHON ?= python3
.PHONY: help source-view prepare-linux prepare-nvidia test host-check lib cli
help:
	@echo 'source-view                  create isolated native input copies (offline)'
	@echo 'prepare-linux / prepare-nvidia assemble exact pinned upstream + project overlay'
	@echo 'test TEST=tests/<canonical.py> run one test through the source view'
	@echo 'host-check                   standalone host production-rule contracts'
	@echo 'lib / cli                    build library / CLI in the source view'
source-view:
	$(PYTHON) tools/layout.py view
prepare-linux:
	$(PYTHON) tools/build/prepare_sources.py --component linux
prepare-nvidia:
	$(PYTHON) tools/build/prepare_sources.py --component nvidia
test:
	@test -n "$(TEST)" || { echo 'Set TEST to a canonical test path'; exit 2; }
	$(PYTHON) tools/test.py $(TEST) $(ARGS)
host-check:
	$(PYTHON) tools/ci/test_host.py $(ARGS)
lib:
	$(PYTHON) tools/run.py --cwd src/cli make lib $(ARGS)
cli:
	$(PYTHON) tools/run.py --cwd src/cli make xdev_ext_mech_ctl $(ARGS)
