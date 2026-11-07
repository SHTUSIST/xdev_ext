# SPDX-License-Identifier: GPL-2.0-only
.DEFAULT_GOAL := help
PYTHON ?= python3
.PHONY: help source-view prepare-linux prepare-nvidia test host-check cross-device-check lib cli ce-random-check ce-random-native-build
help:
	@echo 'source-view                  create isolated native input copies (offline)'
	@echo 'prepare-linux / prepare-nvidia assemble exact pinned upstream + project overlay'
	@echo 'test TEST=tests/<canonical.py> run one test through the source view'
	@echo 'host-check                   standalone host production-rule contracts'
	@echo 'cross-device-check           host checks of guest-tested cross-device features'
	@echo 'lib / cli                    build library / CLI in the source view'
	@echo 'ce-random-check              host rules and independent oracle; no device runtime'
	@echo 'ce-random-native-build       compile native runner/BPF only; requires libbpf and target BTF'
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
cross-device-check:
	$(PYTHON) tools/ci/check_cross_device_host.py --log-dir build/cross-device-check $(ARGS)
lib:
	$(PYTHON) tools/run.py --cwd src/cli make lib $(ARGS)
cli:
	$(PYTHON) tools/run.py --cwd src/cli make xdev_ext_mech_ctl $(ARGS)
ce-random-check:
	$(PYTHON) tests/compute/ce/random_target/run.py --suite all
	$(PYTHON) tests/compute/ce/random_target/runtime_validate.py --suite all
	$(PYTHON) tests/compute/ce/random_target/range_lease.py --suite all
	$(PYTHON) tests/compute/ce/random_target/actual_entry.py --suite all
	$(PYTHON) tests/compute/ce/random_target/request_builders.py --suite all
	$(PYTHON) tests/integration/nvme_ce_random/control_test.py
	$(PYTHON) tests/integration/nvme_ce_random/control_test.py --case key-end
	$(PYTHON) tests/integration/nvme_ce_random/test_expected.py
	$(PYTHON) tests/integration/nvme_ce_random/test_native_bounds.py
	$(PYTHON) tests/integration/nvme_ce_random/test_generator.py
ce-random-native-build:
	$(PYTHON) tests/integration/nvme_ce_random/build.py $(ARGS)
