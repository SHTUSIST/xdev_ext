PYTHON ?= python3

.PHONY: check
# Host tests only: the frozen acceptance contract and the native-arm checks.
# Neither links SPDK nor opens a device.
check:
	$(PYTHON) test_contract.py -v
	$(PYTHON) test_native.py -v
