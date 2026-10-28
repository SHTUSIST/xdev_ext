PYTHON ?= python3

.PHONY: check
check:
	@command -v redis-server >/dev/null || { echo 'redis-server is a required test dependency' >&2; exit 1; }
	@command -v cc >/dev/null || { echo 'cc is required for the preload mapping control' >&2; exit 1; }
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s . -p 'test_*.py' -v
