# SPDX-License-Identifier: GPL-2.0
KDIR ?= /lib/modules/$(shell uname -r)/build
.PHONY: all clean test
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
test:
	python3 -m unittest discover -s . -p 'test_*.py' -v
