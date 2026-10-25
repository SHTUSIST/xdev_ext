#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The controller's --poll: one switch sets XDEV_EXT_MECH_STAGE_F_POLL on every stage.

xdev_ext_mech_ctl_poll_stages() is the pure helper of
tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h; every CREATE of the controller
goes through ctl_create(), which applies it.
"""
import unittest

from poll_extract import body, compile_and_run, fields, source

CTL = 'tools/xdev_ext_mech/xdev_ext_mech_ctl.c'

FIXTURE = r'''
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

int main(void)
{
	struct xdev_ext_mech_create c;
	unsigned int i, ok = 1;

	memset(&c, 0, sizeof(c));
	c.nr_stages = 3;
	c.st[0].flags = XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE;
	c.st[2].flags = XDEV_EXT_MECH_STAGE_F_FANOUT;
	xdev_ext_mech_ctl_poll_stages(&c, false);
	ok &= c.st[0].flags == (XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE) && !c.st[1].flags &&
	      c.st[2].flags == XDEV_EXT_MECH_STAGE_F_FANOUT;
	xdev_ext_mech_ctl_poll_stages(&c, true);
	for (i = 0; i < 3; i++)
		ok &= !!(c.st[i].flags & XDEV_EXT_MECH_STAGE_F_POLL);
	ok &= (c.st[0].flags & ~XDEV_EXT_MECH_STAGE_F_POLL) == (XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE);
	ok &= (c.st[2].flags & ~XDEV_EXT_MECH_STAGE_F_POLL) == XDEV_EXT_MECH_STAGE_F_FANOUT;
	ok &= !c.st[3].flags;
	{
		char line[64];

		ok &= xdev_ext_mech_ctl_poll_line(line, sizeof(line), 2) &&
		      !strcmp(line, "XDEV_EXT_MECH_POLL stages=2\n");
	}
	printf("ok=%u\n", ok);
	return 0;
}
'''


class CtlPoll(unittest.TestCase):
    def test_helper_sets_poll_on_used_stages_only(self):
        code, out = compile_and_run(FIXTURE)
        self.assertEqual(code, 0, out)
        self.assertEqual(fields(out)['ok'], 1, out)

    def test_every_create_applies_the_switch(self):
        text = source(CTL)
        create = body(text, 'ctl_create')
        self.assertIn('xdev_ext_mech_ctl_poll_stages(c, ctl_poll_all);', create)
        self.assertIn('xdev_ext_mech_ctl_poll_line(line, sizeof(line), c->nr_stages)', create)
        self.assertLess(create.index('xdev_ext_mech_ctl_poll_stages'), create.index('XDEV_EXT_MECH_OP_CREATE'))
        self.assertEqual(text.count('XDEV_EXT_MECH_OP_CREATE'), 1, 'one CREATE path in the controller')
        self.assertIn('{ "poll", no_argument, NULL, OPT_POLL },', text)
        self.assertIn('case OPT_POLL: ctl_poll_all = true; break;', text)
        self.assertIn('[--poll]', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
