// SPDX-License-Identifier: GPL-2.0

/*
 * Build the shipped five-backend reference policy as a test_progs skeleton.
 * The object under test is the loader's object: this file adds no programs,
 * maps or variables, so the two cannot drift.  The shipped source finds
 * xdev_ext_reference_policy_abi.h next to itself, so no extra include path is
 * needed.
 */
#include "../../../../xdev_ext_reference_policy.bpf.c"
