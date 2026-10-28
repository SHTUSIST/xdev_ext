/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SESSION_PROGRAMS_WIRE_H
#define SESSION_PROGRAMS_WIRE_H
/* Frozen independent wire: STAGE_DIAG stays 11, CREATE_PROGRAMS appends 12. */
#define SP_CREATE_PROGRAMS 12U
#define SP_PRIVATE 1U
struct sp_create_programs_wire {
 __u32 size,version;
 __s32 program_fds[4];
 struct xdev_ext_mech_create_with_report request;
};
_Static_assert(XDEV_EXT_MECH_MAX_STAGES==4,"four accepted selectors");
_Static_assert(XDEV_EXT_MECH_OP_STAGE_DIAG==11,"existing diagnostic opcode");
_Static_assert(offsetof(struct sp_create_programs_wire,request)==24,"input selectors precede report request");
_Static_assert(sizeof(struct sp_create_programs_wire)==520,"frozen new wrapper");
_Static_assert(sizeof(struct xdev_ext_mech_create_with_report)==496,"old envelope unchanged");
#endif
