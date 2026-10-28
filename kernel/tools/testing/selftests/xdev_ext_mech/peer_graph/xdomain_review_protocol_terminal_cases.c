/* SPDX-License-Identifier: GPL-2.0 */
/* Class-side remote silence after explicit local incarnation failure. */
static void review_sender_terminal(void)
{
 fresh(0,0,3,65536,8192);review_require(!bind_side(&sides[0]),"sender binds independently of absent peer RX");
 review_require(!submit(&sides[0],0),"unbound peer request starts as actual TX announcement");
 /* Deliberately do not deliver to the fixture's handwritten unbound boundary.
  * The separate real ring TU proved failed reply admission and EAGAIN transfer.
  * No physical receipt or immediate remote error is assumed here. */
 run_worker_once(&sides[0]);
 review_require(!sides[0].batches[0].publishes&&!sides[0].posts&&!sides[0].live,"no terminal or native ownership is fabricated before the deadline");
 advance_ms(15000);run_worker_once(&sides[0]);
 review_require(wire_count(&sides[0],XDEV_EXT_XD_CANCEL)==1&&!sides[0].batches[0].publishes,"actual policy withdraws silent peer request at immutable deadline");
 advance_ms(1000);run_worker_once(&sides[0]);
 review_require(sides[0].link_failures&&sides[0].last_link_error==-ETIMEDOUT,"withdrawal hard deadline ends the waiting sender incarnation");
 review_require(sides[0].batches[0].publishes==1&&sides[0].batches[0].status<0&&!sides[0].batches[0].sequester,"unaccepted sender request reaches exact single error terminal CQE");
 review_require(!sides[0].posts&&!sides[0].live&&!sides[0].released_q0&&!sides[0].session.native_controls,"unaccepted request cannot leave native/UNKNOWN custody behind");
 fprintf(stderr,"REVIEW-P TERMINAL sender publishes=%u status=%d native_posts=%u now=%llu\n",sides[0].batches[0].publishes,sides[0].batches[0].status,sides[0].posts,(unsigned long long)host_ns);
}
int main(int argc,char **argv)
{
 if(argc==2&&!strcmp(argv[1],"sender_terminal")){review_sender_terminal();return 0;}
 return review_protocol_case_main(argc,argv);
}
