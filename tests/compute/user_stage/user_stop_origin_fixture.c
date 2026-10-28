/* SPDX-License-Identifier: GPL-2.0 */
/* Independent origin assertions layered onto the complete strict USER/core
 * composition. No completion, publication or native-error latch is replaced. */
static int origin_case(const char *mode)
{
 REQUIRE(!real_setup(true,false,false,false),"strict USER binds through actual CREATE/bind");
 struct xdev_ext_mech_batch *b=start(0,4092);
 REQUIRE(b&&us->nr_held==1,"real producer completion publishes held USER work");
 struct xdev_ext_user_ready r=take();
 REQUIRE(held_out_pending(b),"USER owns OUT_PENDING before completion");
 REQUIRE(!session.last_err&&!b->locally_cancelled,"accepted work starts without native error or local cancellation");
 if(!strcmp(mode,"active-zero")){
  post(r.slot,r.ticket,0);progress();drain();
  CHECK(accepts[2]==1&&!ends,"ACTIVE zero reaches downstream exactly once");
  CHECK(!b->locally_cancelled&&!session.last_err,"ACTIVE zero is not relabeled as local cancellation");
  callback(2,0);drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_DONE&&!end_err,"ordinary ACTIVE path completes successfully");
  goto done;
 }
 /* Exercise real session_stop, rather than changing the state directly. */
 xdev_ext_mech_session_stop(&session,0);
 REQUIRE(!session.last_err&&!session.stop_err,"clean STOP closes admission without inventing an error");
 progress();drain();
 REQUIRE(us->nr_held==1&&held_out_pending(b)&&!ends,"STOP alone does not declare external work quiesced");
 if(!strcmp(mode,"stale-duplicate")){
  struct xdev_ext_mech_completion saved=b->completion;
  struct xdev_ext_mech_life saved_life=life[0];
  int ret=xdev_ext_mech_batch_external_complete(b,r.ticket+1,-EIO,XDEV_EXT_MECH_EXTERNAL_UNKNOWN);
  CHECK(ret==-ESTALE,"wrong ticket is rejected before claim");
  CHECK(!memcmp(&saved,&b->completion,sizeof(saved))&&!memcmp(&saved_life,&life[0],sizeof(saved_life))&&!b->locally_cancelled&&!session.last_err,
        "stale direct completion cannot change origin, native latch or lifecycle");
  post(r.slot,r.ticket+1,-EIO);progress();drain();
  CHECK(us->nr_held==1&&!ends&&!session.last_err&&!b->locally_cancelled,"stale USER entry cannot attribute an error to held work");
  post(r.slot,r.ticket,0);progress();drain();
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==-ESHUTDOWN,"matching late zero safely cancels the batch");
  CHECK(!session.last_err&&b->locally_cancelled,"matching late zero retains a clean native latch");
  saved=b->completion;saved_life=life[0];bool origin=b->locally_cancelled;
  ret=xdev_ext_mech_batch_external_complete(b,r.ticket,-EIO,XDEV_EXT_MECH_EXTERNAL_UNKNOWN);
  CHECK(ret==-ESTALE,"duplicate completion is rejected after ticket consumption");
  CHECK(!memcmp(&saved,&b->completion,sizeof(saved))&&!memcmp(&saved_life,&life[0],sizeof(saved_life))&&b->locally_cancelled==origin&&!session.last_err,
        "duplicate cannot replace cancellation origin or create a native error");
  post(r.slot,r.ticket,-EIO);progress();drain();
  CHECK(ends==1&&!session.last_err&&b->locally_cancelled==origin,"duplicate USER done cannot complete or mutate origin twice");
  goto stopped;
 }
 if(!strcmp(mode,"core-error")){
  CHECK(!xdev_ext_mech_batch_external_complete(b,r.ticket,-EIO,XDEV_EXT_MECH_EXTERNAL_QUIESCED),"raw QUIESCED error wins its real core claim");
  drain();
 }else if(!strcmp(mode,"core-unknown")){
  CHECK(!xdev_ext_mech_batch_external_complete(b,r.ticket,0,XDEV_EXT_MECH_EXTERNAL_UNKNOWN),"raw UNKNOWN wins its real core claim");
  drain();
 }else if(!strcmp(mode,"user-unknown")){
  jiffies+=1000;progress();drain();
 }else{
  if(!strcmp(mode,"user-badlen"))us->slots[r.slot].f[1].out_len=4091;
  post(r.slot,r.ticket,!strcmp(mode,"user-error")?-EIO:!strcmp(mode,"user-protocol")?7:0);
  progress();drain();
 }
 if(!strcmp(mode,"user-zero")){
  CHECK(ends==1&&end_how==XDEV_EXT_MECH_END_ABORT&&end_err==-ESHUTDOWN,"late valid zero aborts only as STOP cancellation");
  CHECK(!session.last_err&&!session.stop_err,"late valid zero must not turn clean STOP into a native failure");
  CHECK(b->locally_cancelled,"synthetic STOP completion carries explicit local origin");
 }else{
  int want=!strcmp(mode,"user-unknown")?-ETIMEDOUT:
           (!strcmp(mode,"user-protocol")||!strcmp(mode,"user-badlen"))?-EPROTO:-EIO;
  bool unknown=strcmp(mode,"core-error")&&strcmp(mode,"user-badlen");
  CHECK(ends==1&&end_err==want,"real error survives STOP without being overwritten by cancellation");
  CHECK(session.last_err==want,"real core publication latches the originating error after STOP");
  CHECK(!b->locally_cancelled,"real errors and UNKNOWN cannot be laundered as local cancellation");
  CHECK(end_how==(unknown?XDEV_EXT_MECH_END_SEQUESTER:XDEV_EXT_MECH_END_ABORT),"UNKNOWN retains custody while explicit quiescence permits safe abort");
  if(unknown)CHECK(quarantined(b),"UNKNOWN frames remain quarantined");
 }
stopped:
 CHECK(!attempts[2],"no STOP completion reaches downstream");
done:
 CHECK(!warnings,"actual production warning count is zero");
 printf("USER_STOP_ORIGIN %s last_err=%d stop_err=%d local=%u end=%d status=%d failures=%d\n",
        mode,session.last_err,session.stop_err,b->locally_cancelled,end_how,end_err,failures);
 return !!failures;
}
int main(int argc,char **argv){return argc==2?origin_case(argv[1]):2;}
