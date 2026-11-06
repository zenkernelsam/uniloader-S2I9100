#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "control-session.h"
static void receive(struct ControlSession *s, const char *p)
{ while(*p)control_receive(s,(unsigned char)*p++); }
int main(void)
{
    struct ControlSession s={0}; char wire[64];
    receive(&s,"noise\nI9CTL1 READY control=1\nI9CTL1 BUILD 1234567890abcdef\n");
    assert(s.ready && s.tag_seen && !s.rejected);
    assert(control_request(&s,wire,0x12ab,"ping")==21);
    assert(!strcmp(wire,"I9CTL1 000012ab ping\n"));
    receive(&s,"I9CTL1 000012ac OK control=1\n");assert(!s.matched);
    receive(&s,"I9CTL1 000012ab OK control=1\n");assert(s.matched);
    control_request(&s,wire,0x12ac,"reboot-download");
    receive(&s,"I9CTL1 000012ac OK reboot-download\n");assert(s.matched);
    control_request(&s,wire,0x12ad,"ping");
    receive(&s,"I9CTL1 000012ad ERR disabled\n");assert(s.rejected && !s.matched);
    memset(&s,0,sizeof(s));copy(s.expected_tag,"1234567890abcdef");
    receive(&s,"I9CTL1 READY control=1\nI9CTL1 BUILD 1234567890abcdee\n");
    assert(s.rejected && !s.tag_seen);
    memset(&s,0,sizeof(s));
    for(unsigned i=0;i<1000;i++)control_receive(&s,'x');
    receive(&s,"I9CTL1 READY control=1\n");assert(!s.ready);
    receive(&s,"I9CTL1 READY control=1\n");assert(s.ready);
    puts("PASS host framing, correlated ACK, build mismatch, overflow recovery");
}
