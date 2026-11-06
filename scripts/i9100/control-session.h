/* Bounded stream framing shared by the Win32 client and offline tests. */
struct ControlSession {
    char line[128], expected[64], expected_tag[17];
    unsigned used, drop, ready, matched, rejected, tag_seen;
};
static int same(const char *a, const char *b)
{ while (*a && *a == *b) { a++; b++; } return *a == *b; }
static unsigned copy(char *dst, const char *src)
{ unsigned n=0; while(src[n]) {dst[n]=src[n];n++;} dst[n]=0;return n; }
static unsigned control_request(struct ControlSession *s, char *wire,
                                unsigned seq, const char *verb)
{
    static const char hex[]="0123456789abcdef";
    unsigned n=copy(wire,"I9CTL1 ");
    for(unsigned i=0;i<8;i++) wire[n++]=hex[(seq>>(28-i*4))&15];
    wire[n++]=' '; n+=copy(wire+n,verb); wire[n++]='\n'; wire[n]=0;
    for(unsigned i=0;i<16;i++) s->expected[i]=wire[i];
    copy(s->expected+16, same(verb,"ping")||same(verb,"status") ? "OK control=1" :
         same(verb,"reboot") ? "OK reboot" : "OK reboot-download");
    s->matched=s->rejected=0;
    return n;
}
static void control_receive(struct ControlSession *s, unsigned char c)
{
    if(c=='\n') {
        s->line[s->used]=0;
        if(!s->drop) {
            if(same(s->line,"I9CTL1 READY control=1")) s->ready=1;
            if(same(s->line,"I9CTL1 READY control=0")) s->rejected=1;
            if(s->used==29) {
                const char *prefix="I9CTL1 BUILD "; unsigned j=0;
                while(j<13 && s->line[j]==prefix[j])j++;
                if(j==13) {
                    for(;j<29;j++) if(!((s->line[j]>='0'&&s->line[j]<='9')||
                        (s->line[j]>='a'&&s->line[j]<='f')))break;
                    if(j==29) {
                        if(!s->expected_tag[0] || same(s->line+13,s->expected_tag))s->tag_seen=1;
                        else s->rejected=1;
                    }
                }
            }
            if(s->expected[0] && same(s->line,s->expected)) s->matched=1;
            /* A response with our exact sequence but any other result fails. */
            unsigned i=0;
            while(i<16 && s->expected[i] && s->line[i]==s->expected[i]) i++;
            if(i==16 && !same(s->line,s->expected)) s->rejected=1;
        }
        s->used=s->drop=0;
    } else if(c<32 || c>126 || s->used==sizeof(s->line)-1) s->drop=1;
    else if(!s->drop) s->line[s->used++]=(char)c;
}
