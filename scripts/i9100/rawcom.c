/* Windows capture/control client, cross-built in WSL. Control sessions request
 * DTR once so a late opener gets a fresh READY/BUILD. No CRT, WMI, SetCommState,
 * RTS changes, retries or forced termination; retain a blocked opener. */
typedef unsigned long DWORD;
typedef unsigned long long U64;
typedef int BOOL;
typedef void *HANDLE;
typedef unsigned short WCHAR;
#define API __declspec(dllimport)
API WCHAR *GetCommandLineW(void);
API HANDLE CreateFileW(const WCHAR *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
API BOOL ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
API BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
API BOOL FlushFileBuffers(HANDLE);
API BOOL CloseHandle(HANDLE);
API DWORD GetLastError(void);
API U64 GetTickCount64(void);
API HANDLE GetStdHandle(DWORD);
API HANDLE CreateMutexW(void *,BOOL,const WCHAR *);
API void ExitProcess(DWORD);
struct Timeouts { DWORD interval,multiplier,constant,write_multiplier,write_constant; };
API BOOL SetCommTimeouts(HANDLE,struct Timeouts *);
API BOOL EscapeCommFunction(HANDLE,DWORD);
#define INVALID ((HANDLE)(long long)-1)
static WCHAR args[8][1024], path[1200], device[32];
static unsigned char bytes[4096];
static HANDLE events, capture;
#include "control-session.h"
static struct ControlSession protocol;
static char verb[24], wire[64];

static void text(HANDLE h,const char *s)
{ DWORD n=0,written; while(s[n])n++; WriteFile(h,s,n,&written,0); }
static void event(const char *label,U64 value)
{
    char number[24]; unsigned n=0;
    do { number[n++]=(char)('0'+value%10); value/=10; } while(value);
    for(unsigned a=0,b=n-1;a<b;a++,b--){char t=number[a];number[a]=number[b];number[b]=t;}
    number[n]=0;
    text(events,label);text(events,number);text(events,"\r\n");FlushFileBuffers(events);
}
static int parse(void)
{
    WCHAR *s=GetCommandLineW(); unsigned n=0;
    while(*s&&n<8){
        while(*s==' '||*s=='\t')s++;
        if(!*s)break;
        unsigned i=0,quote=0;
        while(*s&&(quote||(*s!=' '&&*s!='\t'))){
            if(*s=='"'){quote=!quote;s++;continue;}
            if(i==1023)return 0;
            args[n][i++]=*s++;
        }
        args[n++][i]=0;
    }
    return *s ? 0 : (int)n;
}
static void filename(const WCHAR *suffix)
{
    unsigned i=0,j=0;
    while(args[3][i]){path[i]=args[3][i];i++;}
    path[i++]='\\';
    while(suffix[j])path[i++]=suffix[j++];
    path[i]=0;
}
static DWORD run(void)
{
    int count=parse();
    if(count!=4 && count!=6 && count!=8){text(GetStdHandle((DWORD)-11),"Usage: rawcom COMnumber seconds existing-output-directory [-Send ping|status|root-status|reboot|reboot-download [-Expect 16hex-build-tag]]\r\nSend: request DTR, wait READY, ping, capture, then send final command; one open, no retries.\r\n");return 2;}
    if(count>=6) {
        const WCHAR *flag=(const WCHAR *)L"-Send";
        unsigned j=0; while(flag[j]&&flag[j]==args[4][j])j++;
        if(flag[j]||args[4][j])return 2;
        for(j=0;args[5][j];j++) {
            if(j>=sizeof(verb)-1||args[5][j]>127)return 2;
            verb[j]=(char)args[5][j];
        }
        if(!same(verb,"ping")&&!same(verb,"status")&&!same(verb,"root-status")&&!same(verb,"reboot")&&!same(verb,"reboot-download"))return 2;
    }
    if(count==8) {
        const WCHAR *flag=(const WCHAR *)L"-Expect";
        unsigned j=0;while(flag[j]&&flag[j]==args[6][j])j++;
        if(flag[j]||args[6][j])return 2;
        for(j=0;j<16;j++) {
            WCHAR c=args[7][j];
            if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return 2;
            protocol.expected_tag[j]=(char)c;
        }
        if(args[7][16])return 2;
    }
    WCHAR *p=args[1];
    if(p[0]!='C'||p[1]!='O'||p[2]!='M'||!p[3])return 2;
    unsigned i=3;
    for(;p[i];i++)if(p[i]<'0'||p[i]>'9'||i>=20)return 2;
    unsigned seconds=0;
    for(i=0;args[2][i];i++){
        if(args[2][i]<'0'||args[2][i]>'9')return 2;
        seconds=seconds*10+args[2][i]-'0';if(seconds>3600)return 2;
    }
    if(!seconds)return 2;
    HANDLE lock=CreateMutexW(0,1,(const WCHAR *)L"Local\\I9100OneShotRawReader");
    if(!lock||GetLastError()==183){if(lock)CloseHandle(lock);return 33;}
    filename((const WCHAR *)L"events.txt");
    events=CreateFileW(path,0x40000000,1,0,1,0,0);
    if(events==INVALID){CloseHandle(lock);return 3;}
    filename((const WCHAR *)L"received.bin");
    capture=CreateFileW(path,0x40000000,1,0,1,0,0);
    if(capture==INVALID){CloseHandle(events);CloseHandle(lock);return 3;}
    device[0]='\\';device[1]='\\';device[2]='.';device[3]='\\';
    for(i=0;p[i];i++)device[4+i]=p[i];device[4+i]=0;
    U64 begin=GetTickCount64(),total=0;
    event("OPEN_BEGIN tick_ms=",begin);
    HANDLE h=CreateFileW(device,count>=6?0xc0000000:0x80000000,0,0,3,0,0);
    DWORD result=0;
    if(h==INVALID){result=GetLastError();event("OPEN_ERROR code=",result);goto done;}
    event("OPEN_OK elapsed_ms=",GetTickCount64()-begin);
    struct Timeouts t={0,0,250,0,1000};
    if(!SetCommTimeouts(h,&t)){result=GetLastError();event("TIMEOUT_SETUP_ERROR code=",result);goto closed;}
    if(count>=6) {
        /* Kernel SET_CONTROL_LINE_STATE re-advertises identity. The original
         * boot banner may already have been consumed before this open. */
        event("DTR_BEGIN tick_ms=",GetTickCount64());
        if(!EscapeCommFunction(h,5)){result=GetLastError();event("DTR_ERROR code=",result);goto closed;}
        event("DTR_OK tick_ms=",GetTickCount64());
    }
    begin=GetTickCount64();
    unsigned phase=count>=6?0:2, seq=(unsigned)GetTickCount64();
    if(!seq || seq>0xfffffffcU) seq=1;
    U64 deadline=begin+(count>=6?90000:(U64)seconds*1000);
    while(1){
        U64 now=GetTickCount64();
        if(count>=6 && (protocol.rejected || (now>=deadline && phase!=2))) {
            result=40;event("CONTROL_TIMEOUT_OR_REJECT phase=",phase);break;
        }
        int send=0;
        if(count>=6 && phase==0 && protocol.ready && protocol.tag_seen) {
            event("CONTROL_READY tick_ms=",now);send=1;phase=1;deadline=now+10000;
        } else if(count>=6 && phase==1 && protocol.matched) {
            event("PING_OK tick_ms=",now);phase=2;deadline=now+(U64)seconds*1000;
        } else if(phase==2 && now>=deadline) {
            if(count==4 || same(verb,"ping"))break;
            send=1;phase=3;deadline=now+10000;
        } else if(count>=6 && phase==3 && protocol.matched) {
            if(same(verb,"root-status")) {
                text(events,"ROOT_STATE ");text(events,protocol.root_state);text(events,"\r\n");
            }
            event("COMMAND_ACK tick_ms=",now);break;
        }
        if(send) {
            DWORD written=0;
            unsigned len=control_request(&protocol,wire,++seq,phase==1?"ping":verb);
            event("SEND_BEGIN sequence=",seq);
            if(!WriteFile(h,wire,len,&written,0)||written!=len){
                result=GetLastError();if(!result)result=41;
                event("SEND_ERROR code=",result);break;
            }
            event("SEND_OK bytes=",written);
        }
        DWORD n=0,w=0;
        if(!ReadFile(h,bytes,sizeof(bytes),&n,0)){result=GetLastError();event("READ_ERROR code=",result);break;}
        if(n){
            if(!WriteFile(capture,bytes,n,&w,0)||w!=n){result=GetLastError();if(!result)result=42;event("FILE_ERROR code=",result);break;}
            if(count>=6)for(unsigned j=0;j<n;j++)control_receive(&protocol,bytes[j]);
            total+=n;FlushFileBuffers(capture);event("RECEIVED total=",total);
        }
    }
closed:
    CloseHandle(h);
done:
    event("DONE bytes=",total);
    CloseHandle(capture);CloseHandle(events);CloseHandle(lock);return result;
}
void entry(void){ExitProcess(run());}
