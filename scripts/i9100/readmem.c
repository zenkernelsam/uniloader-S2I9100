/* Windows read-memory client for the kernel I9CTL1 maintenance channel.
 * Sends "I9CTL1 <seq> read-memory <pa8> <len8>\n", waits for the
 * "I9CTL1 <seq> OK DATA <pa8> <len8>\n" header, then writes exactly <len>
 * raw payload bytes to the output file. Same no-CRT/no-SetCommState style
 * as rawcom.c: one open, timeouts only, no retries. */
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
#define INVALID ((HANDLE)(long long)-1)
static WCHAR args[5][1024], device[32];
static unsigned char bytes[4096];

static void text(HANDLE h,const char *s)
{ DWORD n=0,written; while(s[n])n++; WriteFile(h,s,n,&written,0); }
static void number(HANDLE h,U64 value)
{
    char buf[24]; unsigned n=0;
    do { buf[n++]=(char)('0'+value%10); value/=10; } while(value);
    for(unsigned a=0,b=n-1;a<b;a++,b--){char t=buf[a];buf[a]=buf[b];buf[b]=t;}
    DWORD w; WriteFile(h,buf,n,&w,0);
}
static void msg(const char *s,U64 v)
{ HANDLE e=GetStdHandle((DWORD)-12); text(e,s); number(e,v); text(e,"\r\n"); }

static int parse(void)
{
    WCHAR *s=GetCommandLineW(); unsigned n=0;
    while(*s&&n<5){
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
static unsigned hexw(const WCHAR *s)
{
    unsigned v=0,n=0;
    for(;s[n];n++){
        WCHAR c=s[n]; unsigned d;
        if(c>='0'&&c<='9')d=c-'0';
        else if(c>='a'&&c<='f')d=c-'a'+10;
        else if(c>='A'&&c<='F')d=c-'A'+10;
        else return 0xffffffffU;
        if(n>=8)return 0xffffffffU;
        v=(v<<4)|d;
    }
    return n?v:0xffffffffU;
}

/* Reply matcher: first match "\nI9CTL1 <seq8> ", then collect the answer
 * line. "OK DATA <pa8> <len8>" means the payload starts on the next byte;
 * "ERR ..." fails fast. Binary payload may contain \n, so from the header
 * newline on we count raw bytes, never lines. */
static char mark[24], line[48];
static unsigned mark_len, mark_at, line_at, stage;
static void mark_setup(unsigned seq)
{
    static const char hex[]="0123456789abcdef";
    unsigned n=0;
    mark[n++]='\n';
    const char *p="I9CTL1 "; while(*p)mark[n++]=*p++;
    for(unsigned i=0;i<8;i++)mark[n++]=hex[(seq>>(28-i*4))&15];
    mark[n++]=' ';
    mark_len=n; mark_at=line_at=stage=0;
}
static int prefix(const char *s)
{
    unsigned i=0;
    while(s[i]&&line[i]==s[i])i++;
    return !s[i];
}
/* Feed one byte; returns 1 when the DATA header just completed,
 * 2 for an ERR reply, else 0. */
static int feed(unsigned char c)
{
    if(!stage){
        if(c==mark[mark_at]){
            if(++mark_at==mark_len){stage=1;line_at=0;}
        } else mark_at=(c=='\n')?1:0;
        return 0;
    }
    if(c=='\n'){
        int r;
        line[line_at]=0;
        r=prefix("OK DATA ")?1:prefix("ERR")?2:0;
        stage=0;mark_at=0;
        return r;
    }
    if(line_at<sizeof(line)-1)line[line_at++]=c;
    else {stage=0;mark_at=0;} /* overlong line: resync */
    return 0;
}

static DWORD run(void)
{
    int count=parse();
    if(count!=5){
        text(GetStdHandle((DWORD)-11),
            "Usage: readmem COMnumber hexaddr hexlen output-file\r\n");
        return 2;
    }
    WCHAR *p=args[1];
    if(p[0]!='C'||p[1]!='O'||p[2]!='M'||!p[3])return 2;
    unsigned i=3;
    for(;p[i];i++)if(p[i]<'0'||p[i]>'9'||i>=20)return 2;
    unsigned addr=hexw(args[2]), len=hexw(args[3]);
    if(addr==0xffffffffU||!len||len>32768)return 2;

    HANDLE lock=CreateMutexW(0,1,(const WCHAR *)L"Local\\I9100OneShotRawReader");
    if(!lock||GetLastError()==183){if(lock)CloseHandle(lock);return 33;}
    HANDLE out=CreateFileW(args[4],0x40000000,1,0,2,0,0);
    if(out==INVALID){CloseHandle(lock);return 3;}
    device[0]='\\';device[1]='\\';device[2]='.';device[3]='\\';
    for(i=0;p[i];i++)device[4+i]=p[i];device[4+i]=0;

    HANDLE h=CreateFileW(device,0xc0000000,0,0,3,0,0);
    DWORD result=0;
    if(h==INVALID){result=GetLastError();msg("OPEN_ERROR code=",result);goto done;}
    { struct Timeouts t={0,0,250,0,1000};
      if(!SetCommTimeouts(h,&t)){result=GetLastError();msg("TIMEOUT_ERROR code=",result);goto closed;} }

    unsigned seq=(unsigned)GetTickCount64();
    if(!seq||seq>0xfffffffcU)seq=1;
    mark_setup(seq);
    { static const char hex[]="0123456789abcdef";
      char wire[64]; unsigned n=0;
      const char *s="I9CTL1 "; while(*s)wire[n++]=*s++;
      for(i=0;i<8;i++)wire[n++]=hex[(seq>>(28-i*4))&15];
      wire[n++]=' ';
      s="read-memory "; while(*s)wire[n++]=*s++;
      for(i=0;i<8;i++)wire[n++]=hex[(addr>>(28-i*4))&15];
      wire[n++]=' ';
      for(i=0;i<8;i++)wire[n++]=hex[(len>>(28-i*4))&15];
      wire[n++]='\n';
      DWORD w=0;
      if(!WriteFile(h,wire,n,&w,0)||w!=n){
          result=GetLastError();if(!result)result=41;
          msg("SEND_ERROR code=",result);goto closed;
      }
    }
    msg("SENT addr=",addr);msg("SENT len=",len);

    /* Wait for header then collect exactly len bytes. Progress every 64K. */
    unsigned got=0,header=0,next_report=65536;
    U64 deadline=GetTickCount64()+600000; /* 10 min ceiling */
    U64 last_rx=GetTickCount64();
    while(got<len){
        DWORD n=0,w=0;
        if(!ReadFile(h,bytes,sizeof(bytes),&n,0)){
            result=GetLastError();msg("READ_ERROR code=",result);goto closed;
        }
        if(!n){
            if(GetTickCount64()>deadline||GetTickCount64()-last_rx>120000){
                msg(header?"STALL got=":"NO_HEADER got=",got);
                result=header?43:44;goto closed;
            }
            continue;
        }
        last_rx=GetTickCount64();
        if(!header){
            for(i=0;i<n;i++){
                int r=feed(bytes[i]);
                if(r==2){msg("ERR_REPLY line_at=",line_at);
                    result=45;goto closed;}
                if(r==1){header=1;msg("HEADER pos=",i);break;}
            }
            if(!header)continue;
            /* remaining bytes in this buffer are payload */
            unsigned start=i+1,avail=n-start;
            if(avail){
                DWORD w2=0;unsigned take=avail>len?len:avail;
                if(!WriteFile(out,bytes+start,take,&w2,0)||w2!=take){
                    result=GetLastError();msg("FILE_ERROR code=",result);goto closed;
                }
                got+=take;
            }
            continue;
        }
        unsigned take=n>len-got?len-got:n;
        if(!WriteFile(out,bytes,take,&w,0)||w!=take){
            result=GetLastError();msg("FILE_ERROR code=",result);goto closed;
        }
        got+=take;
        if(got>=next_report){msg("GOT bytes=",got);next_report+=65536;}
    }
    FlushFileBuffers(out);
    msg("DONE bytes=",got);
closed:
    CloseHandle(h);
done:
    CloseHandle(out);CloseHandle(lock);return result;
}
void entry(void){ExitProcess(run());}
