/* Minimal Windows reader, cross-built in WSL. No CRT, WMI, SetCommState,
 * DTR/RTS changes, retries or forced process termination. CreateFile can
 * still wait on usbser: keep one opener until device disconnects. */
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
static WCHAR args[5][1024], path[1200], device[32];
static unsigned char bytes[4096];
static HANDLE events, capture;

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
    return n;
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
    if(count!=4){text(GetStdHandle((DWORD)-11),"Usage: rawcom COMnumber seconds existing-output-directory\r\n");return 2;}
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
    HANDLE h=CreateFileW(device,0x80000000,0,0,3,0,0);
    DWORD result=0;
    if(h==INVALID){result=GetLastError();event("OPEN_ERROR code=",result);goto done;}
    event("OPEN_OK elapsed_ms=",GetTickCount64()-begin);
    struct Timeouts t={0,0,250,0,0};
    if(!SetCommTimeouts(h,&t)){result=GetLastError();event("TIMEOUT_SETUP_ERROR code=",result);goto closed;}
    begin=GetTickCount64();
    while(GetTickCount64()-begin<(U64)seconds*1000){
        DWORD n=0,w=0;
        if(!ReadFile(h,bytes,sizeof(bytes),&n,0)){result=GetLastError();event("READ_ERROR code=",result);break;}
        if(n){
            if(!WriteFile(capture,bytes,n,&w,0)||w!=n){result=GetLastError();event("FILE_ERROR code=",result);break;}
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
