#include "../install-bootstrap-retention.h"
#include "../install-stage.h"
#include "../startup-installed.h"
#include <stdio.h>
#include <string.h>
typedef struct {WCHAR name[96];DWORD type,size;BYTE data[4096];} VALUE;
static VALUE values[20];static unsigned count;static DWORD flushError,eraseError,referenceError;
static BOOL denySecurity;static int deleteCountdown=-1;static WCHAR base[MAX_PATH],keep[65];
static int find(LPCWSTR name){for(unsigned i=0;i<count;++i)if(!_wcsicmp(values[i].name,name))return (int)i;return -1;}
static LSTATUS WINAPI query(HKEY key,LPCWSTR name,LPDWORD reserved,LPDWORD type,LPBYTE data,LPDWORD bytes){
    (void)key;(void)reserved;int i=find(name);if(i<0)return ERROR_FILE_NOT_FOUND;
    DWORD capacity=*bytes;*bytes=values[i].size;if(type)*type=values[i].type;if(!data)return 0;
    if(capacity<*bytes)return ERROR_MORE_DATA;memcpy(data,values[i].data,*bytes);return 0;
}
static LSTATUS WINAPI put(HKEY key,LPCWSTR name,DWORD reserved,DWORD type,const BYTE *data,DWORD size){
    (void)key;(void)reserved;int i=find(name);if(i<0){if(count==20)return ERROR_DISK_FULL;i=(int)count++;}
    if(size>sizeof(values[i].data))return ERROR_MORE_DATA;
    wcscpy_s(values[i].name,96,name);values[i].size=size;values[i].type=type;memcpy(values[i].data,data,size);return 0;
}
static LSTATUS WINAPI flush(HKEY key){(void)key;return flushError;}
static LSTATUS WINAPI erase(HKEY key,LPCWSTR name){(void)key;if(eraseError)return eraseError;int i=find(name);if(i<0)return ERROR_FILE_NOT_FOUND;values[i]=values[--count];return 0;}
static LSTATUS WINAPI enumerate(HKEY key,DWORD i,LPWSTR name,LPDWORD length,LPDWORD reserved,LPDWORD type,LPBYTE data,LPDWORD bytes){
    (void)key;(void)reserved;(void)type;(void)data;(void)bytes;if(i>=count)return ERROR_NO_MORE_ITEMS;
    DWORD capacity=*length;*length=(DWORD)wcslen(values[i].name);if(capacity<=*length)return ERROR_MORE_DATA;
    wcscpy_s(name,capacity,values[i].name);return 0;
}
static DWORD fixture_root(const WCHAR *hash,PB_VERIFIED_PAYLOAD *guard,HANDLE *root){
    WCHAR path[MAX_PATH];swprintf_s(path,MAX_PATH,L"%s\\%s",base,hash);
    DWORD error=pb_payload_lock_directory(path,guard);
    if(!error)*root=guard->directories[guard->directoryCount-1];else pb_payload_close(guard);return error;
}
static DWORD security(PSECURITY_DESCRIPTOR descriptor){(void)descriptor;return denySecurity?ERROR_ACCESS_DENIED:0;}
static BOOL WINAPI dispose(HANDLE file,FILE_INFO_BY_HANDLE_CLASS kind,void *info,DWORD size){
    if(!deleteCountdown){SetLastError(ERROR_SHARING_VIOLATION);return FALSE;}
    if(deleteCountdown>0)--deleteCountdown;return SetFileInformationByHandle(file,kind,info,size);
}
#define RegQueryValueExW query
#define RegSetValueExW put
#define RegEnumValueW enumerate
#define RegFlushKey flush
#define RegDeleteValueW erase
#define pb_bootstrap_root_read fixture_root
#define pb_startup_file_security security
#define SetFileInformationByHandle dispose
#include "../install-bootstrap-retention.c"
#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s (Win=%lu)\n",__LINE__,#x,GetLastError());return 1;}}while(0)
static DWORD referenced(void *context,const WCHAR *directory,BOOL *used){
    (void)context;const WCHAR *hash=wcsrchr(directory,L'\\');*used=hash && !_wcsicmp(hash+1,keep);return referenceError;
}
static void hash_text(unsigned n,WCHAR hash[65]){swprintf_s(hash,65,L"%064X",n);}
static BOOL create_files(const WCHAR *hash){
    WCHAR dir[MAX_PATH],path[MAX_PATH];swprintf_s(dir,MAX_PATH,L"%s\\%s",base,hash);
    if(!CreateDirectoryW(dir,NULL))return FALSE;
    for(unsigned i=0;i<3;++i){swprintf_s(path,MAX_PATH,L"%s\\%s",dir,bootstrapNames[i]);HANDLE h=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL);
        if(h==INVALID_HANDLE_VALUE)return FALSE;DWORD bytes;BOOL ok=WriteFile(h,"INERT",5,&bytes,NULL);CloseHandle(h);if(!ok || bytes!=5)return FALSE;}
    return TRUE;
}
static BOOL present(const WCHAR *hash,unsigned index){WCHAR path[MAX_PATH];swprintf_s(path,MAX_PATH,L"%s\\%s\\%s",base,hash,bootstrapNames[index]);return GetFileAttributesW(path)!=INVALID_FILE_ATTRIBUTES;}
static PB_INSTALL_JOURNAL journal(unsigned n){
    PB_INSTALL_JOURNAL r={0};r.size=sizeof(r);r.version=PB_JOURNAL_VERSION;r.transaction.Data1=n;r.phase=PB_INSTALL_COMMITTED;
    r.targetProtocol=r.targetDriverVersion=1;r.targetManifestHash[31]=(BYTE)n;
    wcscpy_s(r.targetDirectory,MAX_PATH,L"C:\\fixture\\target");wcscpy_s(r.deviceInstance,200,L"ROOT\\FIXTURE");return r;
}
int wmain(int argc,WCHAR **argv){
    CHECK(argc==2);wcscpy_s(base,MAX_PATH,argv[1]);WCHAR hashes[8][65];
    for(unsigned i=0;i<8;++i){hash_text(i+1,hashes[i]);CHECK(create_files(hashes[i]));CHECK(!pb_bootstrap_retire((HKEY)1,hashes[i]));}
    PB_INSTALL_JOURNAL current=journal(1),pending=journal(3);pending.phase=PB_INSTALL_PREPARED;
    current.previousProtocol=current.previousDriverVersion=1;current.previousManifestHash[31]=2;wcscpy_s(current.previousDirectory,MAX_PATH,L"C:\\fixture\\previous");
    CHECK(!put((HKEY)1,L"PendingStage",0,REG_BINARY,(BYTE*)&pending,sizeof(pending)));
    wcscpy_s(keep,65,hashes[3]); // Shortcut/registration reference.
    WCHAR busyPath[MAX_PATH];swprintf_s(busyPath,MAX_PATH,L"%s\\%s\\%s",base,hashes[4],bootstrapNames[2]);
    HANDLE busy=CreateFileW(busyPath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);CHECK(busy!=INVALID_HANDLE_VALUE);
    CHECK(!pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL));
    for(unsigned i=0;i<6;++i)CHECK(present(hashes[i],0));
    CHECK(!present(hashes[6],0) && !present(hashes[7],2));CHECK(count==7);
    CloseHandle(busy);denySecurity=TRUE;
    CHECK(pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL)==ERROR_ACCESS_DENIED && present(hashes[4],0));
    denySecurity=FALSE;deleteCountdown=1;
    CHECK(!pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL) && count==7);
    CHECK(!present(hashes[4],0) && present(hashes[4],1));deleteCountdown=-1;
    eraseError=ERROR_WRITE_FAULT;
    CHECK(pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL)==eraseError && count==7);eraseError=0;
    CHECK(!pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL) && count==6);
    CHECK(!erase((HKEY)1,L"PendingStage"));keep[0]=0;referenceError=ERROR_READ_FAULT;
    CHECK(pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL)==referenceError && present(hashes[2],0));referenceError=0;
    current.phase=PB_INSTALL_DRIVER_PENDING;CHECK(!pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL) && present(hashes[2],0));
    current.phase=PB_INSTALL_COMMITTED;CHECK(!pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL) && count==3);
    CHECK(pb_bootstrap_retire((HKEY)1,L"invalid")==ERROR_INVALID_PARAMETER);
    flushError=ERROR_WRITE_FAULT;CHECK(pb_bootstrap_retire((HKEY)1,hashes[0])==flushError);flushError=0;
    WCHAR name[96];swprintf_s(name,96,L"RetiredBootstrap-%s",hashes[0]);DWORD bad=2;
    CHECK(!put((HKEY)1,name,0,REG_DWORD,(BYTE*)&bad,sizeof(bad)));
    CHECK(pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL)==ERROR_INVALID_DATA);
    bad=1;CHECK(!put((HKEY)1,name,0,REG_DWORD,(BYTE*)&bad,sizeof(bad)));
    WCHAR foreign[65],foreignPath[MAX_PATH];hash_text(9,foreign);CHECK(create_files(foreign));
    swprintf_s(foreignPath,MAX_PATH,L"%s\\%s\\unknown.txt",base,foreign);
    HANDLE unknown=CreateFileW(foreignPath,GENERIC_WRITE,0,NULL,CREATE_NEW,0,NULL);CHECK(unknown!=INVALID_HANDLE_VALUE);CloseHandle(unknown);
    CHECK(!pb_bootstrap_retire((HKEY)1,foreign));
    CHECK(pb_bootstrap_collect((HKEY)1,&current,hashes[5],referenced,NULL)==ERROR_INVALID_DATA && present(foreign,0));
    puts("PASS bootstrap retention: target/rollback/pending/active/reference keep, terminal gate, busy files, security/read refusal, partial delete and receipt retry. Real files; registry/root/security/reference adapters.");return 0;
}
