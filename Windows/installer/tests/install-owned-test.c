#include "../install-owned.h"
#include "../install-stage.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef struct VALUE { WCHAR name[100]; DWORD type, size; BYTE data[4096]; } VALUE;
static VALUE values[20];
static unsigned count, writes, flushedWrites, begins, deleted;
static DWORD flushError, cleanupError, writeError, eraseError;
static BOOL collision;
static WCHAR removed[MAX_PATH];
static int find(const WCHAR *name){for(unsigned i=0;i<count;++i)if(!_wcsicmp(values[i].name,name))return (int)i;return -1;}
static LSTATUS WINAPI query(HKEY key,LPCWSTR name,LPDWORD reserved,LPDWORD type,LPBYTE data,LPDWORD bytes){
    (void)key;(void)reserved;int at=find(name);if(at<0)return ERROR_FILE_NOT_FOUND;
    DWORD capacity=*bytes;*bytes=values[at].size;if(type)*type=values[at].type;if(!data)return 0;
    if(capacity<*bytes)return ERROR_MORE_DATA;
    memcpy(data,values[at].data,*bytes);return 0;
}
static LSTATUS WINAPI put(HKEY key,LPCWSTR name,DWORD reserved,DWORD type,const BYTE *data,DWORD bytes){
    if(writeError)return writeError;
    (void)key;(void)reserved;int at=find(name);if(at<0){if(count==20)return ERROR_DISK_FULL;at=(int)count++;}
    if(bytes>sizeof(values[at].data))return ERROR_MORE_DATA;
    wcscpy_s(values[at].name,100,name);values[at].type=type;values[at].size=bytes;memcpy(values[at].data,data,bytes);++writes;return 0;
}
static LSTATUS WINAPI flush(HKEY key){(void)key;if(flushError)return flushError;flushedWrites=writes;return 0;}
static LSTATUS WINAPI enumerate(HKEY key,DWORD index,LPWSTR name,LPDWORD length,LPDWORD reserved,LPDWORD type,LPBYTE data,LPDWORD bytes){
    (void)key;(void)reserved;(void)type;(void)data;(void)bytes;if(index>=count)return ERROR_NO_MORE_ITEMS;
    DWORD capacity=*length;*length=(DWORD)wcslen(values[index].name);
    if(capacity<=*length)return ERROR_MORE_DATA;wcscpy_s(name,capacity,values[index].name);return 0;
}
static LSTATUS WINAPI erase(HKEY key,LPCWSTR name){
    if(eraseError)return eraseError;
    (void)key;int at=find(name);if(at<0)return ERROR_FILE_NOT_FOUND;
    values[at]=values[--count];++writes;return 0;
}
static DWORD begin(HKEY key,const PB_INSTALL_JOURNAL *record){
    (void)key;(void)record;if(flushedWrites!=writes)return ERROR_WRITE_FAULT;++begins;return 0;
}
static DWORD cleanup(HANDLE root,const WCHAR *directory,const BYTE hash[32],DWORD protocol,DWORD version){
    (void)root;if(!hash[0] || protocol!=1 || version!=1)return ERROR_INVALID_DATA;
    if(cleanupError)return cleanupError;++deleted;wcscpy_s(removed,MAX_PATH,directory);return 0;
}
static DWORD stage_path(HANDLE root,const GUID *id,WCHAR path[MAX_PATH]){
    (void)root;WCHAR guid[40];if(!StringFromGUID2(id,guid,40))return ERROR_INVALID_DATA;
    return swprintf_s(path,MAX_PATH,L"C:\\fixture\\versions\\%s",guid)<0?ERROR_INVALID_NAME:0;
}
static DWORD partial(HANDLE root,const GUID *id,const WCHAR *directory){
    (void)root;(void)id;if(cleanupError)return cleanupError;++deleted;wcscpy_s(removed,MAX_PATH,directory);return 0;
}
static DWORD WINAPI missing_file(LPCWSTR path){(void)path;if(collision)return FILE_ATTRIBUTE_DIRECTORY;SetLastError(ERROR_FILE_NOT_FOUND);return INVALID_FILE_ATTRIBUTES;}
#define pb_stage_target_path stage_path
static DWORD validate_target(HANDLE root,const GUID *id,const WCHAR *directory){
    WCHAR path[MAX_PATH];DWORD error=stage_path(root,id,path);
    return error?error:(_wcsicmp(path,directory)?ERROR_INVALID_NAME:0);
}
#define pb_stage_validate_target validate_target
#define pb_stage_cleanup_partial partial
#define GetFileAttributesW missing_file
#define RegQueryValueExW query
#define RegSetValueExW put
#define RegFlushKey flush
#define RegEnumValueW enumerate
#define RegDeleteValueW erase
#define pb_journal_begin begin
#define pb_stage_cleanup_files cleanup
#include "../install-owned.c"
#define CHECK(x) do{if(!(x)){printf("FAIL %d: %s\n",__LINE__,#x);return 1;}}while(0)
static PB_INSTALL_JOURNAL journal(unsigned n){
    PB_INSTALL_JOURNAL r={0};r.size=sizeof(r);r.version=PB_JOURNAL_VERSION;
    r.phase=PB_INSTALL_PREPARED;r.transaction.Data1=n;r.targetProtocol=r.targetDriverVersion=1;
    r.targetManifestHash[0]=(BYTE)n;wcscpy_s(r.deviceInstance,200,L"ROOT\\FIXTURE");
    swprintf_s(r.targetDirectory,MAX_PATH,L"C:\\fixture\\versions\\{%08X-0000-0000-0000-000000000000}",n);return r;
}
static void previous(PB_INSTALL_JOURNAL *r,const PB_INSTALL_JOURNAL *prior){
    wcscpy_s(r->previousDirectory,MAX_PATH,prior->targetDirectory);memcpy(r->previousManifestHash,prior->targetManifestHash,32);
    r->previousProtocol=r->previousDriverVersion=1;
}
int main(void){
    PB_INSTALL_JOURNAL empty={0},a=journal(1),b=journal(2),c=journal(3);
    CHECK(pb_owned_begin((HKEY)1,&empty,&a)==0 && count==1 && begins==1);
    a.phase=PB_INSTALL_COMMITTED;previous(&b,&a);
    flushError=ERROR_WRITE_FAULT;
    CHECK(pb_owned_begin((HKEY)1,&a,&b)==flushError && begins==1 && count==2);
    flushError=0;CHECK(pb_owned_begin((HKEY)1,&a,&b)==0 && begins==2 && count==2);
    b.phase=PB_INSTALL_COMMITTED;previous(&c,&b);
    CHECK(pb_owned_begin((HKEY)1,&b,&c)==0 && count==3);
    CHECK(pb_owned_cleanup((HKEY)1,(HANDLE)1,&c)==ERROR_INVALID_STATE && !deleted);
    c.phase=PB_INSTALL_COMMITTED;
    cleanupError=ERROR_SHARING_VIOLATION;
    CHECK(pb_owned_cleanup((HKEY)1,(HANDLE)1,&c)==cleanupError && count==3 && !deleted);
    cleanupError=0;
    CHECK(pb_owned_cleanup((HKEY)1,(HANDLE)1,&c)==0 && count==2 && deleted==1 && !wcscmp(removed,a.targetDirectory));
    CHECK(pb_owned_cleanup((HKEY)1,(HANDLE)1,&c)==0 && deleted==1);
    c.targetManifestHash[0]=99;
    CHECK(pb_owned_cleanup((HKEY)1,(HANDLE)1,&c)==ERROR_REVISION_MISMATCH && deleted==1);
    CHECK(pb_owned_begin((HKEY)1,&empty,&c)==ERROR_REVISION_MISMATCH);
    c.targetManifestHash[0]=3;
    BYTE dummy=0;
    CHECK(put((HKEY)1,L"Unrelated",0,REG_BINARY,&dummy,1)==0);
    CHECK(put((HKEY)1,L"Unrelated-long-name-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",0,REG_BINARY,&dummy,1)==0);
    CHECK(pb_owned_cleanup((HKEY)1,(HANDLE)1,&c)==0 && count==4);
    CHECK(put((HKEY)1,L"OwnedPayload-bad",0,REG_BINARY,&dummy,1)==0);
    CHECK(pb_owned_cleanup((HKEY)1,(HANDLE)1,&c)==ERROR_INVALID_DATA);
    CHECK(erase((HKEY)1,L"OwnedPayload-bad")==0);
    c.phase=PB_INSTALL_CLEANED;wcscpy_s(c.removalInf,MAX_PATH,L"oem1.inf");
    CHECK(pb_owned_cleanup((HKEY)1,(HANDLE)1,&c)==0 && count==2 && deleted==3);
    CHECK(find(L"Unrelated")>=0);
    count=writes=flushedWrites=begins=deleted=0;
    a=journal(1);b=journal(2);c=journal(3);
    flushError=ERROR_WRITE_FAULT;
    CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&a)==flushError && !begins && !deleted);
    flushError=0;
    CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&b)==ERROR_BUSY);
    cleanupError=ERROR_SHARING_VIOLATION;
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&empty)==cleanupError && count==1);
    cleanupError=0;
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&empty)==0 && deleted==1 && !count);
    CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&a)==0 && flushedWrites==writes);
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&a)==ERROR_INVALID_STATE && deleted==1);
    c.phase=PB_INSTALL_COMMITTED;previous(&c,&a);
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&c)==ERROR_INVALID_STATE && deleted==1);
    CHECK(pb_owned_begin((HKEY)1,&empty,&a)==0);
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&a)==0 && deleted==1 && count==1);
    // Complete staging + durable receipt, interrupted before journal publication.
    CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&b)==0);
    CHECK(pb_owned_begin((HKEY)1,&a,&b)==0);
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&a)==0 && deleted==1 && count==2);
    // An unrelated unfinished transaction blocks partial cleanup.
    CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&c)==ERROR_INVALID_STATE);
    c.phase=PB_INSTALL_PREPARED;
    CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&c)==0);
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&a)==ERROR_BUSY);
    a.phase=PB_INSTALL_COMMITTED;
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&a)==0 && deleted==2 && count==2);
    collision=TRUE;CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&c)==ERROR_ALREADY_EXISTS && find(L"PendingStage")<0);collision=FALSE;
    writeError=ERROR_DISK_FULL;CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&c)==writeError && find(L"PendingStage")<0);writeError=0;
    CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&c)==0);
    eraseError=ERROR_ACCESS_DENIED;
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&a)==eraseError && find(L"PendingStage")>=0);
    eraseError=0;CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&a)==0 && find(L"PendingStage")<0);
    CHECK(pb_owned_stage_prepare((HKEY)1,(HANDLE)1,&c)==0);
    CHECK(pb_owned_begin((HKEY)1,&a,&c)==0);
    flushError=ERROR_WRITE_FAULT;
    CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&c)==flushError && find(L"PendingStage")>=0);
    flushError=0;CHECK(pb_owned_stage_recover((HKEY)1,(HANDLE)1,&c)==0);
    puts("PASS ownership receipts and pending stage: write/flush/delete failures, collision, no-journal cleanup, target/rollback preservation, busy transaction, permanent receipt handoff, retry and malformed identity guards");return 0;
}
