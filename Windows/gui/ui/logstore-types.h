// UI history is UI-thread owned; native producers only touch pending under lock.
#ifndef PB_LOGSTORE_TYPES_H
#define PB_LOGSTORE_TYPES_H
#define LOG_MAX_LINES 4000
#define LOG_PEND_MAX 8000
#define LOG_STORE_BYTES (2u * 1024u * 1024u)
#define LOG_FLUSH_LINES 256
typedef struct {
    HWND edit;
    wchar_t* lines[LOG_MAX_LINES];
    int count, head;
    size_t bytes;
    wchar_t filter[128];
    wchar_t* pend[LOG_PEND_MAX];
    int pendCount, pendHead;
    size_t pendBytes;
    SRWLOCK lock;                 // zero initialized; remains valid after close
    BOOL accepting;
    ULONGLONG dropped;           // under pending lock; saturates instead of wrapping
    ULONGLONG reported, reportAt; // UI-thread only
} LogStore;
#endif
