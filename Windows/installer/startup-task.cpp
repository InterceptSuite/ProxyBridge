#include "startup-task.h"
extern "C" {
#include "startup-identity.h"
}
#include <taskschd.h>
#include <sddl.h>
#include <wchar.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

template<class T> struct Ptr {
    T *p = nullptr;
    ~Ptr() { if (p) p->Release(); }
    T *operator->() const { return p; }
};
struct Text {
    BSTR p = nullptr;
    Text() = default;
    explicit Text(const WCHAR *s) : p(SysAllocString(s)) {}
    ~Text() { SysFreeString(p); }
};
static DWORD winerror(HRESULT hr) {
    if (SUCCEEDED(hr)) return 0;
    return HRESULT_FACILITY(hr) == FACILITY_WIN32 ? HRESULT_CODE(hr) : (DWORD)hr;
}
static const WCHAR taskName[] = L"InterceptSuite.ProxyBridge";
struct Session {
    const WCHAR *root;
    Ptr<ITaskService> service;
    Ptr<ITaskFolder> folder;
    Ptr<IRegisteredTask> task;
    Ptr<ITaskDefinition> definition;
    Ptr<IExecAction> action;
};
#define TRY(call) do { HRESULT hr_ = (call); if (FAILED(hr_)) return winerror(hr_); } while (0)

static DWORD read_task(void *context, PB_STARTUP_SNAPSHOT *snapshot)
{
    Session &s = *(Session *)context;
    Text name(taskName);
    if (!name.p) return ERROR_NOT_ENOUGH_MEMORY;
    HRESULT hr = s.folder->GetTask(name.p, &s.task.p);
    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) return 0;
    if (FAILED(hr)) return winerror(hr);
    snapshot->exists = TRUE;
    TRY(s.task->get_Definition(&s.definition.p));
    Ptr<IRegistrationInfo> info;
    Ptr<IActionCollection> actions;
    TRY(s.definition->get_RegistrationInfo(&info.p));
    Text uri, path, arguments, working;
    TRY(info->get_URI(&uri.p));
    TRY(s.definition->get_Actions(&actions.p));
    LONG count = 0;
    TRY(actions->get_Count(&count));
    if (count != 1) return 0;
    Ptr<IAction> action;
    TRY(actions->get_Item(1, &action.p));
    TASK_ACTION_TYPE type;
    TRY(action->get_Type(&type));
    if (type != TASK_ACTION_EXEC) return 0;
    TRY(action->QueryInterface(IID_IExecAction, (void **)&s.action.p));
    TRY(s.action->get_Path(&path.p));
    TRY(s.action->get_Arguments(&arguments.p));
    TRY(s.action->get_WorkingDirectory(&working.p));
    // Reject embedded NULs rather than validating only a BSTR prefix.
    if (!uri.p || !path.p || !arguments.p || SysStringLen(uri.p) != wcslen(uri.p) ||
        SysStringLen(path.p) != wcslen(path.p) || SysStringLen(arguments.p) != wcslen(arguments.p) ||
        (working.p && SysStringLen(working.p))) return 0;
    snapshot->owned = pb_startup_task_owned(s.root, uri.p, count, path.p, arguments.p);
    VARIANT_BOOL enabled;
    TRY(s.task->get_Enabled(&enabled));
    snapshot->enabled = enabled != VARIANT_FALSE;
    return 0;
}

static DWORD current_user(Text &sid)
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return GetLastError();
    alignas(TOKEN_USER) BYTE buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE]; DWORD bytes = 0;
    BOOL ok = GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &bytes);
    DWORD error = ok ? 0 : GetLastError();
    CloseHandle(token);
    if (error) return error;
    LPWSTR string = nullptr;
    if (!ConvertSidToStringSidW(((TOKEN_USER *)buffer)->User.Sid, &string)) return GetLastError();
    sid.p = SysAllocString(string); LocalFree(string);
    return sid.p ? 0 : ERROR_NOT_ENOUGH_MEMORY;
}

static DWORD check_legacy_task(Session &s)
{
    // Do not create a second logon task beside an unmarked legacy task.
    Text legacy(L"ProxyBridge"); Ptr<IRegisteredTask> old;
    if (!legacy.p) return ERROR_NOT_ENOUGH_MEMORY;
    HRESULT found = s.folder->GetTask(legacy.p, &old.p);
    if (SUCCEEDED(found)) return ERROR_ALREADY_EXISTS;
    if (found != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) return winerror(found);
    return 0;
}

static DWORD create_definition(Session &s)
{
    TRY(s.service->NewTask(0, &s.definition.p));
    Ptr<IRegistrationInfo> info; Ptr<IPrincipal> principal;
    Ptr<ITriggerCollection> triggers; Ptr<ITrigger> trigger; Ptr<ILogonTrigger> logon;
    Ptr<IActionCollection> actions; Ptr<IAction> action;
    Text uri(PB_STARTUP_TASK_URI), delay(L"PT15S"), sid;
    if (!uri.p || !delay.p) return ERROR_NOT_ENOUGH_MEMORY;
    DWORD error = current_user(sid); if (error) return error;
    TRY(s.definition->get_RegistrationInfo(&info.p)); TRY(info->put_URI(uri.p));
    TRY(s.definition->get_Principal(&principal.p));
    TRY(principal->put_UserId(sid.p));
    TRY(principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN));
    TRY(principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST));
    TRY(s.definition->get_Triggers(&triggers.p));
    TRY(triggers->Create(TASK_TRIGGER_LOGON, &trigger.p));
    TRY(trigger->QueryInterface(IID_ILogonTrigger, (void **)&logon.p));
    TRY(logon->put_UserId(sid.p)); TRY(logon->put_Delay(delay.p));
    TRY(s.definition->get_Actions(&actions.p));
    TRY(actions->Create(TASK_ACTION_EXEC, &action.p));
    TRY(action->QueryInterface(IID_IExecAction, (void **)&s.action.p));
    return 0;
}

static DWORD prepare_registration(Session &s, PB_STARTUP_OPERATION operation, const WCHAR *launcher,
                                  Text &user, TASK_LOGON_TYPE &logon)
{
    Ptr<IPrincipal> principal;
    TRY(s.definition->get_Principal(&principal.p));
    TRY(principal->get_LogonType(&logon));
    // Password/group/service-account tasks need different registration flows;
    // never silently replace their principal or request stored credentials.
    if (logon != TASK_LOGON_INTERACTIVE_TOKEN) return ERROR_NOT_SUPPORTED;
    Text path(launcher), arguments(PB_STARTUP_ARGUMENTS);
    if (!path.p || !arguments.p) return ERROR_NOT_ENOUGH_MEMORY;
    TRY(principal->get_UserId(&user.p));
    if (!user.p || !SysStringLen(user.p) || SysStringLen(user.p) != wcslen(user.p)) return ERROR_INVALID_DATA;
    TRY(s.action->put_Path(path.p)); TRY(s.action->put_Arguments(arguments.p));
    if (operation == PB_STARTUP_ENABLE) {
        Ptr<ITaskSettings> settings;
        TRY(s.definition->get_Settings(&settings.p)); TRY(settings->put_Enabled(VARIANT_TRUE));
    }
    return 0;
}

static DWORD write_task(void *context, PB_STARTUP_OPERATION operation, BOOL create, const WCHAR *launcher)
{
    Session &s = *(Session *)context;
    Text name(taskName);
    if (!name.p) return ERROR_NOT_ENOUGH_MEMORY;
    if (operation == PB_STARTUP_REMOVE) return winerror(s.folder->DeleteTask(name.p, 0));
    if (operation == PB_STARTUP_DISABLE) return winerror(s.task->put_Enabled(VARIANT_FALSE));
    if (create) {
        DWORD error = check_legacy_task(s); if (error) return error;
        error = create_definition(s); if (error) return error;
    }
    Text user; TASK_LOGON_TYPE logon;
    DWORD error = prepare_registration(s, operation, launcher, user, logon);
    if (error) return error;
    VARIANT empty = {}, identity = {};
    identity.vt = VT_BSTR; identity.bstrVal = user.p;
    Ptr<IRegisteredTask> registered;
    HRESULT registeredResult = s.folder->RegisterTaskDefinition(name.p, s.definition.p,
        (create ? TASK_CREATE : TASK_UPDATE | TASK_DONT_ADD_PRINCIPAL_ACE) | TASK_IGNORE_REGISTRATION_TRIGGERS,
        identity, empty, logon, empty, &registered.p);
    // SCHED_S_* may mean a registered task with broken triggers/logon. Surface
    // this partial result; the caller must re-read state before retry/recovery.
    return registeredResult == S_OK ? 0 : FAILED(registeredResult) ? winerror(registeredResult) : (DWORD)registeredResult;
}

DWORD pb_startup_task_apply(PB_STARTUP_OPERATION operation, const WCHAR *programData,
                            const WCHAR *launcher, BOOL *enabled)
{
    if (!programData || !enabled) return ERROR_INVALID_PARAMETER;
    *enabled = FALSE;
    HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized) && initialized != RPC_E_CHANGED_MODE) return winerror(initialized);
    DWORD error;
    {
        Session s = {}; s.root = programData;
        HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_ITaskService, (void **)&s.service.p);
        VARIANT empty = {};
        if (SUCCEEDED(hr)) hr = s.service->Connect(empty, empty, empty, empty);
        Text root(L"\\");
        if (SUCCEEDED(hr)) hr = root.p ? s.service->GetFolder(root.p, &s.folder.p) : E_OUTOFMEMORY;
        if (FAILED(hr)) error = winerror(hr);
        else {
            PB_STARTUP_BACKEND backend = {&s, read_task, write_task};
            error = pb_startup_dispatch(&backend, operation, programData, launcher, enabled);
        }
    }
    if (SUCCEEDED(initialized)) CoUninitialize();
    return error;
}
