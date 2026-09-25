// Real Task Scheduler definition objects only. Never calls write_task,
// pb_startup_task_apply, RegisterTaskDefinition, DeleteTask or get_Enabled on
// an installed task. No folder is opened and no task name is looked up.
#include "../startup-task.cpp"
#include <stdio.h>
#define CHECK(x) do { if (!(x)) { printf("FAIL %d: %s\n",__LINE__,#x); return 1; } } while(0)
static int run(void)
{
    Session s = {};
    CHECK(SUCCEEDED(CoCreateInstance(CLSID_TaskScheduler,nullptr,CLSCTX_INPROC_SERVER,IID_ITaskService,(void**)&s.service.p)));
    VARIANT empty = {};
    CHECK(SUCCEEDED(s.service->Connect(empty,empty,empty,empty)));
    CHECK(create_definition(s)==0);
    Ptr<IPrincipal> principal; Ptr<ITaskSettings> settings; Ptr<ITriggerCollection> triggers;
    CHECK(SUCCEEDED(s.definition->get_Principal(&principal.p)));
    CHECK(SUCCEEDED(s.definition->get_Settings(&settings.p)));
    CHECK(SUCCEEDED(s.definition->get_Triggers(&triggers.p)));
    LONG count=0; CHECK(SUCCEEDED(triggers->get_Count(&count)) && count==1);
    Ptr<ITrigger> trigger; Ptr<ILogonTrigger> logonTrigger;
    CHECK(SUCCEEDED(triggers->get_Item(1,&trigger.p)));
    CHECK(SUCCEEDED(trigger->QueryInterface(IID_ILogonTrigger,(void**)&logonTrigger.p)));
    Text oldUser, triggerUser, delay;
    CHECK(SUCCEEDED(principal->get_UserId(&oldUser.p)) && oldUser.p);
    CHECK(SUCCEEDED(logonTrigger->get_UserId(&triggerUser.p)) && !wcscmp(oldUser.p,triggerUser.p));
    CHECK(SUCCEEDED(logonTrigger->get_Delay(&delay.p)) && !wcscmp(delay.p,L"PT15S"));
    CHECK(SUCCEEDED(settings->put_Enabled(VARIANT_FALSE)));
    CHECK(SUCCEEDED(settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE)));
    CHECK(SUCCEEDED(settings->put_StopIfGoingOnBatteries(VARIANT_FALSE)));
    Text user; TASK_LOGON_TYPE type;
    CHECK(prepare_registration(s,PB_STARTUP_RETARGET,L"C:\\test\\launcher-b.exe",user,type)==0);
    CHECK(type==TASK_LOGON_INTERACTIVE_TOKEN && !wcscmp(oldUser.p,user.p));
    VARIANT_BOOL enabled, battery, stop;
    CHECK(SUCCEEDED(settings->get_Enabled(&enabled)) && enabled==VARIANT_FALSE);
    CHECK(SUCCEEDED(settings->get_DisallowStartIfOnBatteries(&battery)) && battery==VARIANT_FALSE);
    CHECK(SUCCEEDED(settings->get_StopIfGoingOnBatteries(&stop)) && stop==VARIANT_FALSE);
    TASK_RUNLEVEL_TYPE level; CHECK(SUCCEEDED(principal->get_RunLevel(&level)) && level==TASK_RUNLEVEL_HIGHEST);
    Text path,args; CHECK(SUCCEEDED(s.action->get_Path(&path.p)) && !wcscmp(path.p,L"C:\\test\\launcher-b.exe"));
    CHECK(SUCCEEDED(s.action->get_Arguments(&args.p)) && !wcscmp(args.p,PB_STARTUP_ARGUMENTS));
    // Serialize and parse actual definition XML without registering anything.
    Text xml; CHECK(SUCCEEDED(s.definition->get_XmlText(&xml.p)));
    Ptr<ITaskDefinition> parsed; CHECK(SUCCEEDED(s.service->NewTask(0,&parsed.p)));
    CHECK(SUCCEEDED(parsed->put_XmlText(xml.p)));
    Text enabledUser; CHECK(prepare_registration(s,PB_STARTUP_ENABLE,L"C:\\test\\launcher-c.exe",enabledUser,type)==0);
    CHECK(SUCCEEDED(settings->get_Enabled(&enabled)) && enabled==VARIANT_TRUE);
    CHECK(SUCCEEDED(principal->put_LogonType(TASK_LOGON_PASSWORD)));
    Text unsupportedUser;
    CHECK(prepare_registration(s,PB_STARTUP_RETARGET,L"C:\\test\\must-not-change.exe",unsupportedUser,type)==ERROR_NOT_SUPPORTED);
    Text finalPath; CHECK(SUCCEEDED(s.action->get_Path(&finalPath.p)) && !wcscmp(finalPath.p,L"C:\\test\\launcher-c.exe"));
    puts("PASS real in-memory COM task: SID/logon/delay/settings preserved, retarget/enable, XML roundtrip, unsupported principal rejected; no task registered");
    return 0;
}
int main(void) {
    HRESULT hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(FAILED(hr)) return 2;
    int result=run(); CoUninitialize(); return result;
}
