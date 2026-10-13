// Dumps the registered manifest of Microsoft-Windows-DNS-Client: every event ID with
// its exact property names and types. Reading a manifest needs no privileges, unlike
// starting an ETW session, so this can answer "what fields does 3008 really have"
// without an elevated shell.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tdh.h>
#include <evntprov.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "tdh.lib")

static const GUID g_provider =
    { 0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d } };

static const char *intype_name(USHORT t)
{
    switch (t)
    {
    case TDH_INTYPE_NULL: return "NULL";
    case TDH_INTYPE_UNICODESTRING: return "UnicodeString";
    case TDH_INTYPE_ANSISTRING: return "AnsiString";
    case TDH_INTYPE_INT8: return "Int8";
    case TDH_INTYPE_UINT8: return "UInt8";
    case TDH_INTYPE_INT16: return "Int16";
    case TDH_INTYPE_UINT16: return "UInt16";
    case TDH_INTYPE_INT32: return "Int32";
    case TDH_INTYPE_UINT32: return "UInt32";
    case TDH_INTYPE_INT64: return "Int64";
    case TDH_INTYPE_UINT64: return "UInt64";
    case TDH_INTYPE_FLOAT: return "Float";
    case TDH_INTYPE_DOUBLE: return "Double";
    case TDH_INTYPE_BOOLEAN: return "Boolean";
    case TDH_INTYPE_BINARY: return "Binary";
    case TDH_INTYPE_GUID: return "GUID";
    case TDH_INTYPE_POINTER: return "Pointer";
    case TDH_INTYPE_FILETIME: return "FileTime";
    case TDH_INTYPE_SYSTEMTIME: return "SystemTime";
    case TDH_INTYPE_SID: return "SID";
    case TDH_INTYPE_HEXINT32: return "HexInt32";
    case TDH_INTYPE_HEXINT64: return "HexInt64";
    case TDH_INTYPE_COUNTEDSTRING: return "CountedString";
    case TDH_INTYPE_COUNTEDANSISTRING: return "CountedAnsiString";
    case TDH_INTYPE_REVERSEDCOUNTEDSTRING: return "ReversedCountedString";
    case TDH_INTYPE_NONNULLTERMINATEDSTRING: return "NonNullTerminatedString";
    case TDH_INTYPE_UNICODECHAR: return "UnicodeChar";
    case TDH_INTYPE_ANSICHAR: return "AnsiChar";
    case TDH_INTYPE_SIZET: return "SizeT";
    case TDH_INTYPE_HEXDUMP: return "HexDump";
    case TDH_INTYPE_WBEMSID: return "WbemSID";
    default: return "other";
    }
}

int wmain(void)
{
    ULONG size = 0;
    ULONG status = TdhEnumerateManifestProviderEvents(&g_provider, NULL, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER)
    {
        printf("TdhEnumerateManifestProviderEvents sizing failed (%lu)\n", status);
        return 1;
    }
    PROVIDER_EVENT_INFO *events = (PROVIDER_EVENT_INFO *)calloc(1, size);
    if (!events) return 1;
    status = TdhEnumerateManifestProviderEvents(&g_provider, events, &size);
    if (status != ERROR_SUCCESS)
    {
        printf("TdhEnumerateManifestProviderEvents failed (%lu)\n", status);
        return 1;
    }

    printf("Microsoft-Windows-DNS-Client: %lu event definitions\n", events->NumberOfEvents);
    for (ULONG i = 0; i < events->NumberOfEvents; i++)
    {
        EVENT_DESCRIPTOR desc = events->EventDescriptorsArray[i];
        ULONG info_size = 0;
        status = TdhGetManifestEventInformation(&g_provider, &desc, NULL, &info_size);
        if (status != ERROR_INSUFFICIENT_BUFFER)
        {
            printf("id=%u v=%u keyword=0x%llx channel=%u : no template (%lu)\n",
                   desc.Id, desc.Version, (unsigned long long)desc.Keyword,
                   desc.Channel, status);
            continue;
        }
        TRACE_EVENT_INFO *info = (TRACE_EVENT_INFO *)calloc(1, info_size);
        if (!info) continue;
        status = TdhGetManifestEventInformation(&g_provider, &desc, info, &info_size);
        if (status != ERROR_SUCCESS)
        {
            printf("id=%u v=%u : template failed (%lu)\n", desc.Id, desc.Version, status);
            free(info);
            continue;
        }
        printf("id=%u v=%u keyword=0x%llx channel=%u level=%u props=%u top=%u\n",
               desc.Id, desc.Version, (unsigned long long)desc.Keyword, desc.Channel,
               desc.Level, info->PropertyCount, info->TopLevelPropertyCount);
        for (ULONG p = 0; p < info->PropertyCount; p++)
        {
            EVENT_PROPERTY_INFO *prop = &info->EventPropertyInfoArray[p];
            const WCHAR *name = (const WCHAR *)((const BYTE *)info + prop->NameOffset);
            printf("    [%u] %-26ls flags=0x%x in=%s out=%u\n", p, name, prop->Flags,
                   intype_name(prop->nonStructType.InType), prop->nonStructType.OutType);
        }
        free(info);
    }
    free(events);
    return 0;
}
