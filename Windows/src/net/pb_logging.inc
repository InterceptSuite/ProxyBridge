// Capture once; unregister does not join callbacks already in flight.
PROXYBRIDGE_API void ProxyBridge_SetLogCallback(LogCallback callback)
{
    InterlockedExchangePointer((PVOID volatile *)&g_log_callback, (PVOID)callback);
}

void log_message(const char *msg, ...)
{
    LogCallback callback = (LogCallback)InterlockedCompareExchangePointer((PVOID volatile *)&g_log_callback, NULL, NULL);
    if (callback == NULL) return;
    char buffer[LOG_BUFFER_SIZE];
    va_list args;
    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);
    callback(buffer);
}

