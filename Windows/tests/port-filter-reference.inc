char* skip_whitespace(char *str)
{
    while (*str == ' ' || *str == '\t')
        str++;
    return str;
}

BOOL parse_token_list(const char *list, const char *delimiters, token_match_func match_func, const void *match_data)
{
    if (list == NULL || list[0] == '\0' || strcmp(list, "*") == 0)
        return TRUE;

    // strtok_s needs a writable copy. Use a stack buffer for the common (short) case and
    // only fall back to malloc for unusually long lists - avoids a heap alloc on the
    // packet thread for every rule that has a specific host/port filter.
    char   stackbuf[256];
    size_t len    = strnlen_s(list, MAX_LIST_SIZE) + 1;
    size_t dstsz  = len;
    char  *list_copy;
    BOOL   on_heap = FALSE;
    if (len <= sizeof(stackbuf))
    {
        list_copy = stackbuf;
        dstsz     = sizeof(stackbuf);
    }
    else
    {
        list_copy = (char *)malloc(len);
        if (list_copy == NULL)
            return FALSE;
        on_heap = TRUE;
    }

    strncpy_s(list_copy, dstsz, list, _TRUNCATE);
    BOOL matched = FALSE;
    char *context = NULL;
    char *token = strtok_s(list_copy, delimiters, &context);
    while (token != NULL)
    {
        token = skip_whitespace(token);
        if (match_func(token, match_data))
        {
            matched = TRUE;
            break;
        }
        token = strtok_s(NULL, delimiters, &context);
    }
    if (on_heap)
        free(list_copy);
    return matched;
}

BOOL match_port_pattern(const char *pattern, UINT16 port)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    char *dash = strchr(pattern, '-');
    if (dash != NULL)
    {
        int start_port = atoi(pattern);
        int end_port = atoi(dash + 1);
        return (port >= start_port && port <= end_port);
    }

    return (port == atoi(pattern));
}

BOOL port_match_wrapper(const char *token, const void *data)
{
    return match_port_pattern(token, *(const UINT16*)data);
}

// Match port list: "80;443;8000-9000"
BOOL match_port_list(const char *port_list, UINT16 port)
{
    return parse_token_list(port_list, ",;", port_match_wrapper, &port);
}

