BOOL reference_process_pattern(const char *pattern, const char *process_full_path)
{
    if (pattern == NULL || strcmp(pattern, "*") == 0)
        return TRUE;

    // Extract just the filename from the full path for comparison
    // Windows path sucks
    const char *filename = strrchr(process_full_path, '\\');
    if (filename != NULL)
        filename++; // Skip the backslash
    else
        filename = process_full_path; // No path separator, use as-is

    // Check if pattern contains path separators (backslash or forward slash)
    BOOL is_full_path_pattern = (strchr(pattern, '\\') != NULL || strchr(pattern, '/') != NULL);

    // match against full path if pattern has a path separator, otherwise filename only
    const char *match_target = is_full_path_pattern ? process_full_path : filename;

    // Wildcard pattern: use full wildcard matcher (handles *, *x*, x*y, etc.)
    if (strchr(pattern, '*') != NULL)
        return wildcard_match(pattern, match_target);

    // No wildcard, plain case-insensitive comparison
    return _stricmp(pattern, match_target) == 0;
}

// Match process list: "chrome.exe;firefox.exe;*.bin"
BOOL reference_process_list(const char *process_list, const char *process_name)
{
    if (process_list == NULL || process_list[0] == '\0' || strcmp(process_list, "*") == 0)
        return TRUE;

    // Stack buffer for the common short case; malloc only for unusually long lists.
    char   stackbuf[256];
    size_t len   = strnlen_s(process_list, MAX_LIST_SIZE) + 1;
    size_t dstsz = len;
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

    strncpy_s(list_copy, dstsz, process_list, _TRUNCATE);
    BOOL matched = FALSE;
    char *context = NULL;

    // Support both semicolon and comma as separators - Need to figure complex rules in CLI parsing
    char *token = strtok_s(list_copy, ",;", &context);
    while (token != NULL)
    {
        // Skip leading whitespace
        while (*token == ' ' || *token == '\t')
            token++;

        // Trim trailing whitespace (matters for CLI-parsed lists)
        size_t token_length = strnlen_s(token, MAX_LIST_SIZE);
        char *end = token + (token_length ? token_length - 1 : 0);
        while (end > token && (*end == ' ' || *end == '\t'))
        {
            *end = '\0';
            end--;
        }

        // Remove quotes if present: "C:\some app.exe"  - Need to carefully handle this in CLI app
        if (*token == '"' && strnlen_s(token, MAX_LIST_SIZE) > 1)
        {
            token++;
            char *quote = strchr(token, '"');
            if (quote != NULL)
                *quote = '\0';
        }

        if (reference_process_pattern(token, process_name))
        {
            matched = TRUE;
            break;
        }
        token = strtok_s(NULL, ",;", &context);
    }
    if (on_heap)
        free(list_copy);
    return matched;
}

