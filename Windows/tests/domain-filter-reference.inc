BOOL match_domain_pattern(const char *pattern, const char *domain)
{
    if (pattern == NULL || pattern[0] == '\0' || strcmp(pattern, "*") == 0)
        return TRUE;
    if (domain == NULL || domain[0] == '\0')
        return FALSE;

    // "*.example.com" should also match the bare apex "example.com" (Proxifier/Clash convention).
    if (pattern[0] == '*' && pattern[1] == '.' && pattern[2] != '\0')
    {
        if (_stricmp(pattern + 2, domain) == 0)
            return TRUE;
    }

    if (strchr(pattern, '*') != NULL)
        return wildcard_match(pattern, domain);

    return _stricmp(pattern, domain) == 0;
}

// Match a resolved hostname against a semicolon/comma separated domain list.
// Empty list or "*" means no restriction (matches anything, including unknown domain).
BOOL match_domain_list(const char *domain_list, const char *domain)
{
    if (domain_list == NULL || domain_list[0] == '\0' || strcmp(domain_list, "*") == 0)
        return TRUE;
    if (domain == NULL || domain[0] == '\0')
        return FALSE;

    // Stack buffer for the common short case; malloc only for unusually long lists.
    char   stackbuf[256];
    size_t len   = strnlen_s(domain_list, MAX_LIST_SIZE) + 1;
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

    strncpy_s(list_copy, dstsz, domain_list, _TRUNCATE);
    BOOL matched = FALSE;
    char *context = NULL;
    char *token = strtok_s(list_copy, ",;", &context);
    while (token != NULL)
    {
        while (*token == ' ' || *token == '\t')
            token++;
        char *end = token + strnlen_s(token, MAX_LIST_SIZE);
        while (end > token && (end[-1] == ' ' || end[-1] == '\t'))
            *(--end) = '\0';

        if (token[0] != '\0' && match_domain_pattern(token, domain))
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

