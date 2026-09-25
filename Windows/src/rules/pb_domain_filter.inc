// Returns trimmed nonempty spans; quotes remain literal, as in the old parser.
static BOOL pb_next_domain(const char **cursor, const char **token, size_t *length)
{
    const char *p = *cursor;
    while (*(p += strspn(p, ",;")) != '\0') {
        const char *end = p + strcspn(p, ",;");
        *cursor = end;
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        while (end > p && (end[-1] == ' ' || end[-1] == '\t')) --end;
        if (end > p) { *token = p; *length = (size_t)(end - p); return TRUE; }
        p = *cursor;
    }
    *cursor = p;
    return FALSE;
}

PB_DOMAIN_FILTER *pb_prepare_domain_list(const char *list)
{
    if (list == NULL) list = "";
    if (strnlen_s(list, MAX_LIST_SIZE) >= MAX_LIST_SIZE) return NULL;
    BOOL unrestricted = *list == '\0' || strcmp(list, "*") == 0;
    size_t bytes = 0, length;
    const char *cursor = list, *token;
    if (!unrestricted)
        while (pb_next_domain(&cursor, &token, &length)) bytes += length + 2;
    PB_DOMAIN_FILTER *result = malloc(sizeof(*result) + bytes);
    if (result == NULL) return NULL;
    result->bytes = bytes;
    result->unrestricted = unrestricted;
    char *out = result->patterns;
    cursor = list;
    if (!unrestricted) while (pb_next_domain(&cursor, &token, &length)) {
        unsigned char flags = memchr(token, '*', length) != NULL ? 1 : 0;
        if (length > 2 && token[0] == '*' && token[1] == '.') flags |= 2;
        *out++ = (char)flags;
        memcpy(out, token, length); out += length; *out++ = '\0';
    }
    return result;
}

BOOL pb_match_domain_prepared(const PB_DOMAIN_FILTER *filter, const char *domain)
{
    if (filter->unrestricted) return TRUE;
    if (domain == NULL || *domain == '\0') return FALSE;
    const char *pattern = filter->patterns, *end = pattern + filter->bytes;
    while (pattern < end) {
        unsigned char flags = (unsigned char)*pattern++;
        if ((flags & 2) && _stricmp(pattern + 2, domain) == 0) return TRUE;
        if (flags & 1 ? wildcard_match(pattern, domain) : _stricmp(pattern, domain) == 0)
            return TRUE;
        pattern += strlen(pattern) + 1;
    }
    return FALSE;
}
