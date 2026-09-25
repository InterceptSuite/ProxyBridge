// Preserve the original decimal-octet grammar; this intentionally adds no CIDR.
static BOOL pb_prepare_ipv4_pattern(const char *pattern, PB_IPV4_TERM *term)
{
    memset(term, 0, sizeof(*term));
    if (strcmp(pattern, "*") == 0) return TRUE; // zero mask
    const char *dash = strchr(pattern, '-');
    if (dash != NULL) {
        char start[64], end[64];
        size_t length = (size_t)(dash - pattern);
        if (length >= sizeof(start)) return FALSE;
        memcpy(start, pattern, length); start[length] = 0;
        strncpy_s(end, sizeof(end), dash + 1, _TRUNCATE);
        int a[4], b[4];
        if (sscanf_s(start, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]) != 4 ||
            sscanf_s(end, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3]) != 4) return FALSE;
        for (int i = 0; i < 4; ++i) {
            if ((unsigned)a[i] > 255 || (unsigned)b[i] > 255) return FALSE;
            term->first = (term->first << 8) | (UINT32)a[i];
            term->last = (term->last << 8) | (UINT32)b[i];
        }
        term->range = TRUE;
        return term->first <= term->last;
    }
    char copy[256], octet[16];
    strncpy_s(copy, sizeof(copy), pattern, _TRUNCATE);
    int count = 0, used = 0;
    size_t length = strlen(copy);
    for (size_t i = 0; i <= length && count < 4; ++i) {
        if (copy[i] == '.' || copy[i] == 0) {
            octet[used] = 0;
            if (strcmp(octet, "*") != 0) {
                int value = atoi(octet);
                if ((unsigned)value > 255) return FALSE;
                term->first |= (UINT32)value << (8 * count);
                term->last |= (UINT32)255 << (8 * count); // mask
            }
            ++count; used = 0;
        } else if (used < 15) octet[used++] = copy[i];
    }
    return count == 4;
}

PB_IPV4_FILTER *pb_prepare_ipv4_list(const char *list)
{
    if (list == NULL || *list == 0) list = "*";
    if (strnlen_s(list, MAX_LIST_SIZE) >= MAX_LIST_SIZE) return NULL;
    char *copy = _strdup(list);
    if (copy == NULL) return NULL;
    PB_IPV4_TERM term;
    size_t count = 0;
    char *context = NULL;
    for (char *token = strtok_s(copy, ";", &context); token; token = strtok_s(NULL, ";", &context)) {
        while (*token == ' ' || *token == '\t') ++token;
        if (pb_prepare_ipv4_pattern(token, &term)) ++count;
    }
    PB_IPV4_FILTER *result = malloc(sizeof(*result) + (count ? count - 1 : 0) * sizeof(term));
    if (result == NULL) { free(copy); return NULL; }
    result->count = 0;
    strcpy_s(copy, strlen(list) + 1, list); context = NULL;
    for (char *token = strtok_s(copy, ";", &context); token; token = strtok_s(NULL, ";", &context)) {
        while (*token == ' ' || *token == '\t') ++token;
        if (pb_prepare_ipv4_pattern(token, &term)) result->terms[result->count++] = term;
    }
    free(copy);
    return result;
}

BOOL pb_match_ipv4_prepared(const PB_IPV4_FILTER *filter, UINT32 ip)
{
    UINT32 ordered = ntohl(ip);
    for (size_t i = 0; i < filter->count; ++i) {
        const PB_IPV4_TERM *term = &filter->terms[i];
        if (term->range ? ordered >= term->first && ordered <= term->last
                        : (ip & term->last) == term->first) return TRUE;
    }
    return FALSE;
}
