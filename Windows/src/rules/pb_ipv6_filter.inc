static BOOL pb_prepare_ipv6_pattern(const char *pattern, PB_IPV6_RANGE *range)
{
    if (strcmp(pattern, "*") == 0) {
        memset(range->first, 0, 16); memset(range->last, 255, 16); return TRUE;
    }
    if (strchr(pattern, ':') == NULL) return FALSE;
    char copy[128];
    strncpy_s(copy, sizeof(copy), pattern, _TRUNCATE);
    char *slash = strchr(copy, '/');
    if (slash != NULL) {
        *slash = '\0';
        int prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 128 || inet_pton(AF_INET6, copy, range->first) != 1) return FALSE;
        for (int i = 0; i < 16; ++i) {
            int bits = prefix - 8 * i;
            UINT8 mask = bits >= 8 ? 255 : bits <= 0 ? 0 : (UINT8)(255 << (8 - bits));
            range->first[i] &= mask;
            range->last[i] = range->first[i] | (UINT8)~mask;
        }
        return TRUE;
    }
    char *dash = strchr(copy, '-');
    if (dash != NULL) {
        *dash = '\0';
        return inet_pton(AF_INET6, copy, range->first) == 1 &&
            inet_pton(AF_INET6, dash + 1, range->last) == 1 && memcmp(range->first, range->last, 16) <= 0;
    }
    if (inet_pton(AF_INET6, pattern, range->first) != 1) return FALSE;
    memcpy(range->last, range->first, 16);
    return TRUE;
}

static int pb_compare_ipv6_ranges(const void *left, const void *right)
{
    const PB_IPV6_RANGE *a = left, *b = right;
    int order = memcmp(a->first, b->first, 16);
    return order != 0 ? order : memcmp(a->last, b->last, 16);
}

PB_IPV6_FILTER *pb_prepare_ipv6_list(const char *list)
{
    if (list == NULL || *list == '\0') list = "*";
    if (strnlen_s(list, MAX_LIST_SIZE) >= MAX_LIST_SIZE) return NULL;
    char *copy = _strdup(list);
    if (copy == NULL) return NULL;
    PB_IPV6_RANGE range;
    size_t count = 0;
    char *context = NULL;
    for (char *token = strtok_s(copy, ";", &context); token != NULL; token = strtok_s(NULL, ";", &context)) {
        while (*token == ' ' || *token == '\t') ++token;
        if (pb_prepare_ipv6_pattern(token, &range)) ++count;
    }
    PB_IPV6_FILTER *result = malloc(sizeof(*result) + (count ? count - 1 : 0) * sizeof(range));
    if (result == NULL) { free(copy); return NULL; }
    result->count = 0;
    strcpy_s(copy, strlen(list) + 1, list);
    context = NULL;
    for (char *token = strtok_s(copy, ";", &context); token != NULL; token = strtok_s(NULL, ";", &context)) {
        while (*token == ' ' || *token == '\t') ++token;
        if (pb_prepare_ipv6_pattern(token, &range)) result->ranges[result->count++] = range;
    }
    free(copy);
    qsort(result->ranges, count, sizeof(range), pb_compare_ipv6_ranges);
    size_t merged = 0;
    for (size_t i = 0; i < count; ++i) {
        range = result->ranges[i];
        if (merged && memcmp(range.first, result->ranges[merged - 1].last, 16) <= 0) {
            if (memcmp(range.last, result->ranges[merged - 1].last, 16) > 0)
                memcpy(result->ranges[merged - 1].last, range.last, 16);
        } else result->ranges[merged++] = range;
    }
    result->count = merged;
    return result;
}

BOOL pb_match_ipv6_prepared(const PB_IPV6_FILTER *filter, const UINT8 ip[16])
{
    size_t left = 0, right = filter->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        const PB_IPV6_RANGE *range = &filter->ranges[middle];
        if (memcmp(ip, range->first, 16) < 0) right = middle;
        else if (memcmp(ip, range->last, 16) > 0) left = middle + 1;
        else return TRUE;
    }
    return FALSE;
}
