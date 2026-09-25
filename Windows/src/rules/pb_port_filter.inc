// Match the existing atoi-based grammar, including its permissive invalid tokens.
// Delimiters stop atoi just as the old temporary NUL terminator did.
static BOOL pb_next_port_range(const char **cursor, PB_PORT_RANGE *range)
{
    const char *p = *cursor;
    while (*(p += strspn(p, ",;")) != '\0') {
        const char *end = p + strcspn(p, ",;");
        while (p < end && (*p == ' ' || *p == '\t')) ++p;
        int first, last;
        if (end - p == 1 && *p == '*') { first = 0; last = 65535; }
        else {
            const char *dash = memchr(p, '-', (size_t)(end - p));
            first = atoi(p);
            last = dash != NULL ? atoi(dash + 1) : first;
        }
        p = end;
        if (first < 0) first = 0;
        if (last > 65535) last = 65535;
        if (first <= last && first <= 65535 && last >= 0) {
            range->first = (UINT16)first; range->last = (UINT16)last;
            *cursor = p;
            return TRUE;
        }
    }
    *cursor = p;
    return FALSE;
}

static int pb_compare_port_ranges(const void *left, const void *right)
{
    const PB_PORT_RANGE *a = left, *b = right;
    return a->first != b->first ? (int)a->first - b->first : (int)a->last - b->last;
}

PB_PORT_FILTER *pb_prepare_port_list(const char *list)
{
    if (list == NULL || *list == '\0') list = "*";
    if (strnlen_s(list, MAX_LIST_SIZE) >= MAX_LIST_SIZE) return NULL;
    size_t count = 0;
    PB_PORT_RANGE range;
    const char *cursor = list;
    while (pb_next_port_range(&cursor, &range)) ++count;
    PB_PORT_FILTER *result = malloc(sizeof(*result) + (count ? count - 1 : 0) * sizeof(range));
    if (result == NULL) return NULL;
    result->count = 0;
    cursor = list;
    while (pb_next_port_range(&cursor, &range)) result->ranges[result->count++] = range;
    qsort(result->ranges, count, sizeof(range), pb_compare_port_ranges);
    size_t merged = 0;
    for (size_t i = 0; i < count; ++i) {
        range = result->ranges[i];
        if (merged && (unsigned)range.first <= (unsigned)result->ranges[merged - 1].last + 1) {
            if (range.last > result->ranges[merged - 1].last) result->ranges[merged - 1].last = range.last;
        } else result->ranges[merged++] = range;
    }
    result->count = merged;
    return result;
}

BOOL pb_match_port_prepared(const PB_PORT_FILTER *filter, UINT16 port)
{
    size_t left = 0, right = filter->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        PB_PORT_RANGE range = filter->ranges[middle];
        if (port < range.first) right = middle;
        else if (port > range.last) left = middle + 1;
        else return TRUE;
    }
    return FALSE;
}
