// Prepared before rule publication. Packet matching only reads packed patterns.
PB_PROCESS_PATTERNS *pb_prepare_process_list(const char *list)
{
    if (list == NULL || *list == '\0') list = "*";
    size_t length = strnlen_s(list, MAX_PROCESS_NAME);
    if (length >= MAX_PROCESS_NAME) return NULL;
    char scratch[MAX_PROCESS_NAME], packed[2 * MAX_PROCESS_NAME];
    memcpy(scratch, list, length + 1);
    size_t used = 0;
    char *context = NULL;
    for (char *token = strtok_s(scratch, ",;", &context); token != NULL;
         token = strtok_s(NULL, ",;", &context)) {
        while (*token == ' ' || *token == '\t') ++token;
        char *end = token + strlen(token);
        while (end > token && (end[-1] == ' ' || end[-1] == '\t')) --end;
        *end = '\0';
        if (*token == '"' && end - token > 1) {
            ++token;
            char *quote = strchr(token, '"');
            if (quote != NULL) *quote = '\0';
        }
        unsigned char flags = 0;
        if (strchr(token, '\\') != NULL || strchr(token, '/') != NULL) flags |= 1;
        if (strchr(token, '*') != NULL) flags |= 2;
        size_t bytes = strlen(token) + 1;
        packed[used++] = (char)flags;
        memcpy(packed + used, token, bytes);
        used += bytes;
    }
    PB_PROCESS_PATTERNS *result = malloc(sizeof(*result) + used);
    if (result == NULL) return NULL;
    result->bytes = used;
    memcpy(result->patterns, packed, used);
    return result;
}

BOOL pb_match_process_prepared(const PB_PROCESS_PATTERNS *list, const char *process)
{
    const char *filename = strrchr(process, '\\');
    filename = filename != NULL ? filename + 1 : process;
    const char *pattern = list->patterns;
    const char *end = pattern + list->bytes;
    while (pattern < end) {
        unsigned char flags = (unsigned char)*pattern++;
        const char *target = flags & 1 ? process : filename;
        if (flags & 2 ? wildcard_match(pattern, target) : _stricmp(pattern, target) == 0)
            return TRUE;
        pattern += strlen(pattern) + 1;
    }
    return FALSE;
}
