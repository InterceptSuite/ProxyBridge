static void free_rules(PROCESS_RULE *list)
{
    while (list != NULL) {
        PROCESS_RULE *next = list->next;
        free(list->target_hosts);
        free(list->target_ports);
        free(list->target_domains);
        free(list->prepared_process);
        free(list->prepared_ports);
        free(list->prepared_domains);
        free(list->prepared_ipv6);
        free(list->prepared_ipv4);
        free(list);
        list = next;
    }
}

static void *copy_prepared(const void *source, size_t bytes)
{
    void *copy = malloc(bytes);
    if (copy != NULL) memcpy(copy, source, bytes);
    return copy;
}

static PROCESS_RULE *copy_rule(const PROCESS_RULE *source)
{
    PROCESS_RULE *copy = malloc(sizeof(*copy));
    if (copy == NULL) return NULL;
    *copy = *source;
    copy->next = NULL;
    // Existing published filters are immutable and pointer-free internally.
    // Copy only searchable ranges after compaction, without parsing again.
    copy->prepared_process = source->prepared_process
        ? copy_prepared(source->prepared_process, sizeof(*source->prepared_process) + source->prepared_process->bytes)
        : pb_prepare_process_list(source->process_name);
    copy->prepared_ports = source->prepared_ports
        ? copy_prepared(source->prepared_ports, sizeof(*source->prepared_ports) +
            (source->prepared_ports->count ? source->prepared_ports->count - 1 : 0) * sizeof(PB_PORT_RANGE))
        : pb_prepare_port_list(source->target_ports);
    copy->prepared_domains = source->prepared_domains
        ? copy_prepared(source->prepared_domains, sizeof(*source->prepared_domains) + source->prepared_domains->bytes)
        : pb_prepare_domain_list(source->target_domains);
    copy->prepared_ipv6 = source->prepared_ipv6
        ? copy_prepared(source->prepared_ipv6, sizeof(*source->prepared_ipv6) +
            (source->prepared_ipv6->count ? source->prepared_ipv6->count - 1 : 0) * sizeof(PB_IPV6_RANGE))
        : pb_prepare_ipv6_list(source->target_hosts);
    copy->prepared_ipv4 = source->prepared_ipv4
        ? copy_prepared(source->prepared_ipv4, sizeof(*source->prepared_ipv4) +
            (source->prepared_ipv4->count ? source->prepared_ipv4->count - 1 : 0) * sizeof(PB_IPV4_TERM))
        : pb_prepare_ipv4_list(source->target_hosts);
    copy->target_hosts = _strdup(source->target_hosts);
    copy->target_ports = _strdup(source->target_ports);
    copy->target_domains = _strdup(source->target_domains);
    if (!copy->target_hosts || !copy->target_ports || !copy->target_domains ||
        !copy->prepared_process || !copy->prepared_ports || !copy->prepared_domains ||
        !copy->prepared_ipv6 || !copy->prepared_ipv4) {
        free_rules(copy);
        return NULL;
    }
    return copy;
}

