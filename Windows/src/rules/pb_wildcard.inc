// Case-insensitive wildcard match; '*' matches any sequence (including empty).
// Handles multiple wildcards anywhere in the pattern, e.g. "*steam*", "fire*.exe".
BOOL wildcard_match(const char *pattern, const char *text)
{
    const char *after_star = NULL;
    const char *retry_text = NULL;
    while (*text != '\0')
    {
        if (*pattern == '*')
        {
            while (*pattern == '*') ++pattern;
            if (*pattern == '\0') return TRUE;
            after_star = pattern;
            retry_text = text;
        }
        else if (tolower((unsigned char)*pattern) == tolower((unsigned char)*text))
        {
            ++pattern;
            ++text;
        }
        else if (after_star != NULL) {
            // Expand the latest star by one character. Earlier stars need no
            // recursive alternatives for this literals-and-'*' pattern language.
            pattern = after_star;
            text = ++retry_text;
        }
        else return FALSE;
    }
    while (*pattern == '*') pattern++;
    return *pattern == '\0';
}

