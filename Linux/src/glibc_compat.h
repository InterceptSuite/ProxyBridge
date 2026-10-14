// glibc 2.38 headers redirect strto*/scanf to C23 variants (GLIBC_2.38 symbols), which stops the binary from loading on older
// systems (GitHub issue #146). This header binds the names back to the classic symbol versions; it is force-included when
// building third-party C code (libbpf) that uses them. Our own sources avoid these functions.
#ifndef PB_GLIBC_COMPAT_H
#define PB_GLIBC_COMPAT_H

#include <features.h>

#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 38))
# if defined(__x86_64__)
#  define PB_BASE_GLIBC "GLIBC_2.2.5"
# elif defined(__aarch64__)
#  define PB_BASE_GLIBC "GLIBC_2.17"
# endif
# ifdef PB_BASE_GLIBC
#  define PB_SYMVER(name) __asm__(".symver __isoc23_" #name "," #name "@" PB_BASE_GLIBC)
PB_SYMVER(strtol);  PB_SYMVER(strtoul);  PB_SYMVER(strtoll);  PB_SYMVER(strtoull);
PB_SYMVER(scanf);   PB_SYMVER(fscanf);   PB_SYMVER(sscanf);
PB_SYMVER(vscanf);  PB_SYMVER(vfscanf);  PB_SYMVER(vsscanf);
# endif
#endif

#endif
