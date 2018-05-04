#ifndef _HAVE_ALLOCATE_H
#define _HAVE_ALLOCATE_H

#include <stdlib.h>

/* Add new port:regexp pair to pattern structure */
#define P_ADD(p, r, ps) do { \
  ps.size++; \
  ps.entry = realloc(ps.entry, sizeof(pattern) * (ps.size)); \
  ps.entry[ps.size - 1].port = p; \
  ps.entry[ps.size - 1].regexp = malloc(strlen(r) + 1); \
  memcpy(ps.entry[ps.size - 1].regexp, r, strlen(r)); \
} while (0)

/* Free the whole structure */
#define P_FREE(ps) do { \
  while (ps.size) { \
    free(ps.entry[--ps.size].regexp); \
  } \
  free(ps.entry); \
  ps.entry = NULL; \
} while (0)

#endif
