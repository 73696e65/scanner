#ifndef _HAVE_DEBUG_H
#define _HAVE_DEBUG_H

#include <stdio.h>

#define PRF(x...)        printf(x);

#define SAY(x...)        printf(x); printf("\n");

#define ERR(x...) do { \
  SAY("Error: " x); \
  SAY("Location: %s:%u -> %s()", \
      __FILE__, __LINE__, __FUNCTION__);\
  exit(1); \
} while (0)

#ifdef DEBUG_ENABLED
#define DBG(x...)      SAY(x)
#else
#define DBG(x...)        ;
#endif

#endif
