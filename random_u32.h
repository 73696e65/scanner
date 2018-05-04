#ifndef _HAVE_RANDOM_U32_H
#define _HAVE_RANDOM_U32_H

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "types.h"

struct nrand_handle
{
    u8   i, j, s[256], *tmp;
    int  tmplen;
};
typedef struct nrand_handle nrand_h;

int get_random_bytes(void *buf, int numbytes);
u32 get_random_unique_u32();
static void nrand_addrandom(nrand_h *rand, u8 *buf, int len);
int nrand_get(nrand_h *r, void *buf, size_t len);
static u8 nrand_getbyte(nrand_h *r);
void nrand_init(nrand_h *r);

/* Get Unique Random u32 Routines

 * These magic functions are from nmap sources,
 * For more information see nmap/nbase/nbase_rnd.c
 * file or read:
 * http://seclists.org/nmap-dev/2009/q3/0695.html
 */

int get_random_bytes(void *buf, int numbytes)
{
    static nrand_h state;
    static int state_init = 0;

    /* Initialize if we need to */
    if (!state_init)
    {
        nrand_init(&state);
        state_init = 1;
    }

    /* Now fill our buffer */
    nrand_get(&state, buf, numbytes);

    return 0;
}

u32 get_random_unique_u32()
{
    static u32 state, tweak1, tweak2, tweak3;
    static int state_init = 0;
    u32 output;

    /* Initialize if we need to */
    if (!state_init)
    {
        get_random_bytes(&state, sizeof(state));
        get_random_bytes(&tweak1, sizeof(tweak1));
        get_random_bytes(&tweak2, sizeof(tweak2));
        get_random_bytes(&tweak3, sizeof(tweak3));

        state_init = 1;
    }

    state = (((state * 1664525) & 0xFFFFFFFF) + 1013904223) & 0xFFFFFFFF;

    output = state;

    output = ((output << 7) | (output >> (32 - 7)));
    output = output ^ tweak1;

    output = (((output * 1103515245) & 0xFFFFFFFF) + 12345) & 0xFFFFFFFF;

    output = ((output << 15) | (output >> (32 - 15)));
    output = output ^ tweak2;

    output = (((output * 214013) & 0xFFFFFFFF) + 2531011) & 0xFFFFFFFF;

    output = ((output << 5) | (output >> (32 - 5)));
    output = output ^ tweak3;

    return output;
}

static void nrand_addrandom(nrand_h *rand, u8 *buf, int len)
{
    int i;
    u8 si;

    rand->i--;
    for (i = 0; i < 256; i++)
    {
        rand->i = (rand->i + 1);
        si = rand->s[rand->i];
        rand->j = (rand->j + si + buf[i % len]);
        rand->s[rand->i] = rand->s[rand->j];
        rand->s[rand->j] = si;
    }
    rand->j = rand->i;
}

int nrand_get(nrand_h *r, void *buf, size_t len)
{
    u8 *p;
    size_t i;

    /* Hand out however many bytes were asked for */
    for (p = buf, i = 0; i < len; i++)
    {
        p[i] = nrand_getbyte(r);
    }
    return (0);
}

static u8 nrand_getbyte(nrand_h *r)
{
    u8 si, sj;

    /* This is the core of ARC4 and provides the pseudo-randomness */
    r->i = (r->i + 1);
    si = r->s[r->i];
    r->j = (r->j + si);
    sj = r->s[r->j];
    r->s[r->i] = sj; /* The start of the the swap */
    r->s[r->j] = si; /* The other half of the swap */
    return (r->s[(si + sj) & 0xff]);
}

void nrand_init(nrand_h *r)
{
    u8 seed[256]; /* Starts out with "random" stack data */
    int i;

    struct timeval *tv = (struct timeval *)seed;
    int *pid = (int *)(seed + sizeof(*tv));
    int fd;

    gettimeofday(tv, NULL); /* fill lowest seed[] with time */
    *pid = getpid();        /* fill next lowest seed[] with pid */

    /* Try to fill the rest of the state with OS provided entropy */
    if ((fd = open("/dev/urandom", O_RDONLY)) != -1 ||
            (fd = open("/dev/arandom", O_RDONLY)) != -1)
    {
        ssize_t n;
        do
        {
            errno = 0;
            n = read(fd, seed + sizeof(*tv) + sizeof(*pid),
                     sizeof(seed) - sizeof(*tv) - sizeof(*pid));
        }
        while (n < 0 && errno == EINTR);
        close(fd);
    }

    /* Fill up our handle with starter values */
    for (i = 0; i < 256; i++)
    {
        r->s[i] = i;
    };
    r->i = r->j = 0;

    nrand_addrandom(r, seed, 128); /* lower half of seed data for entropy */
    nrand_addrandom(r, seed + 128, 128); /* Now use upper half */
    r->tmp = NULL;
    r->tmplen = 0;

    /* This stream will start biased.  Get rid of 1K of the stream */
    nrand_get(r, seed, 256);
    nrand_get(r, seed, 256);
    nrand_get(r, seed, 256);
    nrand_get(r, seed, 256);
}


/* Returns 1 if this is a reserved IP address, where "reserved" means
 * either a private address, non-routable address, or even a non-reserved
 * but unassigned address which has an extremely high probability of being
 * black-holed.
 * For more information see nmap/libnetutil/netutil.cc
 */
int ip_is_reserved(struct in_addr *ip)
{
    char *ipc = (char *) & (ip->s_addr);
    unsigned char i1 = ipc[0], i2 = ipc[1], i3 = ipc[2];
    /* i4 not currently used - , i4 = ipc[3]; */

    /* do all the /7's and /8's with a big switch statement, hopefully the
     * compiler will be able to optimize this a little better using a jump table
     * or what have you
     */
    switch (i1)
    {
    case 0:         /* 000/8 is IANA reserved       */
    case 6:         /* USA Army ISC                 */
    case 7:         /* used for BGP protocol        */
    case 10:        /* the infamous 10.0.0.0/8      */
    case 55:        /* misc. U.S.A. Armed forces    */
    case 127:       /* 127/8 is reserved for loopback */
        return 1;
    default:
        break;
    }

    /* 172.16.0.0/12 is reserved for private nets by RFC1819 */
    if (i1 == 172 && i2 >= 16 && i2 <= 31)
        return 1;

    /* 192.0.2.0/24 is reserved for documentation and examples (RFC5737) */
    /* 192.88.99.0/24 is used as 6to4 Relay anycast prefix by RFC3068 */
    /* 192.168.0.0/16 is reserved for private nets by RFC1819 */
    if (i1 == 192)
    {
        if (i2 == 0 && i3 == 2)
            return 1;
        if (i2 == 88 && i3 == 99)
            return 1;
        if (i2 == 168)
            return 1;
    }

    /* 198.18.0.0/15 is used for benchmark tests by RFC2544 */
    /* 198.51.100.0/24 is reserved for documentation (RFC5737) */
    if (i1 == 198)
    {
        if (i2 == 18 || i2 == 19)
            return 1;
        if (i2 == 51 && i3 == 100)
            return 1;
    }

    /* 169.254.0.0/16 is reserved for DHCP clients seeking addresses */
    if (i1 == 169 && i2 == 254)
        return 1;

    /* 203.0.113.0/24 is reserved for documentation (RFC5737) */
    if (i1 == 203 && i2 == 0 && i3 == 113)
        return 1;

    /* 224-239/8 is all multicast stuff */
    /* 240-255/8 is IANA reserved */
    if (i1 >= 224)
        return 1;

    return 0;
}

#endif
