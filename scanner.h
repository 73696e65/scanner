#ifndef _HAVE_SCANNER_H
#define _HAVE_SCANNER_H

#include "types.h"

/* Decrement tasks and save decremented value to second variable */
#define CONSUME(x) (x--)

#define DEF_THREADS_NO      512
#define MAX_THREADS_NO     2048

#define RESPONSE_SIZE      2048
#define REQUEST_SIZE       2048
#define WAIT_TIME_SEC         1

bool supported(u16 port);
void *initialize(void *ptr);
u32 create_tcp_socket();
s32 connect_tcp_socket(s32 sockfd, struct in_addr ip, u16 port);
s32 read_from_tcp_socket(s32 sockfd, char *response, u16 count);
s32 write_to_tcp_socket(s32 sockfd, char *request, u16 count);
u8 match(char *string, char *pattern);
void scan(struct in_addr ip);

typedef struct
{
    u16 port;
    u8 *regexp;
} pattern;

typedef struct
{
    u16 size;
    pattern *entry;
} patterns;

#endif
