#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <regex.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>

#include "debug.h"
#include "scanner.h"
#include "types.h"
#include "random_u32.h"

/*
 * Internal globals for pattern management
 * + Pattern structure, initialize size
 * + Number of IP address (tasks) to scan
 * + Run infinitely in the case no -n parameter specified
 * + Mutex for tasks consumers
 * + List of supported protocols by scanner
 * + Brief mode (output only IP address)
 * + Output file
 * + Input file
 * */
patterns ps = { 0, NULL };
u64 tasks = 0;
bool infinite = true;
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
u16 protocols[] = { 21, 25, 80, 8080 };
bool brief = false;

FILE *output = NULL;
FILE *input = NULL;

/* Check if you can scan this port */
bool supported(u16 port)
{
    int i;
    for (i = 0; i < sizeof(protocols) / 2; i++)
    {
        if (protocols[i] == port) return true;
    }
    return false;
}

/* Scanner function for different threads */
void *initialize(void *ptr)
{
    /* In limited execution (-n), take some task for your own */
    if (!infinite)
    {

        pthread_mutex_lock(&thread_mutex);
        if (tasks) CONSUME(tasks);
        else
        {
            pthread_mutex_unlock(&thread_mutex);
            pthread_exit(NULL);
        }

        DBG("Number of tasks left: %lu", tasks);
        pthread_mutex_unlock(&thread_mutex);
    }

    struct in_addr ip;
    char ip_s[20];
    pthread_mutex_lock(&thread_mutex);
    do
    {
        /* Read from file */
        if (input)
        {
            if (fscanf(input, "%s\n", ip_s) > 0)
            {
                inet_aton(ip_s, &ip);
            }
            else
            {
                tasks = 0;
                infinite = false; /* Exit conditions */
                pthread_mutex_unlock(&thread_mutex);
                pthread_exit(NULL);
            }
            /* .. or generate unique random IP address */
        }
        else
        {
            ip.s_addr = get_random_unique_u32();
        }
    }
    while (ip_is_reserved(&ip));
    pthread_mutex_unlock(&thread_mutex);
    scan(ip);

    return NULL;
}

u32 create_tcp_socket()
{
    s32 sockfd;
    s32 flags;
    /* Create TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    /* Read the socket status flags and set to non-blocking*/
    flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    return sockfd;
}

s32 connect_tcp_socket(s32 sockfd, struct in_addr ip, u16 port)
{
    struct sockaddr_in remote;
    /* Fill everything */
    bzero((char *) &remote, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr = ip;
    remote.sin_port = htons(port);
    /* And connect */
    connect(sockfd, (struct sockaddr *)&remote, sizeof(remote));
    return errno;
}

s32 read_from_tcp_socket(s32 sockfd, char *response, u16 count)
{
    s32 stat, n = 0;
    fd_set rfds;

    struct timeval delay;

    delay.tv_sec = WAIT_TIME_SEC;
    delay.tv_usec = 0;

    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);

    do   /* select() loop */
    {
        stat = select(sockfd + 1, &rfds, NULL, NULL, &delay);
        if (FD_ISSET(sockfd, &rfds))
        {
            n = read(sockfd, response, count);
            break;
        }
        else if (stat == 0) break;   /*Time expired */
    }
    while (0);

    return n;
}

s32 write_to_tcp_socket(s32 sockfd, char *request, u16 count)
{
    s32 stat, n = 0;
    fd_set wfds;

    struct timeval delay;
    delay.tv_sec = WAIT_TIME_SEC;
    delay.tv_usec = 0;

    FD_ZERO(&wfds);
    FD_SET(sockfd, &wfds);

    do   /* select() loop */
    {
        stat = select(sockfd + 1, NULL, &wfds, NULL, &delay);
        if (FD_ISSET(sockfd, &wfds))
        {
            n = write(sockfd, request, count);

            break;
        }
        else if (stat == 0) break;   /*Time expired */
    }
    while (0);

    return n;
}

u8 match(char *string, char *pattern)
{
    int stat;
    regex_t re;
    bzero((char *) &re, sizeof(re));

    if (regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0)
    {
        ERR("Wrong pattern");
    }
    stat = regexec(&re, string, 0, NULL, 0);
    regfree(&re);

    return (stat == REG_NOMATCH) ? false : true;
}

void scan(struct in_addr ip)
{
    char response[RESPONSE_SIZE] = "";
    char request[REQUEST_SIZE] = "";

    char *pattern;

    u16 i, port;
    s32 sockfd, n;

    /* Iterate per pattern entries */
    for (i = 0; i < ps.size; i++)
    {
        /* Create non-blocking socket */
        sockfd = create_tcp_socket();

        port = ps.entry[i].port;
        pattern = (char *) ps.entry[i].regexp;

        pthread_mutex_lock(&thread_mutex);
        DBG("Connecting to socket, host %s:%u", inet_ntoa(ip), port);
        pthread_mutex_unlock(&thread_mutex);

        switch (ps.entry[i].port)
        {
        case 21:
        case 25:
            if (connect_tcp_socket(sockfd, ip, port) == EINPROGRESS)
            {
                n = read_from_tcp_socket(sockfd, response, RESPONSE_SIZE);
                if (n > 0)
                {
                    DBG("Banner(%s:%u):\n%s", inet_ntoa(ip), port, response);
                }
            }
            break;

        case 80:
        case 3000:
            if (connect_tcp_socket(sockfd, ip, port) == EINPROGRESS)
            {
                bzero((char *) request, sizeof(request));
                strcpy(request, "HEAD / HTTP/1.0\n\n");
                n = write_to_tcp_socket(sockfd, request, strlen(request));
                if (n > 0)   /* Write was successful */
                {
                    n = read_from_tcp_socket(sockfd, response, RESPONSE_SIZE);
                    if (n > 0)
                    {
                        DBG("Banner(%s:%u):\n%s", inet_ntoa(ip), port, response);
                    }
                }
            }
            break;
        }
        close(sockfd);
        if (strlen(response))
        {
            if (match(response, pattern))
            {
                pthread_mutex_lock(&thread_mutex);
                /* Dump output */
                if (brief) fprintf(output, "%s\n", inet_ntoa(ip));
                else fprintf(output, "Matched pattern '%s' (%s:%u)\n%s\n",
                                 pattern, inet_ntoa(ip), port, response);
                fflush(output);
                pthread_mutex_unlock(&thread_mutex);
            }
        }
    }
}
