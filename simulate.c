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
#include "types.h"
#include "allocate.h"
#include "scanner.h"


/* Extern constants */
extern u64 tasks;
extern patterns ps;
extern pthread_mutex_t thread_mutex;
extern bool infinite;
extern u16 protocols[];
extern bool brief;

extern FILE *output;

struct tree_elem
{
    struct in_addr ip;
    struct tree_elem *left;
    struct tree_elem *right;
};

typedef struct tree_elem node;

/* Tree manipulation */
void insert(node **tree, node *item)
{
    if (!(*tree))
    {
        *tree = item;
        return;
    }
    if (item->ip.s_addr < (*tree)->ip.s_addr)
        insert(&(*tree)->left, item);
    else if (item->ip.s_addr > (*tree)->ip.s_addr)
        insert(&(*tree)->right, item);
    else return;
}

node *new_node(u32 ip_addr)
{
    node *node = malloc(sizeof(node));
    node->left = node->right = NULL;
    node->ip.s_addr = ip_addr;
    return node;
}

void printall(node *node)
{
    if (node->left) printall(node->left);
    SAY("%s", inet_ntoa(node->ip));
    if (node->right) printall(node->right);
    fflush(stdout);
}

u32 length(node *node)
{
    if (node == NULL)
        return 0;
    else
        return (length(node->left) + 1 + length(node->right));
}

/* Open/read file and update IP addresses structure */
u32 update_addresses(char *file, node **root)
{
    FILE *input = fopen(file, "r");
    char ip_s[20];
    struct in_addr ip;

    node *curr = NULL;
    u32 count = 0;

    while (fscanf(input, "%s", ip_s) != EOF)
    {
        inet_aton(ip_s, &ip);
        // save IP to structure
        curr = new_node(ip.s_addr);
        insert(root, curr);
        count++;
    }
    fclose(input);
    return count;
}

/* Parameters: -f hit_list -t 1536 -n 5000 */

int main(int argc, char *argv[])
{
    node *root = NULL;

    u16 num_threads = 1536;
    u32 i, t;

    u32 epoch = 0;
    u32 epoch_max = 100000;

    brief = true;

    infinite = false;

    P_ADD(80, "Apache/2.2.3", ps);
    pthread_t scanner[num_threads];

    /* Load initial hit list */
    update_addresses("hitlist", &root);

    printall(root);

    while (epoch < epoch_max)
    {
        /* Every node runs one scanner instance */
        for (i = 0; i < length(root); i++)
        {
            tasks = 500;
            output = fopen("out_f", "w");
            /* Consume tasks */
            while (tasks)
            {
                for (t = 0; t < num_threads; t++)
                {
                    pthread_create(&scanner[t], NULL, initialize, NULL);
                }
                for (t = 0; t < num_threads; t++)
                {
                    pthread_join(scanner[t], NULL);
                }
            }
            fclose(output);
            update_addresses("out_f", &root);
        }
        epoch++;
        SAY("Length: %u, epoch %u", length(root), epoch);
        fflush(stdout);
    }

    return 0;
}
