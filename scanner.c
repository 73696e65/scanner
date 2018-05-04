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

#include "allocate.h"
#include "debug.h"
#include "scanner.h"
#include "types.h"

extern patterns ps;
extern u64 tasks;
extern bool infinite;
extern pthread_mutex_t thread_mutex;
extern u16 protocols[];
extern bool brief;

extern FILE* output;
extern FILE* input;

/* Standard Usage Info */
static void usage(char* argv0)
{
  SAY("Usage:\n"
      "%s -p port1:regexp1 [ -p port2:regexp2 ... ] [ -i input.txt ] "
      "-o output.txt [-n tasks] [-t threads] [ -b ]" , argv0);
  exit(1);
}

int main(int argc, char * argv[])
{
  /* Send output to file initiated by -o parameter */
  u8* out_f = NULL;

  /* Receive IP-s from file instead of random generated */
  u8* in_f = NULL;

  /* Number of threads */
  u16 num_threads = DEF_THREADS_NO;

  /* Command line options */
  s32 opt;

  while ((opt = getopt(argc, argv, "+p:i:o:n:t:hb")) > 0)
    switch (opt) {
      case 'p': {
          u16 port = 0;
          u8* x = (u8*) strchr(optarg, ':');
          if (!x) ERR("Patterns must be in 'port:regexp' form.");
          *x = 0;
          port = atoi(optarg);
          if (!port) ERR("Invalid numeric port value '%s'.", optarg);
          if (!supported(port)) ERR("Wrong port number '%u', "
            "protocol is not supported (see documentation).", port);
          P_ADD(port, (char *) x + 1, ps);
        break;
      }

      case 'n': {
        infinite = false;
        tasks = atoi(optarg);
        if (!tasks) ERR("Invalid numeric '%s'.", optarg);
        break;
      }

      case 'i': {
        if (in_f) ERR("Multiple -i options not allowed.");
        in_f = (u8*) optarg;
        input = fopen((char*) in_f, "r");
        /* Stop when reading from file is over */
        break;
      }

      case 'o': {
        if (out_f) ERR("Multiple -o options not allowed.");
        out_f = (u8*) optarg;
        output = fopen((char*) out_f, "w");
        break;
      }

      case 't': {
        num_threads = atoi(optarg);
        if (!num_threads || num_threads > MAX_THREADS_NO)
          ERR("Invalid number of threads '%s', "
              "use numeric value between [1-%u]'.", optarg, MAX_THREADS_NO);
        break;
      }

			case 'b': {
        brief = true;
				break;
			}

      default:
        usage(argv[0]);
    }
  if (!output) ERR("Output file not specified or problem with opening the file"
                 " (-h for help).");
  if (in_f && !input) ERR("Problem with opening the input file '%s'", in_f);
  if (!ps.size) ERR("You must specify at least one pattern (-h for help)");

  /* Thread management */
  pthread_t scanner[num_threads];
  u16 t;

  while (infinite || tasks) {
    for (t = 0; t < num_threads; t++) {
      pthread_create(&scanner[t], NULL, initialize, NULL);
    }
    for (t = 0; t < num_threads; t++) {
      pthread_join(scanner[t], NULL);
    }
  }

  P_FREE(ps);
  fclose(output);

  return 0;
}
