/* Known-answer driver for mayhem/test.sh: parses `-F <file>` with sslhcfg_cl_parse() and prints
 * the parsed configuration with sslhcfg_fprint() (sslh's verbose-config output) to stdout. */
#include <stdio.h>
#include <string.h>
#include "sslh-conf.h"

int main(int argc, char **argv)
{
    struct sslhcfg_item c;
    if (argc != 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }
    char *av[] = { (char *)"sslh", (char *)"-F", argv[1], NULL };
    memset(&c, 0, sizeof(c));
    if (sslhcfg_cl_parse(3, av, &c) != 0) { printf("PARSE ERROR\n"); return 1; }
    sslhcfg_fprint(stdout, &c, 0);
    return 0;
}
