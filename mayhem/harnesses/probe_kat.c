/* Known-answer driver for mayhem/test.sh: for each input file, prints
 *   <file> <AGAIN|MATCH> <label of the matched protocol item | ->
 * using the same protocol list as fuzz_probe. */
#include <stdio.h>
#include "probe_setup.h"

int main(int argc, char **argv)
{
    int i;
    mayhem_probe_setup();
    for (i = 1; i < argc; i++) {
        static char buf[65536];
        FILE *f = fopen(argv[i], "rb");
        if (!f) { perror(argv[i]); return 2; }
        size_t n = fread(buf, 1, sizeof(buf), f);
        fclose(f);
        struct sslhcfg_protocols_item *out = NULL;
        int r = probe_buffer(buf, (int)n, mayhem_proto_list, mayhem_nprotos, &out);
        printf("%s %s %s\n", argv[i], r == PROBE_MATCH ? "MATCH" : r == PROBE_AGAIN ? "AGAIN" : "NEXT",
               out ? out->port : "-");
    }
    return 0;
}
