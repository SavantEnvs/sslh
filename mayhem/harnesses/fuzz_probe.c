/* libFuzzer target: sslh's protocol demultiplexer on the first packet a client sends.
 * probe_buffer() (probe.h) runs every configured probe -- ssh, openvpn, wireguard, tinc, xmpp,
 * http, tls (ClientHello, SNI and ALPN parsing in tls.c), adb, socks5, syslog, teamspeak, msrdp
 * and a pcre2 regex probe -- plus hexdump() of the packet, exactly as tcp-probe.c and
 * udp-listener.c call it on attacker data. */
#include <stdint.h>
#include "probe_setup.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int init;
    struct sslhcfg_protocols_item *out;

    if (!init) { mayhem_probe_setup(); init = 1; }
    /* probe_buffer takes an int length; the daemon never passes more than its read buffer */
    if (size > 65536) return -1;

    /* exact-size heap copy so ASan catches any read past the received bytes */
    char *buf = malloc(size ? size : 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    probe_buffer(buf, (int)size, mayhem_proto_list, mayhem_nprotos, &out);
    free(buf);
    return 0;
}
