/* Shared by fuzz_probe.c (the libFuzzer target) and probe_kat.c (the test.sh oracle).
 *
 * Builds the protocol list the way sslh-main.c's config_protocols() does for a config that
 * enables every builtin probe: get_probe(name) for each builtin, TLS items with an SNI list
 * and an ALPN list (new_tls_data() + tls_data_set_list()), and a "regex" item whose data is a
 * NULL-terminated pcre2_code* array (as setup_regex_probe() builds it). config_protocols()
 * itself is static in sslh-main.c and also resolves backend hosts, so it cannot be called.
 *
 * All of this is built once and never written again: probe_buffer() and the probes only read
 * the list (the regex match data is overwritten by every pcre2_match call).
 */
#ifndef MAYHEM_PROBE_SETUP_H
#define MAYHEM_PROBE_SETUP_H

#include <stdlib.h>
#include <string.h>
#include "probe.h"

static const char *mayhem_sni[] = { "www.example.com", "*.example.org", "localhost" };
static const char *mayhem_alpn[] = { "h2", "http/1.1", "xmpp-client" };
static const char *mayhem_regex[] = { "^GET /secret", "^(foo|bar)+baz$", "^\\x00\\x01RAW[0-9]{2,}" };

static struct sslhcfg_protocols_item *mayhem_protos;
static struct sslhcfg_protocols_item **mayhem_proto_list;
static int mayhem_nprotos;

static struct sslhcfg_protocols_item *mayhem_add(const char *name, const char *label)
{
    struct sslhcfg_protocols_item *p = &mayhem_protos[mayhem_nprotos];
    memset(p, 0, sizeof(*p));
    p->name = (char *)name;
    p->host = (char *)"127.0.0.1";
    p->port = (char *)label;          /* only used to tell the KAT which item matched */
    p->probe = get_probe(name);
    if (!p->probe) abort();
    mayhem_proto_list[mayhem_nprotos] = p;
    mayhem_nprotos++;
    return p;
}

static void mayhem_probe_setup(void)
{
    struct protocol_probe_desc *b = get_builtins();
    int nb = get_num_builtins(), i;

    mayhem_protos = calloc(nb + 8, sizeof(*mayhem_protos));
    mayhem_proto_list = calloc(nb + 8, sizeof(*mayhem_proto_list));
    if (!mayhem_protos || !mayhem_proto_list) abort();

    /* TLS with an SNI list first, then with an ALPN list (tls_data_set_list 0 = SNI, 1 = ALPN) */
    struct sslhcfg_protocols_item *p = mayhem_add("tls", "tls-sni");
    p->data = new_tls_data();
    tls_data_set_list(p->data, 0, mayhem_sni, sizeof(mayhem_sni) / sizeof(*mayhem_sni));
    p = mayhem_add("tls", "tls-alpn");
    p->data = new_tls_data();
    tls_data_set_list(p->data, 1, mayhem_alpn, sizeof(mayhem_alpn) / sizeof(*mayhem_alpn));

    /* regex probe, with a minlength so that branch of probe_buffer is reachable too */
    p = mayhem_add("regex", "regex");
    pcre2_code **pl = calloc(sizeof(mayhem_regex) / sizeof(*mayhem_regex) + 1, sizeof(*pl));
    if (!pl) abort();
    for (i = 0; i < (int)(sizeof(mayhem_regex) / sizeof(*mayhem_regex)); i++) {
        int err; PCRE2_SIZE off;
        pl[i] = pcre2_compile((PCRE2_SPTR8)mayhem_regex[i], PCRE2_ZERO_TERMINATED, 0, &err, &off, NULL);
        if (!pl[i]) abort();
    }
    p->data = pl;
    p->minlength_is_present = 1;
    p->minlength = 4;
    probe_regex_matches = pcre2_match_data_create(1, NULL);

    /* every builtin, in builtin order; "anyprot" is last so probe_buffer skips it and falls back */
    for (i = 0; i < nb; i++) {
        if (!strcmp(b[i].name, "anyprot")) continue;
        p = mayhem_add(b[i].name, b[i].name);
        if (!strcmp(b[i].name, "tls")) p->data = new_tls_data();  /* plain TLS: any hello matches */
    }
    /* openvpn and wireguard probe differently for UDP targets (is_udp) */
    p = mayhem_add("openvpn", "openvpn-udp"); p->is_udp = 1;
    p = mayhem_add("wireguard", "wireguard-udp"); p->is_udp = 1;
    mayhem_add("anyprot", "anyprot");

    /* Reach hexdump() and the probe-info messages, but print nothing: MSG_FILE (4) with no logfile
     * opened makes print_message() a no-op after its callers did their formatting work. */
    cfg.verbose_packets = 4;
    cfg.verbose_probe_info = 4;
    cfg.verbose_probe_error = 4;
}

#endif
