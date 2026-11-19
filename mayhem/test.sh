#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# The suites mayhem/build.sh built with normal flags, in mayhem/build/test:
#  - htest / gtest: upstream's hash-table and gap-array unit drivers (hashtest/*.tst, testgap/*.tst);
#    each script's dump must equal upstream's golden *.tst.ref, as upstream's own `run` scripts check.
#  - probe_kat: the protocol probes on known first packets (mayhem/fuzz_probe/testsuite/*.bin) must
#    pick the protocol listed in mayhem/test/probe/expected.txt.
#  - config_dump: each sample config must parse to exactly mayhem/test/config/<cfg>.expected.
T="$SRC/mayhem/build/test"
for b in htest gtest probe_kat config_dump sslh-fork sslh-select sslh-ev echosrv; do
  [ -x "$T/$b" ] || { echo "missing $T/$b — run mayhem/build.sh first" >&2; exit 1; }
done
W="$(mktemp -d "${TMPDIR:-/tmp}/sslh-test.XXXXXX")"
trap 'rm -rf "$W"' EXIT
pass=0; fail=0
check() {  # check <name> <cmd...>; the command's status is the verdict
  local name="$1"; shift
  if "$@"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $name"; fi
}
for dir in hashtest:htest testgap:gtest; do
  d="${dir%%:*}"; bin="${dir##*:}"
  for t in "$SRC/$d"/*.tst; do
    n="$d/$(basename "$t")"
    out="$W/${d}_$(basename "$t").out"
    ( cd "$SRC/$d" && "$T/$bin" "$(basename "$t")" "$out" >/dev/null 2>&1 ) || true
    check "$n" diff -u "$t.ref" "$out"
  done
done
( cd "$SRC/mayhem/fuzz_probe/testsuite" && "$T/probe_kat" *.bin ) > "$W/probe.out" 2>&1 || true
while read -r f want_r want_p; do
  got="$(grep "^$f " "$W/probe.out" || true)"
  check "probe/$f" test "$got" = "$f $want_r $want_p"
done < "$SRC/mayhem/test/probe/expected.txt"
for c in "$SRC"/mayhem/fuzz_config/testsuite/*.cfg; do
  b="$(basename "$c")"
  "$T/config_dump" "$c" > "$W/$b.out" 2>/dev/null || true
  check "config/$b" diff -u "$SRC/mayhem/test/config/$b.expected" "$W/$b.out"
done

# Upstream's end-to-end suite, t/run (Test::More; what `make test` means to run): start echosrv's
# per protocol, run the daemon on t/*.cfg, connect over loopback and check the reply carries the
# right protocol prefix and the forwarded data (with or without a PROXY header). It runs
# "../<binary>", so it runs from a copy of t/ next to links to the binaries build.sh made. In that
# copy only: ip4-localhost becomes 127.0.0.1 (not in a container's /etc/hosts), and
# Conf::Libconfig is the shim in mayhem/test/perl.
# One `./run --binary B` per daemon rather than one run over all three: t/run only stops the
# daemon when the config changes, so in a single run the previous binary's daemon still holds
# port 8080 and the next binary's case 2 fails with "bind: Address already in use".
# Cases run: 1-7, 11, 12. Skipped, because they fail on the unmodified mirror in any environment:
#  8  (IPv6 to IPv6 PP): the client is IO::Socket::INET, IPv4-only, so it can't reach ip6-localhost.
#  9, 10 (IPv4<->IPv6 PP): expect an IPv4-mapped TCP6 PROXY header; proxyprotocol.c writes the
#     client socket's own family (TCP4) since upstream e5d7cd0 reverted the 77dc76a mapping.
#     (10 also uses test_pp5.cfg, not test_pp6.cfg.)
#  13 (client-side PP removed): its regex backend localhost:9002 has no echosrv; start_echosrv
#     starts only the first config's (test1.cfg) servers.
E2E_CASES="1 2 3 4 5 6 7 11 12"
E2E_SKIPPED_CASES=4
E2E_WANT=16            # assertions per binary: cases 1-2 one each, the 7 probe cases two each
E="$W/e2e"; mkdir -p "$E"
cp -r "$SRC/t" "$E/t"
for b in sslh-fork sslh-select sslh-ev echosrv; do ln -s "$T/$b" "$E/$b"; done
sed -i 's/ip4-localhost/127.0.0.1/g' "$E"/t/run "$E"/t/*.cfg
e2e_skip=0
for bin in sslh-fork sslh-select sslh-ev; do
  killall -q echosrv sslh-fork sslh-select sslh-ev 2>/dev/null || true
  out="$W/t_run.$bin.out"
  # shellcheck disable=SC2086
  ( cd "$E/t" && PERL5LIB="$SRC/mayhem/test/perl" timeout 300 perl ./run --binary "$bin" $E2E_CASES ) \
      > "$out" 2> "$W/t_run.$bin.err"
  rc=$?
  ok=$(grep -c '^ok [0-9]' "$out" || true)
  nok=$(grep -c '^not ok [0-9]' "$out" || true)
  grep '^not ok' "$out" | sed 's/^/FAIL: t\/run: /'
  # Fewer results than assertions (perl died, a daemon or connect hung) is a failure, not a
  # smaller pass count.
  if [ $((ok + nok)) -ne "$E2E_WANT" ]; then
    echo "FAIL: t/run --binary $bin: $((ok + nok)) results, expected $E2E_WANT (exit $rc)"
    tail -20 "$W/t_run.$bin.err"
    [ $((ok + nok)) -lt "$E2E_WANT" ] && nok=$((E2E_WANT - ok))
  fi
  pass=$((pass + ok)); fail=$((fail + nok)); e2e_skip=$((e2e_skip + 2 * E2E_SKIPPED_CASES))
done
killall -q echosrv sslh-fork sslh-select sslh-ev 2>/dev/null || true
emit_ctrf "sslh-golden+t-run" "$pass" "$fail" "$e2e_skip"
