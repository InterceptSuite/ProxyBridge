# User-mode relay regression tests

Installer staging recovery checks (no real driver or registry mutation):
`build-install-owned-test.cmd` includes production receipt handling with registry
and cleanup adapters; PendingStage covers write/flush/delete failure, collisions,
no-journal cleanup, target/rollback preservation and transfer to permanent receipts.
`build-stage-partial-test.cmd` tests production partial cleanup against real files
in a fresh directory supplied to its executable. It models interrupted copies by
creating prefixes of the payload inventory with truncated contents, including the
manifest. Covers absent directories, idempotence, foreign entries, busy files,
security refusal and retry after partial deletion. Security descriptors are
adapted in this fixture; actual persisted ACLs and process/power-loss recovery
must still be checked on PB-SUT.

These tests do not start Core or load/install a driver. Run from a developer
machine with the existing VS 18 Community C toolchain. Build scripts initialize
the toolchain only in their child command process; they do not change system PATH.

Create a fresh results directory outside the repository, then pass its absolute
path to `build-tcp-relay-test.cmd` and `build-udp-clients-test.cmd`. Run the produced
EXEs from that directory. Exit 0 means pass; any other code is failure.

- `tcp-relay-test`: actual production byte pump and send utility, real ephemeral
  IPv4 loopback sockets. Covers client/server half-close and forced relay socket
  shutdown. Timeouts prevent hangs. This does not exercise Core Stop, WFP, SOCKS
  handshakes or measure throughput.
- `udp-clients-test`: actual production client ownership helpers with explicit
  driver/config/transport adapters. Covers confirmed endpoint disappearance,
  query errors, generation/PID/destination replacement, epoch reset, preservation
  of live clients, IPv4/IPv6 and query budgeting. It does not validate real driver
  IOCTL error propagation or SOCKS transport. Integration on PB-SUT is still needed.

The internal `.inc` fragments are included by both production and tests so fixes
are tested without maintaining a copied implementation or conditional production
logic. Test sources and EXEs must not be packaged with the application.

`tcp-relay-test.exe --bench` runs four alternating direct/relay loopback rounds,
2 GiB each, and emits CSV (bytes, elapsed seconds, MiB/s, process CPU seconds).
Every byte is verified; incomplete transfers fail. Iteration 0 is warm-up.
Relay-side socket settings match current connection_handler; direct socket
settings differ. Sender/receiver and relay run in the same process, so CPU includes
generation/validation and extra relay threads can pipeline that work. These
figures are a repeatable byte-pump baseline, not an internet/WFP speed claim or
proof that adding a relay accelerates a direct connection. Multi-connection,
bidirectional and real-proxy tests remain necessary before backend selection.

UDP tests now exercise the 4096 hard ceiling, 512-client stable growth/hash lookup,
slot reuse, active-list integrity, sequential-port hash distribution and each
growth-allocation failure. Allocation accounting must return to zero on teardown.

`build-udp-transport-tests.cmd` builds:

- `udp-queue-test.exe`: production queue/send helpers with deterministic allocation
  and send adapters; FIFO, local/global limits, TTL, WOULD_BLOCK, fast path and
  fatal-send cleanup.
- `udp-socks-test.exe` (also `--auth` and `--reject`): real ephemeral loopback
  SOCKS5 control/UDP sockets, production incremental handshake/readiness selector,
  pre-handshake eight-packet queue and ordered echo. Rejection must clear the queue.
  This fixture pumps the production handshake directly; it does not start the
  full Core relay loop, open a driver or validate WFP mapping/reply routing.

`build-wildcard-test.cmd` builds `wildcard-test.exe`: the production iterative
matcher is compared with a frozen recursive reference across 1,987,804 small
pattern/text combinations and six targeted cases. An adversarial repeated-star
microbenchmark reports both timings; these are not overall traffic measurements.

`build-report-test.cmd` builds `connection-report-test.exe`: the production
connection reporting function with explicit lookup/history/callback adapters.
Checks disabled consumers, numeric history without string lookups, caller-provided
process names, callback delivery with history disabled, fallback name resolution
and duplicate suppression. It does not test concurrent callback registration or
the actual history table's IPv6 identity behavior.

`build-policy-test.cmd` builds `policy-selection-test.exe`: production selection
helper with rule/config adapters and real SRW locking. Covers IPv4/IPv6, missing
definitions, BLOCK, default selection for unknown processes, existing redirected
TCP DIRECT behavior, and settings detached from later edits. Runs 20,000 selections
alongside 20,000 simulated atomic profile publications. It does not exercise the
real driver transaction or TCP worker/socket lifecycle.

The UDP client fixture also checks the production selected-definition guard:
an unchanged SOCKS5 definition is accepted; changed revision, replaced/deleted ID
or an HTTP definition is rejected. Full callback/event-loop integration remains
a PB-SUT check.

`build-process-patterns-test.cmd` builds `process-patterns-test.exe`: production
preparation/matching compared against the previous process matcher (the reference
only fixes pointer formation for an empty trimmed token). Covers 176,616 pairs,
quotes, separators, whitespace, full paths, case, wildcards, dense/max-length lists,
invalid length and allocation failure. Matching must make no preparation allocator
calls. A long-list microbenchmark excludes one-time preparation and is not a
whole-relay throughput benchmark.

`build-rule-storage-test.cmd` builds `rule-storage-test.exe`: production rule
copy/free and process-pattern preparation with allocation fault injection.
Every allocation failure must preserve the original rule; independent clones
survive original deletion, and complete teardown returns allocation balance to zero.

`build-port-filter-test.cmd` builds `port-filter-test.exe`: the production prepared
port filter compared against frozen old token/port parsing on all 65,536 ports for
27 lists (1,769,472 comparisons). Includes wildcard, overlap, reversed/negative
ranges, permissive atoi tokens, whitespace and bounds; checks normalized intervals,
allocation-free matching and preparation failure. A 100-port microbenchmark is
specific to filtering, not full traffic throughput. Rule storage tests now inject
all six allocation failures and verify independent process and port storage.

`build-domain-filter-test.cmd` builds `domain-filter-test.exe`: prepared domain
matching compared against the old parser (215,864 comparisons), including unknown
domains, apex matching for `*.domain`, literal quotes, whitespace and maximum/dense
lists. Checks preparation failure and no allocation during matching. The long-list
timing excludes preparation and DNS lookup. Rule storage tests now cover all seven
allocations and independently owned process, port and domain filters. These tests
do not change or validate DNS-cache expiration or full driver/GUI integration.

`build-ipv6-filter-test.cmd` builds `ipv6-filter-test.exe`: prepared numeric IPv6
intervals versus the old matcher, all prefix lengths 0..128, exact/range/boundary
addresses, unknown tokens and whitespace. Checks both preparation allocations,
bounded input and allocation-free matching. The 100-address timing excludes
preparation. Rule storage now covers nine allocation attempts (eight retained
allocations, plus one temporary IPv6 string). IPv4 matching is unchanged.

`build-ipv4-filter-test.cmd` builds `ipv4-filter-test.exe`: prepared masks/ranges
versus the original parser (188,644 comparisons), all 16 wildcard-octet masks,
range edges, invalid/permissive tokens, truncation, bounds and both allocation
failures. No new IPv4 CIDR semantics. The timing is filtering only.

`build-rule-engine-test.cmd` builds `rule-engine-test.exe`: actual complete IPv4/IPv6
rule engines with all prepared filters, compared to a test-only version using the
legacy parsers. 57,600 decisions across 200 generated profiles compare action and
proxy ID; includes known/unknown DNS names, protocols, disabled rules, precedence
and an explicit deferred unrestricted-wildcard case. DNS lookups are adapters;
this does not test WFP/driver/GUI integration. Each profile also goes through
independent prepared cloning before matching. Current storage fixture injects
11 preparation and 9 clone allocation failures and checks all filter lifetimes.

`build-process-cache-test.cmd` builds the production process-name cache with
explicit process/allocator adapters. Covers live hits, replacement of a PID's
object, terminated/failed waits, access fallback, query failure, allocation failure,
clear during a miss, capacity and complete cleanup.

`build-process-cache-real-test.cmd` builds a real Windows process fixture. Compares
20,000 self-process name lookups with the former resolver, verifies no repeated
OpenProcess/name query on hits, runs 40,000 concurrent reads plus 1,000 clears,
and checks termination of its own hidden child process. It does not load a driver
or validate kernel-event PID identity/GUI Stop. Real PID reuse is modeled in the
adapter test; it is not forced on Windows. The cache holds at most 128 process
handles and names, cleared on Stop/start failure or quiescent DLL unload.

`build-rule-cache-test.cmd` builds actual matching with the bounded decision cache.
Includes full-engine parity, 40,000 concurrent decisions with 1,000 simulated
publications, deletion invalidation and domain appearance/disappearance bypass.
Compares prepared uncached matching with the wrapper on 1-rule and 64-rule profiles.
Profiles with zero/one rule or any active domain filter bypass caching. DNS is an
adapter in this fixture; the real publication IOCTL and DNS timer are not exercised.

`build-profile-config-test.cmd` builds production profile staging/commit with
driver-acceptance adapters. Checks stable IDs/revisions for equal definitions,
reorder/default ordering, duplicate one-to-one assignment, changed fields,
rule-index remapping, rejected publication preserving global state/output IDs,
exhausted ID space and the last available ID. It does not load the driver or
verify live UDP sockets on PB-SUT. Resolved proxy IP is part of definition equality.

`build-log-history-test.cmd` builds production bounded history/reporting. Covers
the old IPv6-fold collision, protocol/family/proxy-revision separation, FIFO
capacity, 80,000 concurrent identical insertions, disabling history against stale
producers and callback reentry/clear. Fixed table uses no per-event allocation.
Report fixture now verifies formatting/keying from the supplied proxy snapshot
without re-reading the store. Callback pointer publication is atomic; unregister
does not join a callback that was already captured/in flight.

`build-gui-logstore-test.cmd` builds the production GUI log storage against a
hidden stock Windows edit control, without loading Core or the driver. Checks
FIFO and pending/history ring wrap, 8000/4000 entry caps, independent 2 MiB byte
caps, 256-line/60000-character flush slices, search rebuild, allocation failure,
auto-clear and 40000 concurrent enqueue attempts racing clear/close. Counts owned
line allocations and requires zero remaining after close, including late enqueue.
Uses an 800x600 hidden edit with automatic scrolling. This is not a full GUI
interaction or traffic throughput test. The fixture also includes production GUI
callbacks: one allocation per accepted line, none when disabled/filtered/oversized,
UTF-8 conversion, maximum activity-message length and allocation failure. Eight
readers perform 80000 filter decisions while the UI publishes 2000 complete
snapshots. Matching must never see a torn pair of include filters. Callbacks still
format synchronously and allocate the final owned line; no whole-traffic speedup
is inferred from these allocation counts.

The report fixture also includes the production GUI traffic-logging toggle helper
with DLL setter adapters. Runs 10000 off/on cycles against production reporting:
off unregisters the connection callback before disabling history, skipping history
lookup, name lookup and delivery; on enables history before subscribing again.
External API callback-only mode remains supported. This does not join in-flight
callbacks, purge already queued GUI lines or disable the separate activity log.

The report fixture covers production driver-event preparation with process/policy
adapters: 10000 events with no consumers perform no name/rule/history work;
history-only and callback-only consumers retain their behavior, including captured
process-name fallback, unknown process, IPv4/TCP and IPv6/UDP. It does not execute
the real event-drain/health/reconnect loop or driver IOCTLs.

`build-logging-test.cmd` compiles the production activity-log setter/report function.
Checks formatting/truncation, disabled delivery, self-unregister and reentry, and
80000 concurrent messages with 20000 callback publications. Atomic capture does
not join callbacks already in flight; callback code must remain loaded until those
calls finish. No driver or application startup is performed by this fixture.

GUI logstore tests also cover loss accounting for full/byte-limited queues,
oversized/conversion failures and callback allocation failures. Disabled, filtered
and closed-queue messages are excluded. Summary rate limiting uses injected time;
tests cover allocation-failure retry, saturating counters, explicit clear and
auto-clear preserving the newly inserted summary. Backlog drain timing excludes
the GUI timer intervals and is not a full UI responsiveness benchmark.

TCP regression fixture now runs 16 concurrent clients through 144 half-close/stop
cases, then a stalled 16 MiB sender with a non-reading receiver and 4 KiB socket
buffer requests. Relay sockets use production transfer-phase zero timeouts. It
requires relay shutdown within one second before stopping the external peers.
KNOWN FAILURE on the current blocking backend: the stalled-write deadline fails;
the test exits 1. Existing half-close/concurrency cases pass. This is a replacement
backend acceptance gate, not a passing whole-suite result or an end-to-end Core
Stop test. Fixture cleanup shuts down peers and joins workers before closing.

`build-tcp-iocp-test.cmd` selects an experimental data-phase backend in the same
fixture. One shared IOCP and two completion workers handle overlapped recv/send;
each direction has one 128 KiB buffer and at most one outstanding operation.
Cancellation uses CancelIoEx and drains completions before freeing pair storage.
The stop hook invokes each backend's cancellation mechanism; the blocking control
still uses shutdown. Fixture owner threads still wait per pair: this is NOT yet
production integration or evidence of fewer total application threads. Accept,
proxy connect/handshake, production Stop registry and failure injection remain.
The candidate passes the stalled-write deadline that fails in the blocking control.
Optional --bench checks the existing deterministic payload over 2 GiB per run;
timing includes the test generator/checker and is not internet/WFP throughput.

IOCP candidate fault coverage: pair allocation, done-event creation, each socket
association, first/second receive submission, send submission, synthetic zero-byte
send completion, port creation and first/second pool worker creation. Partial
startup now joins created workers and releases the port before returning failure.
Tests verify restart afterward and zero tracked pairs/events/requests. Seven-byte
real send requests exercise offset progression; these are not forced short
provider completions for a larger request. Fault controls are test-only and change
only between joined cases. Full production Stop/reentrancy/rundown remains pending.

The candidate exposes async_attach separately from async_join. A test attaches
32 pairs without creating per-pair owner threads and verifies requests, replies,
both EOFs and cleanup using the two shared completion workers. Another test parks
one already-dequeued completion before processing, concurrently cancels the pair
from two threads, requires pair/event/request ownership to remain live, then
releases the completion and checks full cleanup. Barriers control this ordering;
it is not exhaustive coverage of all cancellation interleavings. Production Core
admission, socket ownership and registry integration are still absent.

`build-tcp-iocp-production-test.cmd` tests the actual pb_tcp_iocp.inc now connected
to Core startup/Stop and post-handshake handoff. Covers 96 pairs across 3 restarts,
both FIN directions, normal reaping, stalled 16 MiB stop within 1s, rejected
post-Stop attachment retaining caller-owned sockets and repeated Stop. Each of
the 96 pairs is handed off by a thread that exits before payload transmission.
Initial receives are posted by persistent IOCP workers via startup packets, not
the exiting handshake thread. Test runs this module directly, without the driver
or full Core/GUI startup. Legacy blocking fixture retains its known failure as a
reference; it is no longer the byte pump included by production pb_relay_tcp.c.
Test-only API substitutions now cover 12 production failures (allocation, event,
port, either worker, either association/startup packet/initial receive, and send),
tracked resource cleanup and restart. Admission closure races 320 handoffs.
Deterministic barriers retain a dequeued startup, receive, send or reset-error
completion while cancellation/Stop waits; these cover selected interleavings.
Sixteen real peer resets in both directions must clean up without Stop, followed
by 16 healthy pairs on the same pool. Reset can surface as an immediate Winsock
error or a failed IOCP completion. These hooks do not enter the Core binary.
Full Core/driver lifecycle and performance under representative traffic remain
unverified; module tests do not replace those integration checks.
