# Licensebox for Python 3

Email sign-in, native machine-bound licences, silent renewal and signed offline
access for desktop and command-line applications. Licensebox manages licensing;
product admins handle grants and any commercial arrangements separately.

```sh
python3 -m pip install 'git+https://github.com/licensebox/python.git@v0.4.0'
```

```python
from licensebox import Client, LicenseboxError

# The product's public key, "ed25519-mldsa65:...", about 2.7 KB: keep it in a
# module constant or a file rather than inline.
MYAPP_KEY = "ed25519-mldsa65:YOUR_PUBLIC_VERIFICATION_KEY"

lic = Client("myapp", {"myapp-k1": MYAPP_KEY}, version="1.0")
try:
    lic.require("export")
except LicenseboxError as error:
    raise SystemExit(str(error))
# Read/process the user's files only after require succeeds.
```

Get the product ID, module names and **public verification keys** from the product
administrator. Keep one client per process. `on_sign_in(url, code)` can open a
browser or display the sign-in instructions; the default prints to stderr.
`directory` overrides the private credential folder; `server` overrides the HTTPS
endpoint (HTTP is permitted only on loopback). `ca_bundle` optionally supplies trusted TLS roots; hostname verification stays enabled. `machine_binding` and `clock` are
platform/test integration seams, never end-user configuration knobs.

## Operations

| Call | Behavior |
| --- | --- |
| `require(module)` | authorize before protected work |
| `lease()` | activate initially, then silently renew per process |
| `heartbeat(module, cancel=threading.Event())` | force silent contact without activation; return `{lease, online}` |
| `watch(module, interval=..., cancel=..., on_stop=...)` | explicitly monitor contact and signed expiry |
| `status()` | inspect local verified state without network |
| `sign_in(timeout=..., cancel=threading.Event())` | explicit activation/account or seat transfer |
| `logout()` | remove local access state, retaining installation key |
| `modules()` | discover available modules |
| `request_access(["export"], "why")`, `requests()` | request admin approval and read answers |
| `access_link()` | short-lived private browser access link |
| `record("export", success, elapsed_seconds)` | count fixed command names when enabled |
| `checkout(module)`, `checkin(*modules)` | take and return a floating copy |
| `enrol(token)` | sign a service account's machine in with a one-time token |

Catch `PolicyError` for `machine_changed`, `seat_transferred`, `location_denied`
and `location_unknown`. `ModuleError` identifies missing access. Other
`LicenseboxError.code` values include `offline`, `revoked`, `denied`,
`sign_in_expired`, `expired`, `identity_unavailable`, `no_free_copy` and
`invalid_token`. Display errors and stop
protected work. Explicit refusals persist and are never bypassed offline.

## Platform and security

Linux is runtime-validated. macOS/Windows native adapters are implemented but
await runtime validation. Browser/WASM is not this SDK's target. Raw native IDs
remain on the host; only a product-scoped digest is sent. Native identifiers are
not hardware attestation. Cloned/spoofed IDs and modified host software remain
limitations. Offline transfer/revocation changes become known at the next online
check or lease expiry. Client construction and `require()` start no heartbeat scheduler.

Speaks protocol v3: every signature is Ed25519 and ML-DSA-65 (FIPS 204)
together, and both must verify. Python 3.10+ and
[cryptography](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mldsa/)
48+, the first release with ML-DSA; no hand-written crypto. The admin CLI stays in [licensebox/go](https://github.com/licensebox/go).
See [protocol and conformance](https://github.com/licensebox/protocol) and
[Licensebox docs](https://licensebox.dev/docs).

MIT. Copyright © 2026 [Vijai Kumar](https://meshing.engineer).

## Optional monitoring

`heartbeat("export")` always attempts silent renewal within a three-second total
network budget. Repeated stalled calls retain at most one network-only worker per client; late replies cannot change saved access. It never activates, transfers a seat or creates a missing
installation key. `online: false` means an eligible outage was covered by the
unchanged, verified, unexpired offline lease. Explicit refusals never fall back.
The server's optional signed `heartbeat` policy bounds the contact deadline.

For long-running work, monitoring is explicit:

```python
# Sign in through your normal application flow before starting a monitor.
with lic.watch("export", cancel=user_cancel_event) as monitor:
    while not monitor.stopped.is_set():
        process_one_chunk(cancel=monitor.stopped)  # your safe cancellation points
    if monitor.error:
        show_access_error(monitor.error)
```

The monitor checks at the signed server interval, or 300 seconds for a legacy
lease. `interval=` may request faster checks. An independent monotonic watchdog
sets `stopped` at the last verified signed expiry even if renewal hangs. Outages
never move that deadline; explicit refusal or missing module also stops it.
Protected work must observe `stopped`; the SDK never kills your application or
removes results. `on_stop(error)` is an optional notification; exceptions are
contained. `stop()` signals immediately and is idempotent; `close()` also waits
up to 3.2 seconds for its worker. The context manager calls `close()`. A caller
cancellation event stops scheduling and cancels in-flight network waits. No
monitor starts implicitly. A Python watchdog requires normal thread scheduling;
work that monopolizes the interpreter must cooperate with cancellation.

## Seats per module, floating copies and service accounts

A module can have seats of its own. It is in a machine's lease only while that
machine holds one of its seats; elsewhere the lease names it in `elsewhere`,
and `ModuleError.elsewhere` is set: an explicit `sign_in()` moves the seat here.

A customer can hold a pool of floating copies of a module; the lease names
such modules in `floating`. `require(module)` checks a copy out when the module
is not held outright, and raises `LicenseboxError` with code `no_free_copy`
when every copy is in use. Keep the copy with `heartbeat` or `watch` while the
work runs, and return it with `checkin(module)`. A copy lives only as long as
the lease, so a crashed application frees its copy when the heartbeat grace
passes; a heartbeat takes a lapsed copy again if one is free.

A server or build runner can be licensed as a service account. Set the
one-time token an admin issued as `LICENSEBOX_ENROL_TOKEN`, or pass
`Client(..., enrol_token=...)`: the first `require`, `lease` or `sign_in`
enrols the machine without a browser. A used or expired token raises code
`invalid_token`.
