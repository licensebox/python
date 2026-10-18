# Licensebox for Python 3

Email sign-in, native machine-bound licences, silent renewal and signed offline
access for desktop and command-line applications. Licensebox manages licensing;
product admins handle grants and any commercial arrangements separately.

```sh
python3 -m pip install 'git+https://github.com/licensebox/python.git@v0.1.0'
```

```python
from licensebox import Client, LicenseboxError

lic = Client("myapp", {"myapp-k1": "YOUR_PUBLIC_VERIFICATION_KEY"}, version="1.0")
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
endpoint (HTTP is permitted only on loopback). `machine_binding` and `clock` are
platform/test integration seams, never end-user configuration knobs.

## Operations

| Call | Behavior |
| --- | --- |
| `require(module)` | authorize before protected work |
| `lease()` | activate initially, then silently renew per process |
| `status()` | inspect local verified state without network |
| `sign_in(timeout=..., cancel=threading.Event())` | explicit activation/account or seat transfer |
| `logout()` | remove local access state, retaining installation key |
| `modules()` | discover available modules |
| `request_access(["export"], "why")`, `requests()` | request admin approval and read answers |
| `access_link()` | short-lived private browser access link |
| `record("export", success, elapsed_seconds)` | count fixed command names when enabled |

Catch `PolicyError` for `machine_changed`, `seat_transferred`, `location_denied`
and `location_unknown`. `ModuleError` identifies missing access. Other
`LicenseboxError.code` values include `offline`, `revoked`, `denied`,
`sign_in_expired`, `expired`, `identity_unavailable`. Display errors and stop
protected work. Explicit refusals persist and are never bypassed offline.

## Platform and security

Linux is runtime-validated. macOS/Windows native adapters are implemented but
await runtime validation. Browser/WASM is not this SDK's target. Raw native IDs
remain on the host; only a product-scoped digest is sent. Native identifiers are
not hardware attestation. Cloned/spoofed IDs and modified host software remain
limitations. Offline transfer/revocation changes become known at the next online
check or lease expiry. There is no background heartbeat.

Python 3.10+, [cryptography](https://cryptography.io/en/46.0.4/hazmat/primitives/asymmetric/ed25519/)
43+; no hand-written crypto. The admin CLI stays in [licensebox/go](https://github.com/licensebox/go).
See [protocol and conformance](https://github.com/licensebox/protocol) and
[Licensebox docs](https://licensebox.dev/docs).

MIT. Copyright © 2026 [Vijai Kumar](https://meshing.engineer).
