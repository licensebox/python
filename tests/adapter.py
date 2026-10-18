"""Conformance adapter. Synthetic binding/clock overrides are test-only."""
import json
import sys

from licensebox import Client, LicenseboxError, derive_binding, native_binding, verify_lease

request = json.load(sys.stdin)
try:
    operation = request["op"]
    if operation == "derive":
        result = derive_binding(request["product"], request["source"], request["raw_id"])
    elif operation == "verify":
        result = verify_lease(request["token"], request["product"], request["keys"], request["now"])
    elif operation == "native":
        result = native_binding(request["product"])
    else:
        options = {key: request[key] for key in ("product", "keys", "server", "directory", "ca_bundle") if key in request}
        if "binding" in request:
            options["machine_binding"] = lambda: request["binding"]
        options["clock"] = lambda: request["now"]
        options["on_sign_in"] = lambda *_: None
        client = Client(**options, version="conformance")
        if operation == "lease":
            result = client.lease()
        elif operation == "require":
            result = client.require(request.get("module", "core"))
        elif operation == "repeat":
            result = [client.require("core"), client.require("core")]
        elif operation in {"heartbeat", "heartbeat-repeat", "heartbeat-after-require"}:
            module = request.get("module", "core")
            if operation == "heartbeat-after-require":
                client.require(module)
            if operation == "heartbeat-repeat":
                client.heartbeat(module)
            result = client.heartbeat(module)
        elif operation == "status":
            result = client.status()
        elif operation == "sign_in":
            result = client.sign_in(timeout=3)
        elif operation == "logout":
            result = client.logout()
        elif operation == "modules":
            result = client.modules()
        elif operation == "request":
            result = client.request_access(["export"], "café – test")
        elif operation == "requests":
            result = client.requests()
        elif operation == "access-link":
            result = client.access_link()
        elif operation == "record":
            client.record("export", True, 0.125)
            client.record("export", False, 0.025)
            result = None
        else:
            raise ValueError("unknown adapter operation")
    print(json.dumps({"ok": True, "value": result}))
except LicenseboxError as error:
    print(json.dumps({"ok": False, "error": error.code}))
