from __future__ import annotations

import base64
import ctypes
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import secrets
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener
import ssl

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_SOURCES = {"linux-dmi", "linux-device-tree", "linux-machine-id", "windows-smbios", "macos-platform"}
_POLICY = {"seat_transferred", "location_denied", "location_unknown", "machine_changed"}
_CALLS = {"renew", "modules", "request", "requests", "access-link"}
_LIMIT = 1 << 20


class LicenseboxError(Exception):
    def __init__(self, code: str, detail: str = "", status: int = 0):
        self.code, self.detail, self.status = code, detail or code.replace("_", " "), status
        super().__init__("licensebox: " + self.detail)


class PolicyError(LicenseboxError):
    pass


class ModuleError(LicenseboxError):
    def __init__(self, product: str, module: str, email: str):
        self.product, self.module, self.email = product, module, email
        super().__init__("module_denied", f"{product}: {module} is not licensed to {email}")


def _enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _dec(value: str, length: int | None = None) -> bytes:
    try:
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError()
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if _enc(result) != value or length is not None and len(result) != length:
            raise ValueError()
        return result
    except (ValueError, TypeError) as error:
        raise LicenseboxError("malformed", "invalid base64url value") from error


def _binding_valid(value: str) -> bool:
    parts = value.split(":") if isinstance(value, str) else []
    return len(parts) == 3 and parts[0] == "m1" and parts[1] in _SOURCES and re.fullmatch(r"[0-9a-f]{64}", parts[2]) is not None


def derive_binding(product: str, source: str, raw_id: str) -> str:
    """Derive the public binding; never persist or log raw_id."""
    if not product or "\n" in product or "\r" in product or source not in _SOURCES:
        raise LicenseboxError("identity_unavailable")
    canonical = raw_id.strip("\0").strip().lower().replace("-", "")
    if not re.fullmatch(r"[0-9a-f]+", canonical) or len(canonical) % 2:
        raise LicenseboxError("identity_unavailable")
    decoded = bytes.fromhex(canonical)
    if not 8 <= len(decoded) <= 32 or source != "linux-device-tree" and len(decoded) != 16 or set(decoded) in ({0}, {255}):
        raise LicenseboxError("identity_unavailable")
    key = hashlib.sha256(("licensebox machine binding v1\n" + product).encode()).digest()
    digest = hmac.new(key, (source + "\n" + canonical).encode(), hashlib.sha256).hexdigest()
    return "m1:" + source + ":" + digest


def _smbios_uuid(raw: bytes) -> str:
    if len(raw) < 8 or (size := struct.unpack_from("<I", raw, 4)[0]) > len(raw) - 8:
        raise LicenseboxError("identity_unavailable")
    data = raw[8:8 + size]
    while len(data) >= 4:
        length = data[1]
        if length < 4 or length > len(data):
            break
        if data[0] == 1 and length >= 24:
            return data[8:24].hex()
        if data[0] == 127:
            break
        end = data.find(b"\0\0", length)
        if end < 0:
            break
        data = data[end + 2:]
    raise LicenseboxError("identity_unavailable")


def native_binding(product: str) -> str:
    """Read native identity locally. No random, hostname, IP or MAC fallback."""
    if sys.platform.startswith("linux"):
        for path, source in [("/sys/class/dmi/id/product_uuid", "linux-dmi"),
                             ("/sys/firmware/devicetree/base/serial-number", "linux-device-tree"),
                             ("/etc/machine-id", "linux-machine-id"),
                             ("/var/lib/dbus/machine-id", "linux-machine-id")]:
            try:
                return derive_binding(product, source, Path(path).read_text(encoding="ascii"))
            except (OSError, UnicodeError, LicenseboxError):
                continue
    elif sys.platform == "darwin":
        try:
            raw = subprocess.check_output(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], timeout=3)
            match = re.search(rb'"IOPlatformUUID"\s*=\s*"([0-9a-fA-F-]{36})"', raw)
            if match:
                return derive_binding(product, "macos-platform", match[1].decode("ascii"))
        except (OSError, subprocess.SubprocessError):
            pass
    elif sys.platform == "win32":
        try:
            function = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemFirmwareTable
            function.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
            function.restype = ctypes.c_uint32
            size = function(0x52534D42, 0, None, 0)
            if 8 <= size <= _LIMIT:
                buffer = ctypes.create_string_buffer(size)
                if function(0x52534D42, 0, buffer, size) == size:
                    return derive_binding(product, "windows-smbios", _smbios_uuid(buffer.raw))
        except (OSError, AttributeError):
            pass
    raise LicenseboxError("identity_unavailable", "a stable native machine identity is unavailable")


def _stamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(value: str) -> float:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError()
        return parsed.timestamp()
    except (ValueError, TypeError, AttributeError) as error:
        raise LicenseboxError("malformed", "invalid timestamp") from error


def _parse(token: str) -> tuple[dict, bytes, bytes]:
    try:
        payload, signature = token.strip().split(".")
        data = _dec(payload)
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError()
        return value, data, _dec(signature, 64)
    except (ValueError, UnicodeError, TypeError) as error:
        raise LicenseboxError("malformed", "invalid lease token") from error


def verify_lease(token: str, product: str, keys: Mapping[str, str], now: float, *, allow_expired: bool = False) -> dict:
    value, payload, signature = _parse(token)
    if value.get("v") != 2:
        raise LicenseboxError("version", "unsupported lease version; update the application")
    if value.get("kid") not in keys:
        raise LicenseboxError("unknown_key")
    try:
        Ed25519PublicKey.from_public_bytes(_dec(keys[value["kid"]], 32)).verify(signature, b"licensebox lease v2\n" + payload)
    except InvalidSignature as error:
        raise LicenseboxError("bad_signature") from error
    if value.get("product") != product or not _binding_valid(value.get("binding", "")):
        raise LicenseboxError("malformed", "lease product or native binding does not match")
    _dec(value.get("machine", ""), 32)
    if not isinstance(value.get("modules"), list) or any(not isinstance(item, str) for item in value["modules"]):
        raise LicenseboxError("malformed", "invalid module list")
    expires = _epoch(value.get("expires"))
    heartbeat = value.get("heartbeat")
    if heartbeat is not None:
        if not isinstance(heartbeat, dict):
            raise LicenseboxError("malformed", "invalid heartbeat policy")
        interval, grace = heartbeat.get("interval_seconds"), heartbeat.get("grace_seconds")
        if (type(interval) is not int or type(grace) is not int or not 30 <= interval <= 86400
                or not interval <= grace <= 31536000 or expires > _epoch(value.get("issued")) + grace):
            raise LicenseboxError("malformed", "invalid heartbeat policy or contact deadline")
    if now >= expires and not allow_expired:
        raise LicenseboxError("expired")
    return value


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, product: str, keys: Mapping[str, str], *, version: str = "", server: str = "https://licensebox.dev",
                 directory: str | Path | None = None, on_sign_in: Callable[[str, str], None] | None = None,
                 machine_binding: Callable[[], str] | None = None, clock: Callable[[], float] = time.time,
                 ca_bundle: str | Path | None = None):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", product) or not keys:
            raise ValueError("a product ID and trusted public keys are required")
        for key in keys.values():
            _dec(key, 32)
        url = urlsplit(server)
        if url.username or url.password or url.query or url.fragment or url.scheme != "https" and not (url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError("server must use HTTPS (HTTP is allowed only on loopback)")
        if directory is None:
            base = os.environ.get("APPDATA") if sys.platform == "win32" else (str(Path.home() / "Library/Application Support") if sys.platform == "darwin" else os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
            if not base:
                raise LicenseboxError("io_error", "user configuration directory is unavailable")
            directory = Path(base) / "licensebox" / product
        self.product, self.keys, self.version, self.server = product, dict(keys), version, server.rstrip("/")
        self.directory, self.on_sign_in, self.clock = Path(directory), on_sign_in, clock
        self._binding_provider = machine_binding or (lambda: native_binding(product))
        self._host: str | None = None
        self._checked: dict | None = None
        self._lock = threading.RLock()
        self._transport_lock = threading.Lock()
        self._pending_exchange: threading.Event | None = None
        self._http = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=ca_bundle)))

    def _binding(self) -> str:
        if self._host is None:
            value = self._binding_provider()
            if not _binding_valid(value):
                raise LicenseboxError("identity_unavailable")
            self._host = value
        return self._host

    def _read(self, name: str) -> str:
        try:
            return (self.directory / name).read_text().strip()
        except FileNotFoundError:
            return ""

    def _write(self, name: str, content: str) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=self.directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write(content + "\n")
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.directory / name)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _remove(self, name: str) -> None:
        try:
            (self.directory / name).unlink()
        except FileNotFoundError:
            pass

    def _now(self) -> float:
        now = self.clock()
        seen = self._read("seen")
        if seen:
            now = max(now, _epoch(seen))
        self._write("seen", datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z"))
        return now

    def _key(self) -> Ed25519PrivateKey:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        for _ in range(40):
            try:
                seed = self._read("install.key")
                if seed:
                    return Ed25519PrivateKey.from_private_bytes(_dec(seed, 32))
            except LicenseboxError:
                pass
            try:
                descriptor = os.open(self.directory / "install.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                time.sleep(0.025)
                continue
            key = Ed25519PrivateKey.generate()
            with os.fdopen(descriptor, "w") as output:
                output.write(_enc(key.private_bytes_raw()) + "\n")
            return key
        raise LicenseboxError("io_error", "installation key is damaged or being written by another process")

    def _existing_key(self) -> Ed25519PrivateKey:
        seed = self._read("install.key")
        if not seed:
            raise LicenseboxError("not_signed_in", "the installation key is unavailable; explicitly sign in")
        try:
            return Ed25519PrivateKey.from_private_bytes(_dec(seed, 32))
        except (LicenseboxError, ValueError) as error:
            raise LicenseboxError("io_error", "the installation key is damaged; explicitly sign in") from error

    def _own(self, value: dict, key: Ed25519PrivateKey | None = None) -> None:
        if value.get("binding") != self._binding() or value.get("machine") != _enc((key or self._key()).public_key().public_bytes_raw()):
            raise PolicyError("machine_changed", "these credentials belong to another machine; explicitly sign in to activate here")

    def _denial(self) -> None:
        text = self._read("policy-denial")
        if text or (self.directory / "policy-denial").exists():
            try:
                value = json.loads(text)
                if value["code"] not in _POLICY:
                    raise ValueError()
            except (ValueError, KeyError, TypeError) as error:
                raise LicenseboxError("io_error", "saved policy refusal is damaged; connect to renew") from error
            raise PolicyError(value["code"], value.get("detail", ""))

    def _post(self, path: str, payload: dict, timeout: float = 20,
              cancel: threading.Event | None = None) -> dict | list:
        request = Request(self.server + path, json.dumps(payload, separators=(",", ":")).encode(), {"Content-Type": "application/json"})
        # Only the network exchange runs in this bounded worker. Persistent state
        # is handled on the calling thread, so a late response cannot change access.
        done, abandon = threading.Event(), threading.Event()
        outcome: dict = {}
        deadline = time.monotonic() + timeout
        def exchange():
            try:
                try:
                    response = self._http.open(request, timeout=timeout)
                except HTTPError as response_error:
                    response = response_error
                with response:
                    outcome["status"] = response.code
                    chunks, length = [], 0
                    while length <= _LIMIT and not abandon.is_set():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError()
                        # Bound each socket read by the remaining total budget.
                        try:
                            response.fp.raw._sock.settimeout(remaining)
                        except AttributeError:
                            pass
                        chunk = response.read1(min(65536, _LIMIT + 1 - length))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        length += len(chunk)
                    outcome["data"] = b"".join(chunks)
            except BaseException as error:
                outcome["error"] = error
            finally:
                done.set()
        with self._transport_lock:
            if self._pending_exchange is not None and not self._pending_exchange.is_set():
                raise LicenseboxError("network_error", "the previous licensing connection is still closing")
            self._pending_exchange = done
            try:
                threading.Thread(target=exchange, name="licensebox-http", daemon=True).start()
            except BaseException:
                done.set()
                raise
        while not done.wait(min(0.05, max(0, deadline - time.monotonic()))):
            if cancel is not None and cancel.is_set():
                abandon.set()
                raise LicenseboxError("cancelled")
            if time.monotonic() >= deadline:
                abandon.set()
                raise LicenseboxError("network_error", "cannot reach the licensing server", outcome.get("status", 0))
        if cancel is not None and cancel.is_set():
            abandon.set()
            raise LicenseboxError("cancelled")
        if "error" in outcome:
            raise LicenseboxError("network_error", "cannot reach the licensing server", outcome.get("status", 0)) from outcome["error"]
        status, data = outcome["status"], outcome["data"]
        if len(data) > _LIMIT:
            raise LicenseboxError("protocol_error", "invalid server response", status)
        try:
            value = json.loads(data)
        except (ValueError, UnicodeError) as error:
            raise LicenseboxError("protocol_error" if status == 200 else "http_error", f"HTTP {status}", status) from error
        if status != 200:
            code = value.get("error", "http_error") if isinstance(value, dict) else "http_error"
            detail = value.get("error_description", "") if isinstance(value, dict) else ""
            code = code if isinstance(code, str) else "http_error"
            detail = detail if isinstance(detail, str) else ""
            if code in _POLICY:
                self._write("policy-denial", json.dumps({"code": code, "detail": detail or code}))
                raise PolicyError(code, detail, status)
            if code == "revoked":
                self._forget()
            raise LicenseboxError(code, detail, status)
        return value

    def _save(self, token: str, key: Ed25519PrivateKey | None = None) -> dict:
        value = verify_lease(token, self.product, self.keys, self._now())
        self._own(value, key)
        self._write("lease", token)
        self._remove("policy-denial")
        return value

    def _call(self, kind: str, payload: dict, *, timeout: float = 20, key: Ed25519PrivateKey | None = None, cancel: threading.Event | None = None) -> dict | list:
        if kind not in _CALLS:
            raise ValueError("unknown signed operation")
        token = self._read("lease")
        value, _, _ = _parse(token)
        self._own(value, key)
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        at = _stamp(self.clock())
        message = f"licensebox {kind} v2\n{token}\n{self._binding()}\n{at}\n{hashlib.sha256(body.encode()).hexdigest()}"
        return self._post("/v1/" + kind, {"lease": token, "binding": self._binding(), "time": at,
                          "payload": body, "version": self.version, "signature": _enc((key or self._key()).sign(message.encode()))}, timeout, cancel)

    def _renew(self, timeout: float = 3, *, key: Ed25519PrivateKey | None = None, cancel: threading.Event | None = None) -> dict:
        sent = self._usage()[:100]
        response = self._call("renew", {"usage": sent}, timeout=timeout, key=key, cancel=cancel)
        value = self._save(response["lease"], key)
        self._usage_sent(sent, response.get("usage", False))
        return value

    def lease(self) -> dict:
        with self._lock:
            self._binding()
            now = self._now()
            if self._checked and now < _epoch(self._checked["expires"]) and not (self.directory / "policy-denial").exists():
                return copy.deepcopy(self._checked)
            token = self._read("lease")
            if not token:
                return self._sign_in(False)
            try:
                kept = verify_lease(token, self.product, self.keys, now, allow_expired=True)
            except LicenseboxError:
                return self._sign_in(False)
            self._own(kept)
            try:
                self._checked = self._renew()
                return copy.deepcopy(self._checked)
            except PolicyError:
                raise
            except LicenseboxError as error:
                if error.code in {"invalid_lease", "terms_changed"}:
                    return self._sign_in(False)
                if error.code == "revoked" or 300 <= error.status < 500:
                    raise
                self._denial()
                if error.code == "network_error" or error.status >= 500:
                    if now < _epoch(kept["expires"]):
                        return kept
                    raise LicenseboxError("offline", "the offline lease expired; connect to the internet") from error
                raise

    def require(self, module: str) -> dict:
        with self._lock:
            value = self.lease()
            if module not in value["modules"] and self._checked is None:
                try:
                    value = self._checked = self._renew()
                except PolicyError:
                    raise
                except LicenseboxError as error:
                    if error.code != "network_error" and error.status < 500:
                        raise
            if module not in value["modules"]:
                raise ModuleError(self.product, module, value.get("email", ""))
            return copy.deepcopy(value)

    def heartbeat(self, module: str, *, cancel: threading.Event | None = None) -> dict:
        """Force a silent contact; never activate or replace the installation key."""
        if not isinstance(module, str) or not module:
            raise LicenseboxError("invalid_argument", "a nonempty module is required")
        with self._lock:
            if cancel is not None and cancel.is_set():
                raise LicenseboxError("cancelled")
            token = self._read("lease")
            if not token:
                raise LicenseboxError("not_signed_in")
            kept = verify_lease(token, self.product, self.keys, self._now(), allow_expired=True)
            key = self._existing_key()
            self._own(kept, key)
            try:
                value = self._renew(key=key, cancel=cancel)
                online = True
            except LicenseboxError as error:
                if (isinstance(error, PolicyError) or error.code in {"revoked", "invalid_lease", "terms_changed"}
                        or 300 <= error.status < 500):
                    raise
                if error.code != "network_error" and error.status < 500:
                    raise
                self._denial()
                if self._now() >= _epoch(kept["expires"]):
                    raise LicenseboxError("offline", "the offline lease expired; connect to the internet") from error
                value, online = kept, False
            self._checked = value
            if module not in value["modules"]:
                raise ModuleError(self.product, module, value.get("email", ""))
            return {"lease": copy.deepcopy(value), "online": online}

    def watch(self, module: str, *, interval: float | None = None,
              cancel: threading.Event | None = None,
              on_stop: Callable[[LicenseboxError | None], None] | None = None) -> HeartbeatMonitor:
        """Explicitly start a monitor after the initial heartbeat succeeds."""
        return HeartbeatMonitor(self, module, interval=interval, cancel=cancel, on_stop=on_stop)

    def status(self) -> dict:
        with self._lock:
            self._denial()
            token = self._read("lease")
            if not token:
                raise LicenseboxError("not_signed_in")
            value = verify_lease(token, self.product, self.keys, self._now(), allow_expired=True)
            self._own(value)
            if self._now() >= _epoch(value["expires"]):
                raise LicenseboxError("expired")
            return value

    def sign_in(self, *, timeout: float | None = None, cancel: threading.Event | None = None) -> dict:
        with self._lock:
            return self._sign_in(True, timeout, cancel)

    def _sign_in(self, explicit: bool, timeout: float | None = None, cancel: threading.Event | None = None, rotated: bool = False) -> dict:
        binding = self._binding()
        old = None
        try:
            old, _, _ = _parse(self._read("lease"))
        except LicenseboxError:
            pass
        if old and _binding_valid(old.get("binding", "")) and old["binding"] != binding:
            if not explicit:
                raise PolicyError("machine_changed", "explicitly sign in to activate this machine")
            self._rotate()
            rotated = True
        key, at = self._key(), _stamp(self.clock())
        proof = f"licensebox device v2\n{self.product}\n{binding}\n{at}".encode()
        try:
            device = self._post("/v1/device", {"product": self.product, "machine": _enc(key.public_key().public_bytes_raw()),
                    "binding": binding, "os": {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux"),
                    "arch": {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine()),
                    "version": self.version, "time": at, "signature": _enc(key.sign(proof))})
        except PolicyError as error:
            if explicit and not rotated and error.code == "machine_changed":
                self._rotate()
                return self._sign_in(False, timeout, cancel, True)
            raise
        link = device.get("verification_uri_complete", device["verification_uri"])
        if self.on_sign_in:
            self.on_sign_in(link, device["user_code"])
        else:
            print(f"{self.product} needs a one-time sign-in.\nOpen {link} and enter {device['user_code']}", file=sys.stderr)
        interval = device.get("interval_ms", 0) / 1000 or max(device.get("interval", 1), 1)
        deadline = time.monotonic() + min(device["expires_in"], timeout if timeout is not None else device["expires_in"])
        while time.monotonic() < deadline:
            delay = min(interval, max(0, deadline - time.monotonic()))
            if cancel is not None:
                if cancel.wait(delay):
                    raise LicenseboxError("cancelled")
            else:
                time.sleep(delay)
            if time.monotonic() >= deadline:
                break
            at = _stamp(self.clock())
            try:
                response = self._post("/v1/token", {"device_code": device["device_code"], "binding": binding, "time": at,
                        "signature": _enc(key.sign(f"licensebox token v2\n{device['device_code']}\n{binding}\n{at}".encode()))}, min(20, max(0.01, deadline-time.monotonic())))
                value = self._save(response["lease"])
                if old and old.get("user") != value.get("user"):
                    self._remove("usage.json")
                self._usage_sent([], response.get("usage", False))
                self._checked = value
                return dict(value)
            except LicenseboxError as error:
                if error.code == "authorization_pending":
                    continue
                if error.code == "slow_down":
                    interval += 5
                    continue
                if error.code == "network_error" or error.status >= 500:
                    continue
                if error.code == "access_denied":
                    raise LicenseboxError("denied") from error
                if error.code == "expired_token":
                    raise LicenseboxError("sign_in_expired") from error
                raise
        raise LicenseboxError("sign_in_expired")

    def _rotate(self) -> None:
        self._write("install.key", _enc(Ed25519PrivateKey.generate().private_bytes_raw()))
        self._forget()

    def _forget(self) -> None:
        self._checked = None
        for name in ("lease", "usage.json", "usage-on", "policy-denial"):
            self._remove(name)

    def logout(self) -> None:
        with self._lock:
            self._forget()

    def modules(self) -> list:
        with self._lock:
            self.lease()
            return self._call("modules", {})

    def request_access(self, modules: list[str], note: str) -> dict:
        with self._lock:
            self.lease()
            return self._call("request", {"modules": modules, "note": note})

    def requests(self) -> list:
        with self._lock:
            self.lease()
            return self._call("requests", {})

    def access_link(self) -> str:
        with self._lock:
            self.lease()
            return self._call("access-link", {})["url"]

    def _usage(self) -> list:
        text = self._read("usage.json")
        return json.loads(text) if text else []

    def _usage_sent(self, sent: list, enabled: bool) -> None:
        self._write("usage-on", "on" if enabled else "off")
        if sent:
            remaining = [item for item in self._usage() if item not in sent]
            self._write("usage.json", json.dumps(remaining))

    def record(self, command: str, ok: bool, elapsed_seconds: float) -> None:
        """Count fixed command names only; never pass paths, arguments or data."""
        with self._lock:
            if self._read("usage-on") != "on" or not command or len(command.encode()) > 64 or elapsed_seconds < 0:
                return
            queued = self._usage()
            group = {"day": _stamp(self.clock())[:10], "command": command, "version": self.version[:64],
                     "os": {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux") + "/" + {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())}
            item = next((item for item in queued if all(item.get(k) == v for k, v in group.items())), None)
            if item is None:
                item = dict(group, id=secrets.token_hex(16), ok=0, failed=0, ms=0)
                queued.append(item)
            item["ok" if ok else "failed"] += 1
            item["ms"] += int(elapsed_seconds * 1000)
            self._write("usage.json", json.dumps(queued[-1000:]))


class HeartbeatMonitor:
    """Opt-in heartbeat threads and an independent signed-expiry watchdog.

    Protected work must observe ``stopped``. ``stop()`` signals immediately;
    ``close()`` also waits up to 3.2 seconds for an in-flight check to finish.
    Callbacks never run while holding the client lock and cannot prevent stopping.
    """
    def __init__(self, client: Client, module: str, *, interval: float | None = None,
                 cancel: threading.Event | None = None,
                 on_stop: Callable[[LicenseboxError | None], None] | None = None):
        if interval is not None and (isinstance(interval, bool) or not isinstance(interval, (int, float))
                                     or not 0 < interval < float("inf")):
            raise ValueError("interval must be a positive number of seconds")
        if cancel is not None and cancel.is_set():
            raise LicenseboxError("cancelled")
        first = client.heartbeat(module, cancel=cancel)
        if cancel is not None and cancel.is_set():
            raise LicenseboxError("cancelled")
        self.stopped = threading.Event()
        self.error: LicenseboxError | None = None
        self._client, self._module = client, module
        self._interval, self._cancel, self._on_stop = interval, cancel, on_stop
        self._guard = threading.Lock()
        self._latest = first
        self._expires = _epoch(first["lease"]["expires"])
        self._deadline = time.monotonic() + max(0, self._expires - client._now())
        self._worker = threading.Thread(target=self._run, name="licensebox-heartbeat", daemon=True)
        self._watchdog = threading.Thread(target=self._watch, name="licensebox-expiry", daemon=True)
        self._watchdog.start()
        self._worker.start()

    @property
    def latest(self) -> dict:
        with self._guard:
            return json.loads(json.dumps(self._latest))

    def _expired(self) -> bool:
        return time.monotonic() >= self._deadline

    def _finish(self, error: LicenseboxError | None) -> None:
        with self._guard:
            if self.stopped.is_set():
                return
            self.error = error
            self.stopped.set()
        if self._on_stop:
            def notify():
                try:
                    self._on_stop(error)
                except BaseException:
                    pass
            threading.Thread(target=notify, name="licensebox-notify", daemon=True).start()

    def stop(self) -> None:
        """Cancel scheduling and notify consumer work immediately; idempotent."""
        self._finish(None)

    def close(self) -> None:
        self.stop()
        end = time.monotonic() + 3.2
        for thread in (self._watchdog, self._worker):
            if thread is not threading.current_thread():
                thread.join(max(0, end - time.monotonic()))

    def __enter__(self) -> HeartbeatMonitor:
        return self

    def __exit__(self, *_):
        self.close()

    def _watch(self) -> None:
        while not self.stopped.is_set():
            if self._cancel is not None and self._cancel.is_set():
                self._finish(LicenseboxError("cancelled"))
                return
            with self._guard:
                expired = self._expired()
                delay = min(0.05, max(0, self._deadline - time.monotonic()))
            if expired:
                self._finish(LicenseboxError("expired", "the signed heartbeat deadline expired"))
                return
            self.stopped.wait(delay)

    def _run(self) -> None:
        while not self.stopped.is_set():
            with self._guard:
                policy = self._latest["lease"].get("heartbeat") or {}
                interval = min(self._interval or float("inf"), policy.get("interval_seconds", 300))
            if self.stopped.wait(interval):
                return
            try:
                result = self._client.heartbeat(self._module, cancel=self.stopped)
                # Never hold the watchdog guard while invoking client/host code.
                observed = self._client._now() if result["online"] else None
                # A successful late renewal cannot bridge an authorization gap.
                with self._guard:
                    if self.stopped.is_set():
                        return
                    expired = self._expired()
                    if not expired:
                        self._latest = result
                        if result["online"]:
                            self._expires = _epoch(result["lease"]["expires"])
                            self._deadline = time.monotonic() + max(0, self._expires - observed)
                if expired:
                    self._finish(LicenseboxError("expired", "the signed heartbeat deadline expired"))
                    return
            except BaseException as error:
                self._finish(error if isinstance(error, LicenseboxError) else LicenseboxError("monitor_error", "heartbeat check failed"))
                return
