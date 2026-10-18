import tempfile
import base64
import json
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from licensebox import Client, HeartbeatMonitor, LicenseboxError


def result(seconds=0.2, online=True):
    return {"lease": {"expires": datetime.fromtimestamp(time.time()+seconds, timezone.utc).isoformat(),
                      "heartbeat": {"interval_seconds": 30, "grace_seconds": 90}}, "online": online}


class MonitorTests(unittest.TestCase):
    def fake(self, first, check):
        client = Mock()
        client.clock = time.time
        client._now = time.time
        client.heartbeat.side_effect = [first, check] if isinstance(check, BaseException) else None
        if not isinstance(check, BaseException):
            calls = 0
            def heartbeat(module, **_):
                nonlocal calls
                calls += 1
                return first if calls == 1 else check()
            client.heartbeat.side_effect = heartbeat
        return client

    def test_no_implicit_threads_or_identity_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Client("demo", {"test": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}, directory=directory)
            before = set(threading.enumerate())
            with self.assertRaises(LicenseboxError) as caught:
                client.heartbeat("core")
            self.assertEqual(caught.exception.code, "not_signed_in")
            self.assertEqual(set(threading.enumerate()), before)
            self.assertFalse((Path(directory)/"install.key").exists())

    def test_hung_renewal_cannot_outlive_signed_expiry(self):
        release, entered = threading.Event(), threading.Event()
        def blocked():
            entered.set()
            release.wait(2)
            return result(60)
        client = self.fake(result(), blocked)
        monitor = HeartbeatMonitor(client, "core", interval=0.01)
        try:
            self.assertTrue(entered.wait(0.5))
            self.assertTrue(monitor.stopped.wait(0.6))
            self.assertEqual(monitor.error.code, "expired")
            release.set()
            monitor.close()
            self.assertEqual(monitor.error.code, "expired")
            self.assertFalse(monitor._worker.is_alive())
            self.assertFalse(monitor._watchdog.is_alive())
        finally:
            release.set()
            monitor.close()

    def test_offline_success_does_not_extend_deadline(self):
        initial = result()
        client = self.fake(initial, lambda: dict(initial, online=False))
        with HeartbeatMonitor(client, "core", interval=0.01) as monitor:
            self.assertTrue(monitor.stopped.wait(0.6))
            self.assertEqual(monitor.error.code, "expired")
            self.assertGreater(client.heartbeat.call_count, 1)

    def test_explicit_refusal_stops_and_callback_errors_are_contained(self):
        callback = threading.Event()
        def notify(error):
            callback.set()
            raise RuntimeError("consumer callback")
        client = self.fake(result(60), LicenseboxError("seat_transferred"))
        with HeartbeatMonitor(client, "core", interval=0.01, on_stop=notify) as monitor:
            self.assertTrue(monitor.stopped.wait(0.5))
            self.assertEqual(monitor.error.code, "seat_transferred")
            self.assertTrue(callback.wait(0.5))

    def test_consumer_cancel_and_stop_cleanup(self):
        cancel = threading.Event()
        client = self.fake(result(60), lambda: result(60))
        monitor = HeartbeatMonitor(client, "core", cancel=cancel)
        cancel.set()
        self.assertTrue(monitor.stopped.wait(0.5))
        self.assertEqual(monitor.error.code, "cancelled")
        monitor.close()
        monitor.stop()
        self.assertEqual(client.heartbeat.call_count, 1)
        self.assertFalse(monitor._worker.is_alive())
        self.assertFalse(monitor._watchdog.is_alive())

    def test_initial_refusal_never_starts_monitor(self):
        client = Mock()
        client.heartbeat.side_effect = LicenseboxError("not_signed_in")
        before = set(threading.enumerate())
        with self.assertRaises(LicenseboxError):
            HeartbeatMonitor(client, "core")
        self.assertEqual(set(threading.enumerate()), before)

    def test_faster_interval_only_and_invalid_inputs(self):
        client = self.fake(result(60), lambda: result(60))
        for interval in (0, -1, True, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                HeartbeatMonitor(client, "core", interval=interval)
        with HeartbeatMonitor(client, "core", interval=1000) as monitor:
            time.sleep(0.03)
            self.assertEqual(client.heartbeat.call_count, 1)

    def test_returned_heartbeat_cannot_mutate_cached_authorization(self):
        def enc(value):
            return base64.urlsafe_b64encode(value).decode().rstrip("=")
        install = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        signing = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        now = time.time()
        lease = {"v":2,"kid":"test","product":"demo","machine":enc(install.public_key().public_bytes_raw()),
                 "binding":"m1:linux-dmi:"+"1"*64,"modules":["core"],"issued":datetime.fromtimestamp(now,timezone.utc).isoformat(),
                 "expires":datetime.fromtimestamp(now+60,timezone.utc).isoformat()}
        payload = json.dumps(lease).encode()
        token = enc(payload)+"."+enc(signing.sign(b"licensebox lease v2\n"+payload))
        with tempfile.TemporaryDirectory() as directory:
            Path(directory,"install.key").write_text(enc(install.private_bytes_raw()))
            Path(directory,"lease").write_text(token)
            client = Client("demo",{"test":enc(signing.public_key().public_bytes_raw())},directory=directory,
                            clock=lambda:now,machine_binding=lambda:lease["binding"])
            client._post = Mock(return_value={"lease":token})
            response = client.heartbeat("core")
            response["lease"]["modules"].append("export")
            response["lease"]["expires"] = "2099-01-01T00:00:00Z"
            with self.assertRaises(LicenseboxError) as caught:
                client.require("export")
            self.assertEqual(caught.exception.code,"module_denied")
            self.assertEqual(client.lease()["expires"],lease["expires"])

    def test_watchdog_does_not_hold_guard_while_client_clock_blocks(self):
        release, entered = threading.Event(), threading.Event()
        client = self.fake(result(), lambda: result(60))
        calls = 0
        def observed():
            nonlocal calls
            calls += 1
            if calls > 1:
                entered.set()
                release.wait(2)
            return time.time()
        client._now = observed
        monitor = HeartbeatMonitor(client,"core",interval=0.01)
        try:
            self.assertTrue(entered.wait(0.5))
            self.assertTrue(monitor.stopped.wait(0.6))
            self.assertEqual(monitor.error.code,"expired")
        finally:
            release.set()
            monitor.close()
