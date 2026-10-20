import os
import tempfile
import unittest
from licensebox import Client, LicenseboxError, derive_binding, native_binding
from licensebox.client import _Key

TEST_KEY = _Key(bytes(64)).public()  # synthetic trusted key

class ClientTests(unittest.TestCase):
    def test_missing_identity_is_rejected_before_contact(self):
        with tempfile.TemporaryDirectory() as folder:
            client=Client("demo",{"test":TEST_KEY},directory=folder,
                          server="http://127.0.0.1:1",machine_binding=lambda:"")
            with self.assertRaises(LicenseboxError) as caught:client.require("core")
            self.assertEqual(caught.exception.code,"identity_unavailable")
    def test_native_identifier_validation(self):
        for value in ("", "hostname", "0"*32, "f"*32):
            with self.assertRaises(LicenseboxError):derive_binding("demo","linux-machine-id",value)
    @unittest.skipUnless(os.environ.get("LICENSEBOX_TEST_NATIVE")=="1","opt-in host check")
    def test_native_stability_and_scope(self):
        first=native_binding("licensebox-test-a")
        self.assertTrue(first==native_binding("licensebox-test-a"),"native identity changed")
        self.assertTrue(first!=native_binding("licensebox-test-b"),"native identity is not product-scoped")
