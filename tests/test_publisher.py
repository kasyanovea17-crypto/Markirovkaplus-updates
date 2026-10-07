import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from urllib.request import Request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

spec = importlib.util.spec_from_file_location("publisher", Path(__file__).resolve().parents[1] / "tools/publish_prepared.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.public = base64.b64encode(self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        self.data = {"version": "1.0.62", "installerUrl": publisher.INSTALLER, "sha256": "a" * 64, "size": 2000000, "notes": ["Проверка"]}
        raw = json.dumps(self.data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        self.data.update(signature=base64.urlsafe_b64encode(self.key.sign(raw)).rstrip(b"=").decode(), signatureAlg="ed25519")

    def test_real_signature(self):
        publisher.verify_manifest(self.data, "1.0.62", self.public)

    def test_tampered_manifest(self):
        data = copy.deepcopy(self.data)
        data["size"] += 1
        with self.assertRaises(Exception):
            publisher.verify_manifest(data, "1.0.62", self.public)

    def test_untrusted_key(self):
        with self.assertRaises(Exception):
            publisher.verify_manifest(self.data, "1.0.62")

    def test_version_mismatch(self):
        with self.assertRaises(ValueError):
            publisher.verify_manifest(self.data, "1.0.63", self.public)

    def test_external_installer_forbidden(self):
        data = copy.deepcopy(self.data)
        data["installerUrl"] = "https://example.com/installer.exe"
        with self.assertRaises(ValueError):
            publisher.verify_manifest(data, "1.0.62", self.public)

    def test_versions_numeric(self):
        self.assertLess(publisher.version("v1.0.58"), publisher.version("1.0.62"))
        self.assertGreater(publisher.version("v1.0.100"), publisher.version("1.0.62"))

    def test_invalid_version(self):
        with self.assertRaises(ValueError):
            publisher.version("licenses-v2")

    def test_published_release_not_overwritten(self):
        release = {"tag_name": "v1.0.62", "body": "Source commit: good", "draft": False}
        with self.assertRaises(ValueError):
            publisher.check_release(release, "v1.0.62", "Source commit: good")

    def test_unrelated_draft_not_overwritten(self):
        release = {"tag_name": "v1.0.62", "body": "Source commit: other", "draft": True}
        with self.assertRaises(ValueError):
            publisher.check_release(release, "v1.0.62", "Source commit: good")

    def test_matching_draft(self):
        publisher.check_release({"tag_name": "v1.0.62", "body": "Source commit: good", "draft": True}, "v1.0.62", "Source commit: good")

    def test_auth_is_stripped_on_cross_host_redirect(self):
        request = Request("https://api.github.com/a", headers={"Authorization": "Bearer test-only"})
        result = publisher.StripCrossHostAuth().redirect_request(request, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/file")
        self.assertIsNone(result.get_header("Authorization"))


if __name__ == "__main__":
    unittest.main()
