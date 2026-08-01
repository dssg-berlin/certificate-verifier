import base64
import importlib.util
import pathlib
import sys
import types
import unittest

import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class Dummy:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def _load_verifier_module():
    streamlit_stub = types.ModuleType("streamlit")
    streamlit_stub.sidebar = Dummy()
    streamlit_stub.set_page_config = lambda *args, **kwargs: None
    streamlit_stub.title = lambda *args, **kwargs: None
    streamlit_stub.caption = lambda *args, **kwargs: None
    streamlit_stub.header = lambda *args, **kwargs: None
    streamlit_stub.write = lambda *args, **kwargs: None
    streamlit_stub.markdown = lambda *args, **kwargs: None
    streamlit_stub.info = lambda *args, **kwargs: None
    streamlit_stub.success = lambda *args, **kwargs: None
    streamlit_stub.error = lambda *args, **kwargs: None
    streamlit_stub.warning = lambda *args, **kwargs: None
    streamlit_stub.json = lambda *args, **kwargs: None
    streamlit_stub.expander = lambda *args, **kwargs: Dummy()
    streamlit_stub.file_uploader = lambda *args, **kwargs: None
    streamlit_stub.query_params = {}
    streamlit_stub.secrets = {}

    sys.modules["streamlit"] = streamlit_stub

    module_path = pathlib.Path(__file__).resolve().parents[1] / "app.py"
    spec = importlib.util.spec_from_file_location("verifier_app", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DidKeyVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.verifier = _load_verifier_module()

    def test_resolve_public_key_from_did_supports_multibase_prefix(self):
        did = "did:key:z6MkjzdWcToRce1Ewz6VyYT6rYAW8pAVJYFKt3Z2n8zP5uzP"
        public_key = self.verifier.resolve_public_key_from_did(did)
        self.assertIsNotNone(public_key)

    def test_verify_payload_accepts_generator_style_bundle(self):
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        did_key_bytes = b"\xed\x01" + public_bytes
        did = "did:key:z" + base58.b58encode(did_key_bytes).decode("ascii")

        certificate_data = {"recipient": "Ada Lovelace", "certificateType": "volunteer"}
        payload = self.verifier.canonicalize_payload(certificate_data)
        signature = private_key.sign(payload)

        bundle = {
            "certificate": certificate_data,
            "issuer_did": did,
            "signature_hex": signature.hex(),
        }

        self.verifier.verify_payload(bundle)

    def test_load_allowed_issuers_reads_streamlit_secrets(self):
        self.verifier.st.secrets = {"VERIFIER_ALLOWED_ISSUERS": "did:key:one, did:key:two"}

        issuers = self.verifier.load_allowed_issuers()

        self.assertEqual(issuers, {"did:key:one", "did:key:two"})

    def test_load_allowed_issuers_falls_back_when_streamlit_secrets_missing(self):
        class MissingSecrets:
            def __contains__(self, key):
                raise RuntimeError("secrets not configured")

        self.verifier.st.secrets = MissingSecrets()

        issuers = self.verifier.load_allowed_issuers()

        self.assertIsNone(issuers)

    def test_verify_payload_skips_details_for_untrusted_issuer(self):
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        did_key_bytes = b"\xed\x01" + public_bytes
        did = "did:key:z" + base58.b58encode(did_key_bytes).decode("ascii")

        certificate_data = {"recipient": "Ada Lovelace", "certificateType": "volunteer"}
        payload = self.verifier.canonicalize_payload(certificate_data)
        signature = private_key.sign(payload)

        calls = []

        def warning(message, *args, **kwargs):
            calls.append(("warning", message))

        def expander(*args, **kwargs):
            calls.append(("expander", args[0]))
            return Dummy()

        self.verifier.st.warning = warning
        self.verifier.st.expander = expander
        self.verifier.st.secrets = {"VERIFIER_ALLOWED_ISSUERS": "did:key:another"}

        bundle = {
            "certificate": certificate_data,
            "issuer_did": did,
            "signature_hex": signature.hex(),
        }

        self.verifier.verify_payload(bundle)

        self.assertEqual(calls[0][0], "warning")
        self.assertEqual(calls[0][1], "⚠️ The signature is valid, but the issuer is not in the configured allowlist.")
        self.assertFalse(any(call[0] == "expander" for call in calls))


if __name__ == "__main__":
    unittest.main()
