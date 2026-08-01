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


if __name__ == "__main__":
    unittest.main()
