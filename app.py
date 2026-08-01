import base64
import json
import os
import urllib.parse

import base58
import streamlit as st
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


ED25519_PREFIX = b"\xed\x01"


SUPPORTED_BUNDLE_KEYS = {"certificate", "issuer_did", "signature_hex"}


st.set_page_config(page_title="Digital Credential Verifier", page_icon="🎓", layout="centered")

st.title("🎓 Digital Credential Verifier")
st.caption("Offline verification of open-source certificate credentials using did:key and Ed25519 signatures")

with st.sidebar:
    st.header("How verification works")
    st.write(
        "This verifier uses the issuer's did:key identity and an Ed25519 signature to validate the certificate entirely offline. "
        "No external servers or registries are contacted."
    )
    st.markdown("""
    1. Upload a JSON credential bundle.
    2. Extract the certificate data, issuer DID, and signature.
    3. Decode the public key from the DID.
    4. Re-serialize the certificate deterministically.
    5. Verify the signature locally with Ed25519.
    """)
    st.info("The verification process is fully local and does not depend on internet access.")


def resolve_public_key_from_did(issuer_did: str):
    if not issuer_did.startswith("did:key:"):
        raise ValueError("Unsupported DID format. Expected did:key:...")

    encoded_key = issuer_did.removeprefix("did:key:")
    if encoded_key.startswith("z"):
        encoded_key = encoded_key[1:]

    key_bytes = base58.b58decode(encoded_key)
    if len(key_bytes) <= len(ED25519_PREFIX):
        raise ValueError("Decoded DID key is too short")

    if key_bytes[: len(ED25519_PREFIX)] != ED25519_PREFIX:
        raise ValueError("Unsupported multicodec prefix; expected b'\\xed\\x01'")

    public_key_bytes = key_bytes[len(ED25519_PREFIX) :]
    if len(public_key_bytes) != 32:
        raise ValueError("Decoded public key is not 32 bytes long")

    return ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)


def canonicalize_payload(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_allowed_issuers():
    raw_value = ""

    try:
        if hasattr(st, "secrets") and "VERIFIER_ALLOWED_ISSUERS" in st.secrets:
            raw_value = str(st.secrets["VERIFIER_ALLOWED_ISSUERS"])
        else:
            raw_value = os.getenv("VERIFIER_ALLOWED_ISSUERS", "")
    except Exception:
        raw_value = os.getenv("VERIFIER_ALLOWED_ISSUERS", "")

    if not raw_value:
        return None
    return {value.strip() for value in raw_value.split(",") if value.strip()}


def extract_bundle(payload):
    if not isinstance(payload, dict):
        raise ValueError("The uploaded file must contain a JSON object.")

    if SUPPORTED_BUNDLE_KEYS.issubset(payload.keys()):
        return payload["certificate"], payload["issuer_did"], payload["signature_hex"]

    if "issuer_did" in payload and ("signature_hex" in payload or "signature" in payload) and len(payload) >= 2:
        signature_key = "signature_hex" if "signature_hex" in payload else "signature"
        certificate_data = {k: v for k, v in payload.items() if k not in {"issuer_did", signature_key}}
        if not certificate_data:
            raise ValueError("No certificate fields were found in the uploaded JSON.")
        return certificate_data, payload["issuer_did"], payload[signature_key]

    raise ValueError("Missing required fields: certificate, issuer_did, or signature_hex")


def verify_payload(payload):
    certificate_data, issuer_did, signature_hex = extract_bundle(payload)

    if not isinstance(certificate_data, dict):
        raise ValueError("The certificate field must be a JSON object.")

    signature_value = None
    if isinstance(payload.get("signature_hex"), str) and payload.get("signature_hex"):
        signature_value = bytes.fromhex(payload["signature_hex"])
    elif isinstance(payload.get("signature"), str) and payload.get("signature"):
        signature_value = base64.b64decode(payload["signature"])

    if signature_value is None:
        raise ValueError("A valid signature field was not found in the bundle.")

    public_key = resolve_public_key_from_did(issuer_did)
    serialized_data = canonicalize_payload(certificate_data)

    public_key.verify(signature_value, serialized_data)

    allowed_issuers = load_allowed_issuers()
    is_trusted_issuer = allowed_issuers is None or issuer_did in allowed_issuers

    if not is_trusted_issuer:
        st.warning("⚠️ The signature is valid, but the issuer is not in the configured allowlist.")
        return

    st.success("✅ Signature verified successfully.")
    st.info("This credential is authentic and was signed by a trusted issuer identified by the provided did:key.")

    with st.expander("Certificate details", expanded=True):
        st.json(certificate_data)

    with st.expander("Verification metadata", expanded=False):
        st.write({
            "issuer_did": issuer_did,
            "signature_hex": payload.get("signature_hex") or payload.get("signature"),
            "trusted_issuer": is_trusted_issuer,
            "allowed_issuers": sorted(allowed_issuers) if allowed_issuers is not None else None,
        })


uploaded_file = st.file_uploader(
    "Upload a certificate JSON file",
    type=["json"],
    help="Expected structure: {\"certificate\": {...}, \"issuer_did\": \"did:key:z...\", \"signature_hex\": \"...\"}",
)

query_params = st.query_params
encoded_bundle = query_params.get("bundle", "")

if encoded_bundle:
    try:
        decoded_bundle = base64.b64decode(urllib.parse.unquote(encoded_bundle)).decode("utf-8")
        payload = json.loads(decoded_bundle)
        verify_payload(payload)
    except (ValueError, TypeError, json.JSONDecodeError, InvalidSignature) as exc:
        st.error("❌ Verification failed")
        st.write(str(exc))
        st.warning("The bundle in the URL is invalid or the signature does not match the issuer's public key.")
elif uploaded_file is not None:
    try:
        raw_text = uploaded_file.read().decode("utf-8")
        payload = json.loads(raw_text)
        verify_payload(payload)
    except (ValueError, json.JSONDecodeError, TypeError, InvalidSignature) as exc:
        st.error("❌ Verification failed")
        st.write(str(exc))
        st.warning("The uploaded file is not a valid credential bundle or the signature does not match the issuer's public key.")
else:
    st.info("Please upload a JSON certificate bundle to begin verification, or open a link with ?bundle=...")
