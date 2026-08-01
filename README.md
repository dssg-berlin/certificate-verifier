# Auto Volunteer Certificate Verifier

This folder contains a Streamlit app for verifying offline certificate credentials using did:key and Ed25519 signatures.

## Run locally

1. Install dependencies:
   ```bash
   python3 -m pip install -r requirements.txt
   ```
2. Create a Streamlit secrets file for local runs (optional but recommended if you want to restrict trusted issuers):
   ```bash
   mkdir -p .streamlit
   cat > .streamlit/secrets.toml <<'EOF'
   [general]
   VERIFIER_ALLOWED_ISSUERS = "did:key:YOUR_ISSUER_DID_1, did:key:YOUR_ISSUER_DID_2"
   EOF
   ```
   Streamlit will also read the same value from `/home/codespace/.streamlit/secrets.toml` or from the environment variable `VERIFIER_ALLOWED_ISSUERS`.
3. Start the app:
   ```bash
   streamlit run app.py
   ```

## What it verifies

The app accepts a JSON credential bundle containing:
- `certificate`
- `issuer_did`
- `signature_hex`

It verifies the signature entirely offline using the public key derived from the issuer's did:key identifier.
