# Auto Volunteer Certificate Verifier

This folder contains a Streamlit app for verifying offline certificate credentials using did:key and Ed25519 signatures.

## Run locally

1. Install dependencies:
   ```bash
   python3 -m pip install -r requirements.txt
   ```
2. Start the app:
   ```bash
   streamlit run app.py
   ```

## What it verifies

The app accepts a JSON credential bundle containing:
- `certificate`
- `issuer_did`
- `signature_hex`

It verifies the signature entirely offline using the public key derived from the issuer's did:key identifier.
