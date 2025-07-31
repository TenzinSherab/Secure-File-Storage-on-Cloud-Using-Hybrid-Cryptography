# Secure Cloud File Storage (Hybrid Encryption + Blockchain Logging)

This project is a simple and secure desktop application for encrypting and decrypting files using ChaCha20-Poly1305 encryption and HKDF-derived keys. It also simulates cloud storage and keeps a blockchain-style ledger (`blockchain.json`) to verify file integrity after decryption.

---

## How It Works

This tool helps users:

- Encrypt any file securely
- Simulate uploading the encrypted file to the cloud
- Decrypt it later with integrity verification

It uses:

- ChaCha20-Poly1305: A modern, fast, authenticated encryption algorithm
- HKDF with SHA-256: To derive a strong symmetric key from a shared secret
- Blockchain-style logging: Every encrypted file's SHA-256 hash is stored in `blockchain.json` to later verify that decryption was successful and unmodified

---

## Simulated Cloud Storage

This project does not use real cloud services.

All "cloud uploads" are simulated by saving encrypted files into a local directory named:

