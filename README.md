# lockness coding challenge

This repository contains the prerequisite solution for the Lockness mentorship coding task.

## Solution summary
- Implemented the specified Encrypt/Decrypt scheme using the `generic-ec` crate.
- Uses SHA-256, compressed point encoding, Expand-by-repeat and XOR as described.
- Includes full test vectors for Ed25519, secp256k1 and secp384r1.
- Includes a runnable end-to-end transaction example.

## Execution:
<img width="590" height="1000" alt="image" src="https://github.com/user-attachments/assets/f4d5444c-703c-4d7c-9a12-9fecacf80d32" />


## How to run
From the crate directory:

```bash
cd lockness_crypto
cargo test
```

To run the end-to-end demo:

```bash
cargo run --example transaction
```

## Evidence:
<img width="941" height="422" alt="image" src="https://github.com/user-attachments/assets/5b9a6104-944f-4f99-bad0-15186029bde8" />


The demo prints a real keypair, ciphertext and the recovered plaintext to show a full round trip.

## Implementation location
The code is in the `lockness_crypto` crate:

- `src/lib.rs`: Encrypt/Decrypt implementation and tests
- `examples/transaction.rs`: demo transaction program
