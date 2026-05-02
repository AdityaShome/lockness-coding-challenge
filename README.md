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

## Evidence (text output)
You can capture screenshots of the following command output as proof:

```text
$ cargo run --example transaction
curve: secp256k1
secret key (hex): 6f5dc3a36a3c8e6b80a885b136981edb4a25836990ef0d906bffbf0b74d120de
public key (hex): 033b6e7f1d1714132824443b075083d9187683b4218d1a55066b10db156567aa53
message (utf8): maintainer demo message
ciphertext (hex): 021c835fc26e901f57f3dada7e717f35b9d23f4890930147832f753531a9ab5c6465b591cc70d2a9cbc8ef018803eb343b7a4a401acd4b09
recovered (utf8): maintainer demo message
```

The demo prints a real keypair, ciphertext and the recovered plaintext to show a full round trip.

## Implementation location
The code is in the `lockness_crypto` crate:

- `src/lib.rs`: Encrypt/Decrypt implementation and tests
- `examples/transaction.rs`: demo transaction program
