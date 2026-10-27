All product logic belongs in bh-core; the CLI and apps only call its API.
The server stores only ciphertext, never readable content or decryption keys.
Dependency versions live in the root manifests.
