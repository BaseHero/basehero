# Model library

- Keep this library independent of app shells, hosting adapters and runtime code execution.
- Responses, tools and usage observations are untrusted inputs. Do not add network calls that bypass provider authentication/encryption.
- Never promote caller/body usage into a trusted settlement. Keep uncertainty explicit and separate Stop from remote billing.
- Do not log provider error text or decrypted content. Work-kind attribution belongs only in authorized encrypted activity, not billing projections.
- Affected checks from the product root: `cargo test --locked --offline -p basehero-models --test response` or `cargo test --locked --offline -p basehero-models --test accounting`.
- Feature checks: `cargo test --locked --offline -p basehero-models --features near-route` and `cargo clippy --locked --offline -p basehero-models --all-targets --features near-route -- -D warnings`; the same with `--features tinfoil-route`.
- Full check from the product root: `bash scripts/check.sh`. Format and lint the model crate with `cargo fmt --all --check` and `cargo clippy --locked --offline -p basehero-models --all-targets -- -D warnings`.
- All current tests are offline. Live provider calls require explicit operational authorization and accounting outside the test suite.
