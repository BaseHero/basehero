# Independent public archived vectors — not a matched proof

- `tdx_quote` and `tdx_quote_collateral.json`: dcap-qvl 0.7.0, upstream commit `94208e2753a854191759e493ca5892be482ad453`, `sample/tdx_quote` (SHA-256 `c42f9164325024bca2757bc8819b11879a0a369132ea4e2b7c85df4805ea72db`) and `sample/tdx_quote_collateral.json` (SHA-256 `b0a5f5fd620a8881b1eda45261fdf30dd930b49aff93231556645c81fcb4c0bc`); MIT licence in `DCAP-LICENSE`. Archived verification time 2025-07-01, **not** usable at current time.
- `tdx-lite-getquote.json`: dstack v0.6.0 commit `4699c48ea3a7e568dff4f8792421299f27d50758`, `dstack/verifier/fixtures/tdx-lite-getquote.json` (SHA-256 `fbb00086b21b6f03a4d1ba14391eb7c7008ad7cf3d60f4ab423a3a0ec1cc2c23`). Apache-2.0 (root licence at `../../../../third_party/dstack/LICENSE` from this directory). Used only to parse reference RTMR3 and independently test replay, **not** a QVL-verified quote.

These fixtures have no matched quote, collateral, event log, new verifier-issued nonce and BaseHero service keys. Tests must never treat their separate successes as a positive fresh hardware attestation or authorization.
