# Pinned Yjs 13.6.33 editor correction

Yjs 13.6.33 is MIT licensed (upstream `node_modules/yjs/LICENSE`); its original package remains installed by `npm ci`. `scripts/patch-yjs.mjs` transforms only `src/types/YText.js`, `dist/yjs.mjs` and `dist/yjs.cjs`, with exact input/output SHA-256 checks. No other Yjs source, package files or dependencies are changed.

| File | pristine SHA-256 | corrected SHA-256 |
| --- | --- | --- |
| src/types/YText.js | `9bb124a3bc5ae724ce4a77c705643da29c2d414edb153939df99804db842e07e` | `3c668b2fb276e989b45df221b1b46e74dca8491fc15202982398a83e5f94525a` |
| dist/yjs.mjs | `a514c183100fc375eb46df9cb58acaf0deabbf414d2508841336179b1cb45107` | `600b936c54f1762149df08f39eb0b9c278a2fe62d5da682517c4b51282a36e02` |
| dist/yjs.cjs | `8891769da278d678988510fbe27844082fb1674132e847633dd8d114497c61ce` | `ae5d5a05692f11658a99997ba739e9a043d141eb7c7ce7e3d2277a5c25c03605` |

Inside `YTextEvent.delta`, remove only the two branches that delete a `ContentFormat` item while deriving the delta. In `YText._callObserver`, remove scheduling of automatic remote formatting cleanup. Ordinary local format/delete/applyDelta and explicit cleanup remain untouched. These observations must not discard canonical marks or emit local delete-only updates. The editor's node and browser regressions check fragment/delta behavior; this is not an incoming-core or yrs acceptance gate. Preparation is explicit after `npm ci --ignore-scripts` and before each real editor entry path; no postinstall hook is relied upon.
