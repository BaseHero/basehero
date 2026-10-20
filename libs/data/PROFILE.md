# BaseHero JSON Schema profile

Version: `bh-schema-profile/1`. Record schemas use JSON Schema Draft 2020-12. An explicit `$schema`, when present, must be `https://json-schema.org/draft/2020-12/schema`. Unsupported or misspelled schema keywords fail rather than being silently ignored. Boolean schemas are not supported.

## Supported keywords

- Identity and reuse: `$schema`, `$id` (only at a resource root), `$defs`, `$ref`.
- Data annotations: `$comment`, `title`, `description`, `examples`, `default`, `deprecated`, `readOnly`, `writeOnly`, `format`.
- Values: `type`, `enum`, `const`.
- Objects: `properties`, `required`, `additionalProperties` (boolean only), `minProperties`, `maxProperties`.
- Arrays: `items`, `prefixItems`, `minItems`, `maxItems`, `uniqueItems`.
- Strings: `minLength`, `maxLength`.
- Numbers: `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf` (positive integer only).
- Compositions: `anyOf`, `oneOf`, `allOf`.

Keywords inside `properties` and `$defs` **names** or inside `enum`, `const`, `default`, and `examples` **values** are data, not schema keywords. A schema fragment cannot declare `$id`. Only `#/$defs/<name>` (one JSON Pointer segment, with `~0` and `~1` escaping as needed), compiler-generated `bh:defs:<revision-hex>#/$defs/<name>` for isolated inheritance, and pinned `bh:value:<type-hex>@<rev-hex>` resource references are supported. Reference fragments containing `%` (including percent-encoded names, separators or escapes) are outside this bounded profile and rejected before graph analysis or validator construction, including in supplied pinned and compiler-isolated resources. Use literal names and JSON Pointer `~0`/`~1` escapes instead. This restriction applies to `$ref` schema values, not property/definition names or annotation data. Pinned resources must be supplied to the compiler; no network or file retrieval is performed.

## Limits

The canonical serialized schema is at most 32,768 bytes; JSON nesting depth is at most 32 and the schema contains at most 512 subschemas. Each `anyOf`, `oneOf`, or `allOf` has at most 16 branches. An `enum` has at most 256 entries. A schema with `type: string` requires `maxLength` ≤ 16,384 or an `enum`/`const`; any `maxLength` must be ≤ 16,384. A schema with `type: array` requires `maxItems` ≤ 1,024; any `maxItems` must be ≤ 1,024. The same string and array limits apply when `type` is a union that includes them.

Compilation has one shared ceiling of **1,048,576 bytes (1 MiB)**, applied
independently to each of these quantities:

1. The cumulative compact-JSON serialized `CompiledType` inputs fetched for
   distinct exact dependency pins (record base and value imports). This includes
   annotations, field documentation and all other metadata. A repeated exact pin
   is fetched and charged once, but identity and required kind are still checked
   in each context. Distinct dependencies each cost their full input bytes even
   when they contain identical transitive resources.
2. The effective schema's compact-JSON bytes plus the sum of each distinct
   resource document's compact-JSON bytes and its JSON-encoded URI key (including
   quotes and escapes). Identical URI/document pairs are counted once; a URI
   with conflicting content is rejected. Collection framing is excluded from
   this quantity; it is included in the final representation below. This bound
   also applies to callers supplying resources directly to the validator.
3. The entire final compact-JSON serialized `CompiledType`, using the registry's
   encoding, including resource collection framing, lineage, fields, operations
   and documentation.

Equality with the ceiling is allowed. These compilation checks count UTF-8
bytes and JSON escaping, including annotation values; they do not use the
graph-node cost as a substitute for bytes. Streaming counters stop at the first
over-budget input without building the encoded output. Dependency inputs are
charged before merging, and distinct resources before copying into the closure.
The final representation is checked before validator construction or registry
persistence. An oversized definition is rejected, not partially persisted.
Imports and documentation are never silently discarded to fit. These are
compile/validator-construction checks, not additional walks on ordinary record
edits using an existing validator. They bound serialized inputs and outputs,
not allocator overhead, validator memory or elapsed time. The per-document,
57,344-byte raw-definition, graph and record-work limits remain separate.

Before validator construction, the complete supplied reference graph is resolved offline. Cycles and graph paths longer than 128 edges are rejected (a root starts at depth zero). Each subschema or reference traversal is one edge, including across resource documents; JSON container nesting is a separate per-document limit. Memoised subtrees retain their maximum descendant edge height, so revisiting one through a deeper prefix cannot bypass the limit. Resource order, branch order and consistent URI renaming do not change graph-depth admission. Expanded schema cost is at most 8,192: each schema node costs one, each composition/property/item edge adds its child's cost, and each reference adds its target's cost **each time it is used**. Enum/const add their canonical literal byte length. Each supplied resource root and each root `$defs` entry also contributes once, even if unused. Source-node memoisation bounds the computation itself; additions saturate rather than wrap.

Record validation additionally requires `expanded cost × shape cost ≤ 16,777,216`. Shape cost counts canonical scalar bytes plus one, object delimiters and worst-case escaped property names, and array delimiters/items; each array also adds its byte cost times its length, conservatively allowing pairwise `uniqueItems` comparisons. Nested arrays contribute independently. These deterministic limits, not elapsed time, decide acceptance. Record size/depth checks precede this computation. Ordered Note extension validation replaces the adapter-owned title with the fixed valid empty title before all size/work/schema checks; the real title remains unchanged and is validated by the Note adapter.

Record values have their own size and depth limits. JSON integers must be within ±9,007,199,254,740,991 (the interoperable exact range). Integral floating-point values (for example `1.0`) can satisfy `type: integer` but integral numbers outside that safe range are rejected before schema validation. Non-integral numbers must be finite; unrepresentable numbers are rejected during JSON parsing. `multipleOf` is a positive integer in the safe range.

## Annotations

`$comment`, `title`, `description`, `examples`, `default`, `deprecated`, `readOnly`, `writeOnly`, and `format` do not validate or alter a record. In particular, `format` is not asserted and `default` is never inserted. The validator returns a rejection with the first failing instance location; it never mutates the input.
