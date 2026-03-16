# Test Organization

This document describes the test structure for the rtlp-lib crate.

---

## Test Files

### 1. Unit Tests (`src/lib.rs`)

**Purpose:** Test internal implementation details not exposed in the public API.

**Location:** `#[cfg(test)] mod tests` inside `src/lib.rs`

**Test count: 56**

Categories:
- `TlpHeader` bitfield parsing (all-zeros, all-ones, bit-position verification)
- TLP type decoding — every supported (fmt, type) pair, including all 12 message routing sub-types and TLP prefix variants
- Unsupported / invalid combination error paths
- Invalid format values (all three reserved Fmt values: 0b101, 0b110, 0b111)
- DMWr (Deferrable Memory Write) header decode
- Atomic operand parsing via `new_atomic_req()`
- Completion lower-address field decode
- Message DW3/DW4 upper-bit preservation
- `TlpMode::Flit` stub — returns `NotImplemented`
- `TlpError::NotImplemented` distinctness
- `TlpMode` derive traits (Debug, Clone, Copy, PartialEq)
- `is_non_posted()` exhaustive coverage — all 21 `TlpType` variants
- `packet_mode_returns_correct_mode` — `TlpPacket::mode()` returns `NonFlit`/`Flit` correctly
- `tlp_packet_debug` / `tlp_packet_debug_flit` / `tlp_packet_header_debug` — `Debug` formatting for both packet types

**Why separate:** These tests use `TlpHeader` which is an internal implementation detail, not part of the public API.

---

### 2. Non-Flit Integration Tests (`tests/non_flit_tests.rs`)

**Purpose:** Functional behavior of the library through the public API using `TlpMode::NonFlit` (PCIe 1.0–5.0).

**Test count: 25**

Tests:
- `test_tlp_packet` — structural split test (note: Config Read with extra bytes is intentional)
- `test_complreq_trait` — completion request trait fields
- `test_configreq_trait` — configuration request trait fields
- `is_memreq_tag_works` — tag extraction (3DW and 4DW)
- `is_memreq_3dw_address_works` — 32-bit address parsing
- `is_memreq_4dw_address_works` — 64-bit address parsing
- `is_tlppacket_creates` — `TlpPacketHeader` construction
- `test_tlp_packet_invalid_type` — error propagation
- `atomic_fetchadd_3dw_32_parses_operands` — FetchAdd W32 operand
- `atomic_swap_4dw_64_parses_operands` — Swap W64 operand
- `atomic_cas_3dw_32_parses_operands` — CAS W32 two operands
- `atomic_fetchadd_rejects_invalid_operand_length` — bad operand size
- `dmwr32_decode_via_tlppacket` — DMWr 3DW decode
- `dmwr64_decode_via_tlppacket` — DMWr 4DW decode
- `dmwr_rejects_nodata_formats` — DMWr negative test
- `dmwr_is_non_posted` — non-posted predicate
- `msg_req_decode_route_to_rc_3dw_no_data` — Message TLP decode (was previously broken)
- `msg_req_data_decode_route_to_rc_3dw_with_data` — MsgReqData decode
- `msg_req_all_six_routing_subtypes_decode` — all 6 PCIe message routing codes
- `msg_req_data_all_six_routing_subtypes_decode` — all 6 routing codes with data
- `msg_req_end_to_end_path_with_new_msg_req` — full packet → field extraction
- `local_tlp_prefix_decode_type4_zero` — TLP Prefix decode (was previously broken)
- `end_to_end_tlp_prefix_decode_type4_one` — EndToEndTlpPrefix decode
- `tlp_prefix_local_and_end_to_end_distinguished_by_bit4` — Type[4] discrimination
- `prefix_types_are_not_non_posted` — Prefix is_non_posted() = false

**Why separate:** These verify end-to-end non-flit functionality that users rely on.  
All calls pass `TlpMode::NonFlit` explicitly.

---

### 3. API Contract Tests (`tests/api_tests.rs`)

**Purpose:** Ensure the public API remains stable and catch breaking changes.  
Mode-agnostic — tests API surface only, not behavior.

**Test count: 77**

Categories:
- `TlpError` enum — all variants including `NotImplemented`, `MissingMandatoryOhc`, Display, PartialEq, `std::error::Error`
- `TlpMode` enum — NonFlit and Flit variants, Copy/Clone/Debug/PartialEq
- `TlpMode::Flit` — now implemented for `TlpPacket::new()`; `TlpPacketHeader::new()` still returns `NotImplemented`
- `TlpFmt` enum — all variants, `TryFrom<u32>` valid and invalid values
- `TlpType` enum — all 21 variants, Debug, PartialEq
- `TlpPacket` — constructor, `tlp_type()`, `tlp_format()`, `data()`, `mode()`
- `TlpPacketHeader` — constructor, `tlp_type()`
- `MemRequest` trait — 3DW and 4DW struct accessibility and method types
- `ConfigurationRequest` trait — struct and method types
- `CompletionRequest` trait — struct and method types
- `MessageRequest` trait — struct and method types
- `AtomicOp` / `AtomicWidth` — enum variants, Debug, PartialEq
- Factory functions — `new_mem_req`, `new_conf_req`, `new_cmpl_req`, `new_msg_req`, `new_atomic_req`
- API stability compilation test — all public types and functions (uses concrete `vec![]` calls for `impl Into<Vec<u8>>` factory fns)
- **`mode()` tests** — `tlp_packet_mode_returns_correct_mode`, `tlp_packet_mode_consistent_with_flit_type`
- **Backward compat tests** (`#[allow(deprecated)]`) — one test per deprecated `get_*` alias verifying it delegates correctly: `get_tlp_type`, `get_tlp_format`, `get_flit_type`, `get_header`, `get_data`
- **Debug trait tests** — `tlp_packet_implements_debug`, `tlp_packet_implements_debug_flit`, `tlp_packet_header_implements_debug`
- Edge cases — minimum size, empty data, payload preservation

**Why separate:** These serve as a living contract specification. A failure indicates a breaking API change.

---

### 4. Flit Mode Tests (`tests/flit_mode_tests.rs`)

**Purpose:** Test plan and byte-vector constants for PCIe 6.x flit mode TLP parsing.

**Test count: 45 total (45 passing, 0 `#[ignore]`)**

#### Tier 0 — Regression guards (4 tests)

| Test | What it checks |
|---|---|
| `flit_packet_new_succeeds_for_valid_flit` | `TlpMode::Flit` decodes MRd32 correctly |
| `flit_header_new_returns_not_implemented` | `TlpPacketHeader::new(Flit)` → `NotImplemented` |
| `flit_all_fm_vectors_parse_to_expected_type` | **Parser-driven**: every FM_* constant decodes to the expected `FlitTlpType` (catches spec errors in byte vectors) |
| `flit_all_fm_vectors_parse_with_correct_ohc` | **Parser-driven**: every FM_* OHC bitmap decodes correctly |

#### Tier 1 — DW0 field extraction ✅ (8 tests — implemented)
Implemented: `FlitDW0::from_dw0()` in `src/lib.rs`

#### Tier 2 — Per-vector header + size validation ✅ (15 tests — implemented)
Implemented: `FlitTlpType` enum + `base_header_dw()` + `total_bytes()` + `has_data_payload()` in `src/lib.rs`

Includes `flit_t2_total_bytes_length_zero_encodes_1024dw` — verifies PCIe spec rule that `Length=0` encodes 1024 DW.

#### Tier 3 — OHC field parsing and mandatory-OHC validation ✅ (6 tests — implemented)
Implemented: `FlitOhcA::from_bytes()` + `FlitDW0::validate_mandatory_ohc()` + `TlpError::MissingMandatoryOhc`

#### Tier 4 — Packed stream walking ✅ (3 tests — implemented)
Implemented: `FlitStreamWalker` iterator in `src/lib.rs`

#### Tier 5 — End-to-end `TlpMode::Flit` pipeline ✅ (10 tests — implemented)
Implemented: `TlpPacket::new_flit()` + `flit_type()`

Includes atomic operand-value verification for `FM_FETCHADD32` (operand=0x01000000) and `FM_CAS32` (compare=0x11111111, swap=0x22222222).

**FM_* byte vector constants (all defined in this file):**

| Constant | Bytes | Description |
|---|---|---|
| `FM_NOP` | 4 | Flit NOP (type 0x00) |
| `FM_MRD32_MIN` | 12 | MRd32, minimal, no OHC |
| `FM_MRD32_A1_PASID` | 16 | MRd32 + OHC-A1 (PASID=0x12345) |
| `FM_MWR32_MIN` | 16 | MWr32, minimal, no OHC |
| `FM_MWR32_PARTIAL_A1` | 20 | MWr32 + OHC-A1 (partial BE fdwbe=0x3) |
| `FM_IOWR_A2` | 20 | IOWr + mandatory OHC-A2 (fdwbe=0xF) |
| `FM_CFGWR0_A3` | 20 | CfgWr0 + mandatory OHC-A3 (fdwbe=0xF) |
| `FM_UIOMRD64_MIN` | 16 | UIOMRd 4DW header, no OHC |
| `FM_UIOMWR64_MIN` | 24 | UIOMWr 4DW header + 2DW payload |
| `FM_MSG_TO_RC` | 12 | Message routed to RC, no data |
| `FM_MSGD_TO_RC` | 16 | Message with data routed to RC |
| `FM_FETCHADD32` | 16 | FetchAdd 32-bit atomic, operand=0x01000000 |
| `FM_CAS32` | 20 | CAS 32-bit atomic, compare=0x11111111 swap=0x22222222 |
| `FM_DMWR32` | 16 | DMWr 32-bit |
| `FM_STREAM_FRAGMENT_0` | 48 | 4 back-to-back TLPs |
| `FM_LOCAL_PREFIX_ONLY` | 4 | Local TLP Prefix token |

For byte-level examples of each vector see `docs/tlp_reference.md`.

---

### 5. Documentation Tests

**Purpose:** Ensure examples in doc comments compile and run correctly.

**Test count: 9**

Tests embedded in `src/lib.rs` doc comments:
- `TlpPacket` usage example
- `TlpPacket::mode()` usage example (includes `_ => {}` wildcard for `#[non_exhaustive]`)
- `TlpType::is_posted()` usage example
- `new_mem_req` usage example
- `new_conf_req` usage example (uses `data()` directly — no `.to_vec()`)
- `new_cmpl_req` usage example
- `new_msg_req` usage example
- `new_atomic_req` usage example
- `FlitStreamWalker` usage example

---

## Test Summary

| Test Type | Location | Passes | Ignored | Purpose |
|---|---|---|---|---|
| Unit Tests | `src/lib.rs` | 56 | 0 | Internal implementation |
| Non-Flit Integration | `tests/non_flit_tests.rs` | 25 | 0 | PCIe 1–5 functional behavior |
| API Contract | `tests/api_tests.rs` | 77 | 0 | Public API stability |
| Flit Mode | `tests/flit_mode_tests.rs` | 45 | 0 | PCIe 6.x — all tiers implemented |
| Doc Tests | `src/lib.rs` | 9 | 0 | Documentation examples |
| **Total** | | **212** | **0** | |

> All flit mode tiers (0–5) are implemented. Zero `#[ignore]` tests remain.

---

## Running Tests

```bash
# Run all tests (non-ignored)
cargo test

# Run only non-flit integration tests
cargo test --test non_flit_tests

# Run only flit mode tests
cargo test --test flit_mode_tests

# Run only API contract tests
cargo test --test api_tests

# Run unit tests only
cargo test --lib

# Run doc tests only
cargo test --doc

# Run with output visible
cargo test -- --nocapture
```

---

## Benefits of This Structure

1. **Breaking Change Detection** — `api_tests.rs` fails if the public interface changes
2. **Mode Separation** — non-flit and flit tests are in separate files with explicit scoping
3. **Incremental Plan** — flit mode tiers document implementation history
4. **Parser-Driven Vector Tests** — `flit_all_fm_vectors_parse_to_expected_type` catches spec errors in FM_* constants
5. **Always Green** — all 212 tests pass at every commit (0 ignored)

---

## Flit Mode Implementation Status (v0.5.0)

All tiers complete — no `#[ignore]` tests remain:

1. ~~**Tier 1** — `FlitDW0` struct + `from_dw0()`~~ ✅ Done (v0.4.1)
2. ~~**Tier 2** — `FlitTlpType` enum + `base_header_dw()` + `total_bytes()` + `has_data_payload()`~~ ✅ Done (v0.5.0)
3. ~~**Tier 3** — `FlitOhcA` + `validate_mandatory_ohc()` + `TlpError::MissingMandatoryOhc`~~ ✅ Done (v0.4.1)
4. ~~**Tier 4** — `FlitStreamWalker` iterator~~ ✅ Done (v0.5.0)
5. ~~**Tier 5** — `TlpPacket::new_flit()` + `flit_type()`~~ ✅ Done (v0.5.0)

See `docs/tlp_reference.md` for byte-level TLP examples and the complete test inventory for both framing modes.


