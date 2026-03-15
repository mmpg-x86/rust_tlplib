# Test Organization

This document describes the test structure for the rtlp-lib crate.

---

## Test Files

### 1. Unit Tests (`src/lib.rs`)

**Purpose:** Test internal implementation details not exposed in the public API.

**Location:** `#[cfg(test)] mod tests` inside `src/lib.rs`

**Test count: 48**

Categories:
- `TlpHeader` bitfield parsing (all-zeros, all-ones, bit-position verification)
- TLP type decoding — every supported (fmt, type) pair
- Unsupported / invalid combination error paths
- DMWr (Deferrable Memory Write) header decode
- Atomic operand parsing via `new_atomic_req()`
- Completion lower-address field decode
- Message DW3/DW4 upper-bit preservation
- `TlpMode::Flit` stub — returns `NotImplemented`
- `TlpError::NotImplemented` distinctness
- `TlpMode` derive traits (Debug, Clone, Copy, PartialEq)

**Why separate:** These tests use `TlpHeader` which is an internal implementation detail, not part of the public API.

---

### 2. Non-Flit Integration Tests (`tests/non_flit_tests.rs`)

**Purpose:** Functional behavior of the library through the public API using `TlpMode::NonFlit` (PCIe 1.0–5.0).

**Test count: 16**

Tests:
- `test_tlp_packet` — basic TLP packet parsing
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

**Why separate:** These verify end-to-end non-flit functionality that users rely on.  
All calls pass `TlpMode::NonFlit` explicitly.

---

### 3. API Contract Tests (`tests/api_tests.rs`)

**Purpose:** Ensure the public API remains stable and catch breaking changes.  
Mode-agnostic — tests API surface only, not behavior.

**Test count: 64**

Categories:
- `TlpError` enum — all variants including `NotImplemented`, Debug, PartialEq
- `TlpMode` enum — NonFlit and Flit variants, Copy/Clone/Debug/PartialEq
- `TlpMode::Flit` stub — returns `NotImplemented` for Packet and Header
- `TlpFmt` enum — all variants, `TryFrom<u32>` valid and invalid values
- `TlpType` enum — all 21 variants, Debug, PartialEq
- `TlpPacket` — constructor, getters, error conditions
- `TlpPacketHeader` — constructor, `get_tlp_type()`
- `MemRequest` trait — 3DW and 4DW struct accessibility and method types
- `ConfigurationRequest` trait — struct and method types
- `CompletionRequest` trait — struct and method types
- `MessageRequest` trait — struct and method types
- `AtomicOp` / `AtomicWidth` — enum variants, Debug, PartialEq
- Factory functions — `new_mem_req`, `new_conf_req`, `new_cmpl_req`, `new_msg_req`, `new_atomic_req`
- API stability compilation test — all public types and functions
- Edge cases — minimum size, empty data, payload preservation

**Why separate:** These serve as a living contract specification. A failure indicates a breaking API change.

---

### 4. Flit Mode Tests (`tests/flit_mode_tests.rs`)

**Purpose:** Test plan and byte-vector constants for PCIe 6.x flit mode TLP parsing.

**Test count: 40 total (32 passing, 8 `#[ignore]`)**

#### Tier 0 — Current stubs ✅ (5 tests — permanent regression guards)

| Test | What it checks |
|---|---|
| `flit_packet_new_returns_not_implemented` | `TlpMode::Flit` → `NotImplemented` |
| `flit_header_new_returns_not_implemented` | Same for `TlpPacketHeader` |
| `flit_byte_vectors_have_correct_sizes` | 16 FM_* constants have correct byte lengths |
| `flit_dw0_type_bytes_are_correct` | Byte 0 of each vector matches expected type code |
| `flit_dw0_ohc_bytes_are_correct` | Byte 1 OHC field matches expected flags |

#### Tier 1 — DW0 field extraction ✅ (8 tests — implemented)
Implemented: `FlitDW0::from_dw0()` in `src/lib.rs`

#### Tier 2 — Per-vector header + size validation ✅ (13 tests — implemented)
Implemented: `FlitTlpType` enum + `base_header_dw()` + `total_bytes()` in `src/lib.rs`

#### Tier 3 — OHC field parsing and mandatory-OHC validation ✅ (6 tests — implemented)
Implemented: `FlitOhcA::from_bytes()` + `FlitDW0::validate_mandatory_ohc()` + `TlpError::MissingMandatoryOhc`

#### Tier 4 — Packed stream walking `#[ignore]` (2 tests)
Unlock: `FlitStreamWalker` iterator in `src/lib.rs`

#### Tier 5 — End-to-end `TlpMode::Flit` pipeline `#[ignore]` (6 tests)
Unlock: `TlpPacket::new_flit()` fully wired

**FM_* byte vector constants (all defined in this file):**

| Constant | Bytes | Description |
|---|---|---|
| `FM_NOP` | 4 | Flit NOP (type 0x00) |
| `FM_MRD32_MIN` | 12 | MRd32, minimal, no OHC |
| `FM_MRD32_A1_PASID` | 16 | MRd32 + OHC-A1 (PASID) |
| `FM_MWR32_MIN` | 16 | MWr32, minimal, no OHC |
| `FM_MWR32_PARTIAL_A1` | 20 | MWr32 + OHC-A1 (partial BE) |
| `FM_IOWR_A2` | 20 | IOWr + mandatory OHC-A2 |
| `FM_CFGWR0_A3` | 20 | CfgWr0 + mandatory OHC-A3 |
| `FM_UIOMRD64_MIN` | 16 | UIOMRd 4DW header, no OHC |
| `FM_UIOMWR64_MIN` | 24 | UIOMWr 4DW header + 2DW payload |
| `FM_MSG_TO_RC` | 12 | Message routed to RC, no data |
| `FM_MSGD_TO_RC` | 16 | Message with data routed to RC |
| `FM_FETCHADD32` | 16 | FetchAdd 32-bit atomic |
| `FM_CAS32` | 20 | CAS 32-bit atomic |
| `FM_DMWR32` | 16 | DMWr 32-bit |
| `FM_STREAM_FRAGMENT_0` | 48 | 4 back-to-back TLPs |
| `FM_LOCAL_PREFIX_ONLY` | 4 | Local TLP Prefix token |

For design rationale see `docs/flit_mode_test_plan.md`.

---

### 5. Documentation Tests

**Purpose:** Ensure examples in doc comments compile and run correctly.

**Test count: 6**

Tests embedded in `src/lib.rs` doc comments:
- `TlpPacket` usage example
- `new_mem_req` usage example
- `new_conf_req` usage example
- `new_cmpl_req` usage example
- `new_msg_req` usage example
- `new_atomic_req` usage example

---

## Test Summary

| Test Type | Location | Passes | Ignored | Purpose |
|---|---|---|---|---|
| Unit Tests | `src/lib.rs` | 48 | 0 | Internal implementation |
| Non-Flit Integration | `tests/non_flit_tests.rs` | 16 | 0 | PCIe 1–5 functional behavior |
| API Contract | `tests/api_tests.rs` | 64 | 0 | Public API stability |
| Flit Mode | `tests/flit_mode_tests.rs` | 32 | 8 | PCIe 6.x test plan |
| Doc Tests | `src/lib.rs` | 6 | 0 | Documentation examples |
| **Total** | | **166** | **8** | |

> `#[ignore]` tests compile but do not run by default.  
> Run `cargo test -- --ignored` to see all pending flit mode tests (Tier 4–5).

---

## Running Tests

```bash
# Run all tests (non-ignored)
cargo test

# Run only non-flit integration tests
cargo test --test non_flit_tests

# Run only flit mode tests (Tier 0–3; Tier 4–5 ignored)
cargo test --test flit_mode_tests

# Run only flit mode Tier 0 stubs
cargo test --test flit_mode_tests flit_packet

# See all pending flit mode tests (will show as 'FAILED - panicked at todo!')
cargo test --test flit_mode_tests -- --ignored

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
3. **Incremental Plan** — flit mode tiers unlock as implementation lands
4. **Documentation** — `#[ignore]` test bodies describe exactly what to implement
5. **Always Green** — all 166 non-ignored tests pass at every commit

---

## Future Work (Flit Mode Implementation)

To remove `#[ignore]` from flit mode tests, implement in order:

1. ~~**Tier 1** — `FlitDW0` struct + `flit_dw0_from_bytes()`~~ ✅ Done (v0.4.1)
2. ~~**Tier 2** — `FlitTlpType` enum + base header size table~~ ✅ Done (v0.4.1)
3. ~~**Tier 3** — `FlitOhcA` struct + `validate_mandatory_ohc()` + `TlpError::MissingMandatoryOhc`~~ ✅ Done (v0.4.1)
4. **Tier 4** — `FlitStreamWalker` iterator
5. **Tier 5** — Wire `TlpMode::Flit` in `TlpPacket::new`
6. Bump version to `0.5.0`

See `docs/flit_mode_test_plan.md` for full architectural decisions and acceptance criteria.
