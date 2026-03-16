# Flit Mode Test Plan

**Status:** In progress — Tier 1+2+3 implemented (v0.4.1); Tier 4–5 pending  
**Target release:** 0.5.0  
**Reference:** `docs/flit_mode_tlp_examples.md`

---

## 1. Background

PCIe 6.0 introduced **Flit Mode**, where TLPs are carried inside fixed 256-byte FLIT containers.
The TLP structure inside a flit is fundamentally different from non-flit TLPs:

### DW0 format comparison

| Byte | Non-Flit (PCIe 1–5) | Flit Mode (PCIe 6.x) |
|---|---|---|
| 0 | `Fmt[2:0] \| Type[4:0]` | **`Type[7:0]`** — full flat 8-bit type code |
| 1 | `T9, TC[2:0], T8, Attr_b2, LN, TH` | **`TC[2:0] \| OHC[4:0]`** — OHC presence flags |
| 2 | `TD, EP, Attr[1:0], AT[1:0], Length[9:8]` | `TS[2:0] \| Attr[2:0] \| Length[9:8]` |
| 3 | `Length[7:0]` | `Length[7:0]` |

**Consequence:** The existing `TlpHeader` bitfield and `get_tlp_type()` logic is **completely
incompatible with flit mode DW0**. Flit mode requires its own dedicated parser.

### OHC — Optional Header Content

OHC is a new flit-mode concept with no non-flit equivalent:

- **`OHC[4:0]`** in DW0 byte 1 — each bit indicates an extra OHC word present in the header
- Each OHC word adds **1 DW** to the header after the base header
- Some TLP types have **mandatory OHC rules**:
  - I/O Requests: OHC-A2 is mandatory
  - Configuration Requests: OHC-A3 is mandatory
  - Violation of mandatory OHC rules is a parser error

### New TLP types

Flit mode introduces types not present in the non-flit `TlpType` enum:

| Type code | Name | Non-flit equivalent |
|---|---|---|
| `0x00` | NOP | — (new) |
| `0x03` | MRd32 | MemReadReq (different encoding) |
| `0x22` | UIOMRd (4DW) | — (new, PCIe 6.1+ UIO) |
| `0x40` | MWr32 | MemWriteReq (different encoding) |
| `0x42` | IOWr | IOWriteReq (different encoding) |
| `0x44` | CfgWr0 | ConfType0WriteReq (different encoding) |
| `0x4C` | FetchAdd32 | FetchAddAtomicOpReq (different encoding) |
| `0x4E` | CAS32 | CompareSwapAtomicOpReq (different encoding) |
| `0x5B` | DMWr32 | DeferrableMemWriteReq (different encoding) |
| `0x61` | UIOMWr (4DW) | — (new, PCIe 6.1+ UIO) |
| `0x70` | MsgD to RC | MsgReqData (different encoding) |
| `0x8D` | Local TLP Prefix | LocalTlpPrefix (different encoding) |

---

## 2. Architectural Decisions

### Decision 1: Separate `FlitTlpType` enum

**Decision:** Introduce a new `FlitTlpType` enum, do **not** extend `TlpType`.

**Rationale:**
- Type code numbers are completely disjoint (flit MRd32=0x03 vs non-flit MRd=computed from fmt+type bits)
- New types (NOP, UIOMRd, UIOMWr) have no non-flit equivalent
- Mixing them into `TlpType` would create confusion and invalid `match` arms for callers on both paths

```rust
// Future addition to src/lib.rs
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlitTlpType {
    Nop,
    MemRead32, MemRead64,
    MemWrite32, MemWrite64,
    IoRead, IoWrite,
    CfgRead0, CfgWrite0, CfgRead1, CfgWrite1,
    MsgToRc, MsgDToRc,      // ... other routing variants
    Completion, CompletionWithData,
    FetchAdd32, FetchAdd64,
    Swap32, Swap64,
    CompareSwap32, CompareSwap64,
    DeferrableMemWrite32, DeferrableMemWrite64,
    UioMemRead, UioMemWrite,   // PCIe 6.1+ UIO
    LocalTlpPrefix,
    // #[non_exhaustive] — future codes will be added without breaking match arms
}
```

### Decision 2: New `FlitDW0` struct

**Decision:** Introduce a `FlitDW0` struct to decode flit-mode DW0.

```rust
// Future addition to src/lib.rs
pub struct FlitDW0 {
    pub tlp_type: FlitTlpType,
    pub tc: u8,
    pub ohc: u8,           // 5-bit OHC presence bitmap
    pub ts: u8,
    pub attr: u8,
    pub length: u16,       // in DW, 0 = 1024 DW
}
```

### Decision 3: `TlpMode::Flit` wires to new parser

**Decision:** When `TlpPacket::new(bytes, TlpMode::Flit)` is called, dispatch to
`new_flit(bytes)` which uses `FlitDW0` instead of `TlpHeader`.

Currently returns `Err(TlpError::NotImplemented)` — this is the stub that all
Tier 5 tests verify will eventually succeed.

### Decision 4: `#[ignore]` convention for unimplemented tiers

**Decision:** Write full test bodies now, mark them `#[ignore]` until the required
implementation exists. This gives us:
- Compile-time confidence the test logic is correct
- A runnable "progress check": `cargo test -- --ignored` shows what's pending
- No blocked PRs — all tests pass (48+55+16+N_ignored+6 = green)

---

## 3. Test File Structure

```
tests/
├── api_tests.rs          ← unchanged scope: public API surface stability
│                            includes TlpMode enum tests, TlpError variants
├── non_flit_tests.rs     ← renamed from tlp_tests.rs
│                            all existing functional tests
│                            explicit TlpMode::NonFlit at every call site
└── flit_mode_tests.rs    ← new: flit parser test plan
                             all FM_* byte vector constants defined here
                             tiered test structure (Tier 0–5)
```

---

## 4. Tier Definitions

### Tier 0 — Current stubs ✅ (passes today)

Tests that verify the current `NotImplemented` stub behavior.
These are written and passing NOW.

```rust
// TlpPacket::new(bytes, TlpMode::Flit).err().unwrap() == TlpError::NotImplemented
// TlpPacketHeader::new(bytes, TlpMode::Flit).err().unwrap() == TlpError::NotImplemented
```

**Unlock condition:** N/A — these are permanent regression guards for the stub.

---

### Tier 1 — Flit DW0 field extraction ✅ (implemented v0.4.1)

Tests that decode individual fields from flit DW0 bytes using `FlitDW0::from_dw0()`.

**Implemented:** `FlitDW0` struct + `FlitDW0::from_dw0()` in `src/lib.rs`.

---

### Tier 2 — Per-vector header + size validation ✅ (implemented v0.4.1)

Tests that each FM_* vector produces the correct type, base header size, OHC count, and total TLP size.

**Implemented:** `FlitTlpType` enum + `base_header_dw()` + `total_bytes()` in `src/lib.rs`.

---

### Tier 3 — OHC field parsing ✅ (implemented v0.4.1)

Tests that OHC words are parsed correctly:

- `FM_MRD32_A1_PASID` → OHC-A1 present, PASID=0x12345, fdwbe=0xF, ldwbe=0x0 ✅
- `FM_MWR32_PARTIAL_A1` → OHC-A1 present, fdwbe=0x3 ✅
- `FM_IOWR_A2` → mandatory OHC-A2 present, fdwbe=0xF ✅
- `FM_CFGWR0_A3` → mandatory OHC-A3 present ✅

**Negative tests** (mandatory OHC validation):
- `FM_IOWR_A2` with byte1=0x00 → `Err(TlpError::MissingMandatoryOhc)` ✅
- `FM_CFGWR0_A3` with byte1=0x00 → same error ✅

**Implemented:** `FlitOhcA::from_bytes()` + `FlitDW0::validate_mandatory_ohc()` + `TlpError::MissingMandatoryOhc`.

> **Naming note:** The struct is `FlitOhcA` (not `FlitOhc` as originally planned) to reflect that it
> parses the OHC-A word specifically (OHC-A1, OHC-A2, OHC-A3 share the same byte layout).

---

### Tier 4 — Packed stream walking `#[ignore]`

Tests that the parser can walk `FM_STREAM_FRAGMENT_0` (48 bytes containing 4 back-to-back TLPs)
and correctly determine start offset, type, and size of each TLP.

| Offset | Expected type | Expected size |
|---|---|---|
| 0 | NOP | 4 bytes |
| 4 | MRd32 | 12 bytes |
| 16 | MWr32 | 16 bytes |
| 32 | UIOMRd | 16 bytes |
| 48 | (end) | — |

**Unlock condition:** `FlitStreamWalker` or iterator type over packed byte slice.

---

### Tier 5 — End-to-end `TlpMode::Flit` pipeline `#[ignore]`

Tests that `TlpPacket::new(bytes, TlpMode::Flit)` succeeds for each FM_* vector
and populates fields correctly.

**Unlock condition:** `new_flit()` fully wired up inside `TlpPacket::new` dispatch.

---

## 5. Implementation Roadmap

To unlock each tier, these additions to `src/lib.rs` are required:

| Tier | What to add | New public API | Status |
|---|---|---|---|
| 1 | `FlitDW0` struct + `from_dw0()` | `pub struct FlitDW0` | ✅ v0.4.1 |
| 2 | `FlitTlpType` enum + size table | `pub enum FlitTlpType` | ✅ v0.4.1 |
| 3 | OHC parser + `MissingMandatoryOhc` | `pub struct FlitOhcA`, `TlpError::MissingMandatoryOhc` | ✅ v0.4.1 |
| 4 | Stream walker | `pub struct FlitStreamWalker` or iterator | pending |
| 5 | `TlpPacket::new_flit()` | wires `TlpMode::Flit` to new parser | pending |

Each tier builds on the previous — merge order matters.

---

## 6. "Not Frozen Yet" — Do Not Write Tests For

Per `flit_mode_tlp_examples.md` Appendix, the following should NOT be used
as golden vectors until the full PCIe Base Spec is consulted:

- `Cpl`, `CplD`, `UIORdCplD` — completion field packing not validated
- Vectors using `OHC-A5`, `OHC-B`, `OHC-C`
- IDE trailer examples
- Non-zero 10-bit / 14-bit Tag packing

---

## 7. Test Vector Reference (from `flit_mode_tlp_examples.md`)

All 15 constants are defined in `tests/flit_mode_tests.rs`:

```
FM_NOP                  [4 bytes]   Tier 1-5
FM_MRD32_MIN            [12 bytes]  Tier 1-5
FM_MRD32_A1_PASID       [16 bytes]  Tier 1-5 + OHC-A1 Tier 3
FM_MWR32_MIN            [16 bytes]  Tier 1-5
FM_MWR32_PARTIAL_A1     [20 bytes]  Tier 1-5 + OHC-A1 Tier 3
FM_IOWR_A2              [20 bytes]  Tier 1-5 + OHC-A2 mandatory Tier 3
FM_CFGWR0_A3            [20 bytes]  Tier 1-5 + OHC-A3 mandatory Tier 3
FM_UIOMRD64_MIN         [16 bytes]  Tier 1-5
FM_UIOMWR64_MIN         [24 bytes]  Tier 1-5
FM_MSG_TO_RC            [12 bytes]  Tier 1-5
FM_MSGD_TO_RC           [16 bytes]  Tier 1-5
FM_FETCHADD32           [16 bytes]  Tier 1-5
FM_CAS32                [20 bytes]  Tier 1-5
FM_DMWR32               [16 bytes]  Tier 1-5
FM_STREAM_FRAGMENT_0    [48 bytes]  Tier 4 only
FM_LOCAL_PREFIX_ONLY    [4 bytes]   Tier 2+ (prefix handling)
```

---

## 8. Negative Test Inventory

| Test | Input | Expected error |
|---|---|---|
| `flit_iowr_missing_mandatory_ohc_a2` | FM_IOWR_A2 with byte1=0x00 | `MissingMandatoryOhc` |
| `flit_cfgwr_missing_mandatory_ohc_a3` | FM_CFGWR0_A3 with byte1=0x00 | `MissingMandatoryOhc` |
| `flit_mwrpartial_missing_ohc_a1` | FM_MWR32_PARTIAL_A1 minus OHC word + byte1=0x00 | `MissingMandatoryOhc` (optional) |
| `flit_uiomrd_retyped_invalid` | FM_UIOMRD64_MIN with wrong base size | validator error |
| `flit_uiomwr_truncated_payload` | FM_UIOMWR64_MIN minus last byte | `InvalidLength` |

---

## 9. Acceptance Criteria

A flit mode implementation is considered complete when:

- [ ] All `#[ignore]` tests in `flit_mode_tests.rs` pass without the `#[ignore]` attribute
- [ ] All negative tests produce the correct error variant
- [ ] `FM_STREAM_FRAGMENT_0` stream walk completes with correct offsets
- [ ] `cargo test` shows 0 ignored tests in `flit_mode_tests.rs`
- [ ] `TESTS.md` updated with final counts
- [ ] Version bumped to `0.5.0`

