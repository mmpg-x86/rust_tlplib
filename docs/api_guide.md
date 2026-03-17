# rtlp-lib API Guide

This guide walks through the library from a user perspective: how to parse
TLPs, which method to call and when, how ownership and lifetimes work, and
how to extend or test code that uses the library.

---

## Table of Contents

1. [Core Concepts](#1-core-concepts)
2. [Parsing a Non-Flit TLP (PCIe 1.0–5.0)](#2-parsing-a-non-flit-tlp-pcie-10-50)
3. [Mode Dispatch — Handling Both Modes in the Same Code Path](#3-mode-dispatch--handling-both-modes-in-the-same-code-path)
4. [Non-Flit TLP Types — per-type field extraction](#4-non-flit-tlp-types--per-type-field-extraction)
5. [Parsing a Flit-Mode TLP (PCIe 6.0 Base Spec)](#5-parsing-a-flit-mode-tlp-pcie-6x)
6. [Flit Stream Walking](#6-flit-stream-walking)
7. [Ownership and Lifetimes](#7-ownership-and-lifetimes)
8. [Error Handling](#8-error-handling)
9. [Non-Posted vs Posted Transactions](#9-non-posted-vs-posted-transactions)
10. [Deprecated API Migration](#10-deprecated-api-migration)
11. [How the API Tests Work](#11-how-the-api-tests-work)

---

## 1. Core Concepts

### `TlpPacket` — the single entry point

Everything starts with `TlpPacket::new(bytes, mode)`:

```rust
use rtlp_lib::{TlpPacket, TlpMode};

let bytes: Vec<u8> = capture_from_hardware(); // your byte source
let pkt = TlpPacket::new(bytes, TlpMode::NonFlit)?;
```

`TlpPacket::new` does three things:
1. Validates the length (must be ≥ 4 bytes).
2. Splits the input: **DW0** (first 4 bytes) goes into the header; the rest
   becomes the data payload accessible via `pkt.data()`.
3. For flit mode, additionally parses the DW0 type code and validates
   mandatory OHC fields.

### The two-surface design

The library has **two separate parsing surfaces** because flit-mode and
non-flit-mode use completely different DW0 encodings:

| Surface | Mode | DW0 encoding | Type method |
|---------|------|--------------|-------------|
| Non-flit | `TlpMode::NonFlit` | `Fmt[2:0] \| Type[4:0]` | `pkt.tlp_type()` → `TlpType` |
| Flit | `TlpMode::Flit` | flat 8-bit type code | `pkt.flit_type()` → `Option<FlitTlpType>` |

The `mode()` method tells you which surface to use:

```rust
match pkt.mode() {
    TlpMode::NonFlit => { /* use tlp_type(), tlp_format(), header() */ }
    TlpMode::Flit    => { /* use flit_type() */ }
    _ => {}  // TlpMode is #[non_exhaustive]; wildcard required in external code
}
```

> **Why `mode()` instead of `flit_type().is_some()`?**  
> Both are equivalent, but `mode()` makes the dispatch intent explicit and
> reads like documentation. Compare with `pnet`'s pattern of separate
> packet types per protocol layer — we encode the same clarity in a single
> `match` expression.

---

## 2. Parsing a Non-Flit TLP (PCIe 1.0–5.0)

### Step 1 — create the packet

```rust
use rtlp_lib::{TlpPacket, TlpMode, TlpError};

let bytes = vec![
    0x40, 0x00, 0x00, 0x01,   // DW0: MemWrite 3DW, TC=0, length=1
    0x00, 0x01, 0x20, 0x0F,   // DW1: req_id=0x0001 tag=0x20 BE=0x0F
    0xDE, 0xAD, 0xBE, 0xEF,   // DW2: address32 = 0xDEADBEEF
    0xCA, 0xFE, 0xBA, 0xBE,   // payload DW
];

let pkt = TlpPacket::new(bytes, TlpMode::NonFlit)?;
```

### Step 2 — decode the type

```rust
let tlp_type   = pkt.tlp_type()?;    // → TlpType::MemWriteReq
let tlp_format = pkt.tlp_format()?;  // → TlpFmt::WithDataHeader3DW
```

`tlp_type()` decodes both the `Fmt` and `Type` fields together so you never
see an impossible combination — an `IORead` with a 4DW header is a
`TlpError::UnsupportedCombination`, not a valid `TlpType`.

### Step 3 — extract per-type fields

Use the appropriate factory function, passing `pkt.data()` directly:

```rust
use rtlp_lib::new_mem_req;

// data() returns &[u8] — no allocation
let mr = new_mem_req(pkt.data(), &tlp_format)?;
println!("Address: 0x{:08X}", mr.address());
println!("Req ID:  0x{:04X}", mr.req_id());
println!("Tag:     0x{:02X}", mr.tag());
```

> **Ownership note:** `pkt.data()` returns `&[u8]` borrowed from `pkt`.  
> The factory functions accept `impl Into<Vec<u8>>`, so `&[u8]` is coerced
> into an owned `Vec<u8>` internally — a single allocation at the point you
> need the fields, not at parse time.

---

## 3. Mode Dispatch — Handling Both Modes in the Same Code Path

If your code receives packets of unknown framing (e.g., a mixed PCIe 5/6
trace), use `mode()` to branch cleanly:

```rust
use rtlp_lib::{TlpPacket, TlpMode, TlpType, FlitTlpType};

fn process(pkt: &TlpPacket) {
    match pkt.mode() {
        TlpMode::NonFlit => process_non_flit(pkt),
        TlpMode::Flit    => process_flit(pkt),
        _ => eprintln!("unknown mode"),
    }
}

fn process_non_flit(pkt: &TlpPacket) {
    match pkt.tlp_type().unwrap() {
        TlpType::MemReadReq  => println!("memory read"),
        TlpType::MemWriteReq => println!("memory write @ {} bytes", pkt.data().len()),
        other                => println!("non-flit TLP: {:?}", other),
    }
}

fn process_flit(pkt: &TlpPacket) {
    match pkt.flit_type() {
        Some(FlitTlpType::MemRead32)  => println!("flit MRd32"),
        Some(FlitTlpType::MemWrite32) => println!("flit MWr32 @ {} bytes", pkt.data().len()),
        Some(other)                   => println!("flit TLP: {:?}", other),
        None                          => unreachable!("mode() returned Flit"),
    }
}
```

---

## 4. Non-Flit TLP Types — per-type field extraction

### Memory Requests (MemRead, MemWrite, MemReadLock, DMWr, IORead, IOWrite)

All share the `MemRequest` trait. Use `new_mem_req(bytes, &fmt)`.

```rust
use rtlp_lib::{TlpPacket, TlpMode, TlpType, TlpFmt, new_mem_req};

let pkt = TlpPacket::new(bytes, TlpMode::NonFlit)?;
let fmt = pkt.tlp_format()?;

// Covers MemRead/Write 32 and 64-bit, IORead/Write, DMWr
let mr = new_mem_req(pkt.data(), &fmt)?;
println!("address={:#x} req_id={:#06x} tag={:#04x}",
         mr.address(), mr.req_id(), mr.tag());

// For 3DW headers, address() returns a 32-bit value zero-extended to u64
// For 4DW headers, address() returns the full 64-bit value
```

`new_mem_req` selects `MemRequest3DW` or `MemRequest4DW` based on `fmt`, then
returns a `Box<dyn MemRequest>` so callers never need to match on 3DW vs 4DW.

### Configuration Requests

Configuration requests are always 3DW. `new_conf_req` only needs the bytes.

```rust
use rtlp_lib::new_conf_req;

// data() contains DW1+DW2 (8 bytes)
let cr = new_conf_req(pkt.data()).expect("insufficient bytes");
println!("bus={} dev={} func={} reg={}",
         cr.bus_nr(), cr.dev_nr(), cr.func_nr(), cr.reg_nr());
```

### Completions

```rust
use rtlp_lib::new_cmpl_req;

let cpl = new_cmpl_req(pkt.data()).expect("insufficient bytes");
println!("status={} byte_count={} lower_addr=0x{:02x}",
         cpl.cmpl_stat(), cpl.byte_cnt(), cpl.laddr());
```

> **Note on `laddr()`:** The 7-bit Lower Address field (bits `[6:0]`) is
> preserved in full — bit 6 had previously been incorrectly masked.

### Message Requests

```rust
use rtlp_lib::new_msg_req;

let msg = new_msg_req(pkt.data()).expect("insufficient bytes");
println!("msg_code=0x{:02X} dw3=0x{:08X} dw4=0x{:08X}",
         msg.msg_code(), msg.dw3(), msg.dw4());
```

`dw3()` and `dw4()` return the full 32-bit DW values — all 32 bits preserved.

### Atomic Operations

Atomics are the only type parsed through the full packet rather than just
the data, because the operand width and layout depend on the format field
(3DW → 32-bit operands, 4DW → 64-bit).

```rust
use rtlp_lib::new_atomic_req;

let ar = new_atomic_req(&pkt)?;
println!("op={:?} width={:?} operand0=0x{:X}",
         ar.op(), ar.width(), ar.operand0());

// CAS: operand0 = compare value, operand1 = swap value
if let Some(swap) = ar.operand1() {
    println!("swap value=0x{:X}", swap);
}
```

`new_atomic_req` validates that the data length exactly matches
`header_size + operand_count × operand_size` and returns
`Err(TlpError::InvalidLength)` if not.

---

## 5. Parsing a Flit-Mode TLP (PCIe 6.0 Base Spec)

### Single-packet parsing

```rust
use rtlp_lib::{TlpPacket, TlpMode, FlitTlpType};

// MWr32 flit: DW0(type=0x40, length=1) + 2 header DWs + 1 payload DW
let bytes = vec![
    0x40, 0x00, 0x00, 0x01,  // DW0: MemWrite32, TC=0, ohc=0, length=1
    0x00, 0x00, 0x00, 0x00,  // DW1
    0x00, 0x00, 0x10, 0x00,  // DW2: address32 = 0x1000
    0xDE, 0xAD, 0xBE, 0xEF,  // payload
];

let pkt = TlpPacket::new(bytes, TlpMode::Flit)?;

assert_eq!(pkt.flit_type(), Some(FlitTlpType::MemWrite32));
// data() returns payload bytes (after base header + OHC words)
assert_eq!(pkt.data(), [0xDE, 0xAD, 0xBE, 0xEF]);
```

### Read requests have no payload

In flit mode, a read request never carries a payload even when `Length > 0`
(the Length field describes the expected completion, not the request):

```rust
let mrd32_bytes = vec![
    0x03, 0x00, 0x00, 0x01,  // type=MemRead32, length=1 DW (completion size hint)
    0x00, 0x00, 0x00, 0x00,  // DW1
    0x00, 0x00, 0x10, 0x00,  // DW2: address32
];
let pkt = TlpPacket::new(mrd32_bytes, TlpMode::Flit)?;
assert_eq!(pkt.flit_type(), Some(FlitTlpType::MemRead32));
assert!(pkt.data().is_empty());  // no payload in a read request
```

### OHC (Optional Header Content) words

`FlitDW0` carries the OHC bitmap and count:

```rust
use rtlp_lib::FlitDW0;

let dw0 = FlitDW0::from_dw0(&bytes)?;
println!("ohc_count={} total_bytes={}", dw0.ohc_count(), dw0.total_bytes());
```

To parse an OHC-A word (carries PASID and byte-enables):

```rust
use rtlp_lib::FlitOhcA;

// OHC-A starts at byte offset: base_header_dw() * 4
let ohc_offset = dw0.tlp_type.base_header_dw() as usize * 4;
let ohc = FlitOhcA::from_bytes(&raw_tlp_bytes[ohc_offset..])?;
println!("PASID=0x{:05X} fdwbe=0x{:X} ldwbe=0x{:X}",
         ohc.pasid, ohc.fdwbe, ohc.ldwbe);
```

### Mandatory OHC validation

I/O Write and Config Type 0 Write require OHC-A. `TlpPacket::new` with
`TlpMode::Flit` automatically validates this:

```rust
// I/O Write without OHC → error
let bad_iowr = vec![0x42, 0x00, 0x00, 0x01, /* ... */];
let result = TlpPacket::new(bad_iowr, TlpMode::Flit);
assert_eq!(result.err(), Some(TlpError::MissingMandatoryOhc));
```

---

## 6. Flit Stream Walking

`FlitStreamWalker` iterates over a packed sequence of back-to-back flit
TLPs in a byte buffer. It yields `Ok((offset, FlitTlpType, total_bytes))`
for each TLP, or `Err(TlpError::InvalidLength)` if a TLP extends past the
end of the buffer.

```rust
use rtlp_lib::{FlitStreamWalker, FlitTlpType, TlpError};

let packed_tlps: &[u8] = &[
    // NOP (4 bytes)
    0x00, 0x00, 0x00, 0x00,
    // MRd32 minimal (12 bytes)
    0x03, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x10, 0x00,
];

for result in FlitStreamWalker::new(packed_tlps) {
    match result {
        Ok((offset, typ, size)) =>
            println!("[{:3}] {:?} ({} bytes)", offset, typ, size),
        Err(TlpError::InvalidLength) =>
            eprintln!("truncated TLP — stream is corrupt"),
        Err(e) =>
            eprintln!("parse error: {}", e),
    }
}
// Output:
//   [  0] Nop (4 bytes)
//   [  4] MemRead32 (12 bytes)
```

After the first error, the iterator returns `None` for all subsequent calls.

---

## 7. Ownership and Lifetimes

### `data()` borrows from the packet

```rust
let pkt = TlpPacket::new(bytes, TlpMode::NonFlit)?;
let payload: &[u8] = pkt.data();  // lifetime tied to `pkt`

// This is fine — payload is used while pkt is alive:
let mr = new_mem_req(payload, &pkt.tlp_format()?)?;

// This would NOT compile — pkt moved/dropped before payload used:
// drop(pkt);
// println!("{:?}", payload);  // ← borrow-after-move error
```

### Factory functions own their bytes

All factory functions (`new_mem_req`, `new_conf_req`, `new_cmpl_req`,
`new_msg_req`) take `impl Into<Vec<u8>>` and store an owned `Vec<u8>`
internally. The trait object they return owns its data:

```rust
// Passing pkt.data() (&[u8]) → one Vec allocation inside new_conf_req
let cr: Box<dyn ConfigurationRequest> = new_conf_req(pkt.data()).expect("insufficient bytes");
// `cr` is independent of `pkt` — pkt can be dropped here
drop(pkt);
println!("bus={}", cr.bus_nr());  // cr still valid
```

If you already have a `Vec<u8>`, you can pass it without cloning:
```rust
let owned: Vec<u8> = read_config_bytes();
let cr = new_conf_req(owned).expect("insufficient bytes");  // Vec moved in, no extra allocation
```

### `new_atomic_req` takes `&TlpPacket`

The atomic parser borrows the packet for the duration of parsing and
returns an owned `Box<dyn AtomicRequest>`:

```rust
let ar: Box<dyn AtomicRequest> = new_atomic_req(&pkt)?;
// pkt still owned by you; ar is independent
println!("{:?}", ar);
```

---

## 8. Error Handling

Every parsing step that can fail returns `Result<_, TlpError>`.
`TlpError` implements `std::error::Error` and `Display`, so it composes
naturally with `?` and `Box<dyn Error>`:

```rust
use rtlp_lib::{TlpPacket, TlpMode, TlpError};

fn parse_tlp(bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let pkt = TlpPacket::new(bytes, TlpMode::NonFlit)?;
    let t   = pkt.tlp_type()?;
    println!("TLP type: {}", t);  // TlpType implements Display
    Ok(())
}
```

### Error variants

| Variant | When you see it |
|---------|----------------|
| `InvalidFormat` | Fmt bits are one of the three reserved values (0b101, 0b110, 0b111) |
| `InvalidType` | Type bits don't match any known encoding |
| `UnsupportedCombination` | Valid Fmt + Type individually, but not a legal pair (e.g. IO Request with 4DW header) |
| `InvalidLength` | Byte slice < 4, or atomic payload size doesn't match expected |
| `NotImplemented` | `TlpPacketHeader::new(TlpMode::Flit)`, or calling `tlp_type()` on a flit packet |
| `MissingMandatoryOhc` | Flit IOWrite or CfgWrite0 without the required OHC-A word |

### Pattern matching on errors

```rust
match pkt.tlp_type() {
    Ok(t) => process(t),
    Err(TlpError::UnsupportedCombination) => {
        eprintln!("vendor-specific or reserved TLP, skipping");
    }
    Err(TlpError::InvalidFormat) => {
        eprintln!("malformed DW0 — likely capture artifact");
    }
    Err(e) => return Err(e.into()),
}
```

---

## 9. Non-Posted vs Posted Transactions

`TlpType::is_non_posted()` returns `true` for TLP types that require a
completion. Use this for flow-control accounting, timeout logic, or
filtering trace data:

```rust
use rtlp_lib::TlpType;

fn requires_completion(t: &TlpType) -> bool {
    t.is_non_posted()
}

// Non-posted (require completion): reads, I/O, config, atomics, DMWr
assert!( TlpType::MemReadReq.is_non_posted());
assert!( TlpType::IOWriteReq.is_non_posted());
assert!( TlpType::ConfType0WriteReq.is_non_posted());
assert!( TlpType::FetchAddAtomicOpReq.is_non_posted());
assert!( TlpType::DeferrableMemWriteReq.is_non_posted());

// Posted (no completion): memory writes, messages
assert!(!TlpType::MemWriteReq.is_non_posted());
assert!(!TlpType::MsgReq.is_non_posted());

// Completions and prefixes are neither requests nor posted writes
assert!(!TlpType::CplData.is_non_posted());
assert!(!TlpType::LocalTlpPrefix.is_non_posted());
```

`is_posted()` is the convenience inverse: `!is_non_posted()`.

---

## 10. Deprecated API Migration

In 0.5.0, all `get_*` methods were renamed to follow Rust naming conventions.
The old names are still present with `#[deprecated]` markers so existing code
continues to compile with a `cargo` warning.

### Migration table

| Deprecated method | Replacement | Notes |
|---|---|---|
| `pkt.get_tlp_type()` | `pkt.tlp_type()` | Same return type: `Result<TlpType, TlpError>` |
| `pkt.get_tlp_format()` | `pkt.tlp_format()` | Same return type: `Result<TlpFmt, TlpError>` |
| `pkt.get_flit_type()` | `pkt.flit_type()` | Same return type: `Option<FlitTlpType>` |
| `pkt.get_header()` | `pkt.header()` | Same return type: `&TlpPacketHeader` |
| `pkt.get_data()` | `pkt.data()` | **Different type:** `get_data()` → `Vec<u8>` (allocates); `data()` → `&[u8]` (zero-copy) |
| `hdr.get_tlp_type()` | `hdr.tlp_type()` | Same return type |

### Suppressing the warning during migration

If you have a large codebase you can't migrate all at once:

```rust
#[allow(deprecated)]
fn legacy_process(pkt: &TlpPacket) -> TlpType {
    pkt.get_tlp_type().unwrap()  // suppress warning for this block only
}
```

### What happens to `get_data()` users

`get_data()` returns an owned `Vec<u8>` (clones the payload). The new
`data()` returns `&[u8]` without allocating. Most call sites only read the
data, so the migration is:

```rust
// Before:
let bytes: Vec<u8> = pkt.get_data();
let mr = new_mem_req(bytes, &fmt)?;

// After (allocation moved into `new_mem_req`; no explicit .to_vec() at call site):
let mr = new_mem_req(pkt.data(), &fmt)?;
```

---

## 11. How the API Tests Work

`tests/api_tests.rs` serves three purposes simultaneously:

### Purpose 1: Compilation = correctness

Many tests contain no runtime assertions — they simply use every public
type and function:

```rust
fn api_all_expected_public_types_are_available() {
    use rtlp_lib::{TlpPacket, TlpMode, TlpType, /* ... */};
    let _: Option<TlpPacket> = None;
    // ...
}
```

If `TlpPacket` is renamed or removed, this test fails to **compile**, giving
an instant breaking-change signal before a single test runs.

### Purpose 2: Behavioural contract

Tests like `tlp_packet_mode_returns_correct_mode` assert specific return
values. If the implementation changes the semantics (e.g. `mode()` returns
the wrong variant), the test fails at runtime.

### Purpose 3: Backward-compatibility enforcement

The `#[allow(deprecated)]` tests prove that every deprecated alias still
compiles and delegates to the new method:

```rust
#[test]
#[allow(deprecated)]
fn deprecated_get_tlp_type_on_packet_delegates_to_tlp_type() {
    let pkt = TlpPacket::new(/* ... */, TlpMode::NonFlit).unwrap();
    assert_eq!(pkt.get_tlp_type(), pkt.tlp_type());  // must match
}
```

This ensures that code written against the old API continues to produce
correct results even after the internal implementation moves to the new name.

### Writing tests for your own code

If you write code that processes `TlpPacket`s, mirror the same three-layer
pattern:

```rust
// Layer 1: compilation test — your function accepts the right types
fn my_decoder_accepts_tlp_packet(_pkt: &TlpPacket) {}

// Layer 2: behaviour test — correct output for known input
#[test]
fn my_decoder_handles_mem_write() {
    let bytes = vec![0x40, 0x00, 0x00, 0x01, /* ... */];
    let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::MemWriteReq);
    // test your own logic here
}

// Layer 3: error path — your code handles bad input gracefully
#[test]
fn my_decoder_rejects_flit_packet() {
    let pkt = TlpPacket::new(vec![0x00; 4], TlpMode::Flit).unwrap();
    // tlp_type() returns Err(NotImplemented) for flit packets
    assert!(pkt.tlp_type().is_err());
}
```

---

## Summary: the typical parsing flow

```
Vec<u8>  ──►  TlpPacket::new(bytes, mode)
                    │
                    ▼
              pkt.mode()
             /          \
        NonFlit          Flit
            │               │
    pkt.tlp_type()   pkt.flit_type()
    pkt.tlp_format()        │
            │         FlitTlpType
        TlpType               \── pkt.data() for payload bytes
            │
     match on TlpType
     ├── Mem*    → new_mem_req(pkt.data(), &fmt)  → MemRequest trait
     ├── Conf*   → new_conf_req(pkt.data())        → ConfigurationRequest trait
     ├── Cpl*    → new_cmpl_req(pkt.data())        → CompletionRequest trait
     ├── Msg*    → new_msg_req(pkt.data())          → MessageRequest trait
     └── Atomic* → new_atomic_req(&pkt)            → AtomicRequest trait
```

All factory functions take `impl Into<Vec<u8>>` — pass `pkt.data()` directly,
no `.to_vec()` needed.



