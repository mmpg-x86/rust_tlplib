# Release Notes — rtlp-lib v0.5.0

## What's New

### Flit Mode Support (PCIe 6.0 Base Spec)

`TlpMode::Flit` is now fully implemented in `TlpPacket::new`. Pass raw bytes from
a flit container (PCIe 6.0 Base Spec) and get back a fully parsed `TlpPacket` with the payload
separated from the header.

New flit-mode types and parsers:

| Type / Function | Purpose |
|---|---|
| `FlitTlpType` | 13-variant enum for flit-mode DW0 type codes |
| `FlitDW0` | Parsed flit DW0: `tlp_type`, `tc`, `ohc`, `ts`, `attr`, `length` |
| `FlitOhcA` | Parsed OHC-A word: PASID + byte-enable fields |
| `FlitStreamWalker` | Iterates a packed stream of back-to-back flit TLPs |
| `TlpError::MissingMandatoryOhc` | IoWrite / CfgWrite0 without required OHC-A |

```rust
// Parse a flit-mode TLP
let pkt = TlpPacket::new(bytes, TlpMode::Flit)?;
let flit_type = pkt.flit_type(); // Some(FlitTlpType::MemWrite32)

// Walk a stream of back-to-back flit TLPs
for result in FlitStreamWalker::new(packed_bytes) {
    let (offset, typ, size) = result?;
}
```

### Mode Dispatch API

`TlpPacket::mode()` returns the framing mode the packet was created with.
Use it to cleanly dispatch between the flit and non-flit parsing surfaces:

```rust
match pkt.mode() {
    TlpMode::Flit    => { /* use pkt.flit_type() */ }
    TlpMode::NonFlit => { /* use pkt.tlp_type(), pkt.tlp_format() */ }
    _                => {}  // TlpMode is #[non_exhaustive]
}
```

### Preferred (Non-`get_*`) Method Names

All `get_*` methods are now deprecated in favour of idiomatic Rust names.
The old names still compile — update at your own pace.

| Deprecated | Replacement | Change |
|---|---|---|
| `pkt.get_tlp_type()` | `pkt.tlp_type()` | Same `Result<TlpType, TlpError>` |
| `pkt.get_tlp_format()` | `pkt.tlp_format()` | Same `Result<TlpFmt, TlpError>` |
| `pkt.get_flit_type()` | `pkt.flit_type()` | Same `Option<FlitTlpType>` |
| `pkt.get_header()` | `pkt.header()` | Same `&TlpPacketHeader` |
| `pkt.get_data()` | `pkt.data()` | **Changed:** returns `&[u8]` (no alloc) |
| `hdr.get_tlp_type()` | `hdr.tlp_type()` | Same `Result<TlpType, TlpError>` |

### Factory Function Ergonomics

`new_conf_req`, `new_cmpl_req`, and `new_msg_req` now accept
`impl Into<Vec<u8>>`, matching `new_mem_req`. Pass `pkt.data()` directly:

```rust
// Before — required .to_vec()
let cr = new_conf_req(pkt.get_data());

// After — no explicit .to_vec() needed (allocation happens inside new_conf_req)
let cr = new_conf_req(pkt.data());
```

### Non-Posted / Posted Classification

```rust
TlpType::MemReadReq.is_non_posted()  // true — expects Completion
TlpType::MemWriteReq.is_posted()     // true — no Completion
TlpType::DeferrableMemWriteReq.is_non_posted() // true
```

### Debug Implementations

`TlpPacket` and `TlpPacketHeader` now implement `Debug`:

```rust
println!("{:?}", pkt);
// TlpPacket { header: TlpPacketHeader { format: 2, type: 0, ... }, flit_dw0: None, data_len: 8 }
```

---

## Breaking Changes

**None in v0.5.0.** All deprecated `get_*` aliases remain functional.
`TlpMode::Flit` and `FlitTlpType` are `#[non_exhaustive]` — future PCIe spec
additions will not be breaking changes.

> **Upgrading from v0.3.x or earlier?** The constructor signature changed in
> **v0.4.0** (not this release): `TlpPacket::new(bytes)` became
> `TlpPacket::new(bytes, TlpMode::NonFlit)`. Update any call sites that omit
> the framing-mode argument. v0.5.0 does not change this signature further.

---

## Supported TLP Types

### Non-Flit (PCIe 1.0 – 5.0)

| Category | Types |
|---|---|
| Memory | MemRead 32/64, MemWrite 32/64, MemReadLock |
| I/O | IORead, IOWrite |
| Configuration | Type0/Type1 Read/Write |
| Completion | Cpl, CplData, CplLocked, CplDataLocked |
| Message | MsgReq, MsgReqData (all 6 routing sub-types) |
| Atomic | FetchAdd, Swap, CompareSwap (W32 + W64) |
| Special | DeferrableMemWrite, LocalTlpPrefix, EndToEndTlpPrefix |

### Flit Mode (PCIe 6.0 Base Spec)

| Type | Notes |
|---|---|
| NOP | 1 DW header, no payload |
| MemRead32 / UioMemRead | No payload in request; Length = completion hint |
| MemWrite32 / UioMemWrite | With payload |
| IoWrite | Requires mandatory OHC-A2 |
| CfgWrite0 | Requires mandatory OHC-A3 |
| FetchAdd32, CompareSwap32 | Atomic ops |
| DeferrableMemWrite32 | DMWr |
| MsgToRc, MsgDToRc | Messages |
| LocalTlpPrefix | 1 DW header |

---

## Quality & CI

- **212 tests** — all passing, 0 ignored
- **`cargo clippy --all-targets -- -D warnings`** — clean
- **`RUSTDOCFLAGS=-D warnings cargo doc`** — clean
- **`#![warn(missing_docs)]`** and **`#![deny(unsafe_code)]`** enforced
- **CI pipeline** — 4 focused jobs: `fmt`, `clippy`, `test`, `msrv` (Rust 1.85)
- **MSRV**: Rust 1.85 (edition 2024)

---

## Upgrade Guide

```toml
# Cargo.toml
rtlp-lib = "0.5"
```

**Minimal non-flit migration** (no changes required — deprecated names still work):
```rust
// This still compiles with a deprecation warning:
let t = pkt.get_tlp_type()?;

// Preferred — suppress the warning permanently:
let t = pkt.tlp_type()?;
```

**Opt in to flit mode:**
```rust
let flit_pkt = TlpPacket::new(bytes, TlpMode::Flit)?;
match flit_pkt.mode() {
    TlpMode::Flit => println!("{:?}", flit_pkt.flit_type()),
    _ => {}
}
```

---

*Full change log: [CHANGELOG.md](CHANGELOG.md)*

