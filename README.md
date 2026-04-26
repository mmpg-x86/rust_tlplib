# rtlp-lib — Rust TLP Parsing Library

A Rust crate for parsing PCI Express Transaction Layer Packets (TLPs).

Decode raw TLP byte streams into strongly-typed structs, trait objects, and
helper value types. The library handles DW0 header decoding (format + type),
per-type field extraction (requester ID, tag, address, operands, …), typed
Bus/Device/Function helpers, and validates format/type combinations according
to the PCIe specification.

## Supported TLP Types

| Category | TLP Types | Trait / Constructor |
|---|---|---|
| **Memory Requests** | MemRead (32/64), MemWrite (32/64), MemReadLock | `MemRequest` / `new_mem_req()` |
| **IO Requests** | IORead, IOWrite | `MemRequest` / `new_mem_req()` |
| **Config Requests** | Type 0 Read/Write, Type 1 Read/Write | `ConfigurationRequest` / `new_conf_req()` |
| **Completions** | Cpl, CplData, CplLocked, CplDataLocked | `CompletionRequest` / `new_cmpl_req()` |
| **Messages** | MsgReq, MsgReqData | `MessageRequest` / `new_msg_req()` |
| **Atomic Ops** | FetchAdd, Swap, CompareSwap (32/64-bit operands) | `AtomicRequest` / `new_atomic_req()` |
| **DMWr** | Deferrable Memory Write (32/64) | `MemRequest` / `new_mem_req()` |

For a detailed breakdown of every TLP encoding, header layout, parsed fields,
and byte-level examples taken from the test suite, see **[tlp.md](tlp.md)**.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
rtlp-lib = "0.5"
```

## Usage

```rust
use rtlp_lib::{
    TlpPacket, TlpFmt, TlpType, TlpMode,
    new_mem_req, new_conf_req, new_cmpl_req, new_msg_req, new_atomic_req,
};

// Raw bytes captured from a PCIe trace (DW0 .. DWn)
let bytes = vec![
    0x00, 0x00, 0x20, 0x01,   // DW0: MemRead 3DW, length=1
    0x00, 0x00, 0x20, 0x0F,   // DW1: req_id=0x0000 tag=0x20 BE=0x0F
    0xF6, 0x20, 0x00, 0x0C,   // DW2: address32=0xF620000C
];
let packet = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();

// mode() tells you which parsing surface to use
match packet.mode() {
    TlpMode::NonFlit => {
        let tlp_type   = packet.tlp_type().unwrap();
        let tlp_format = packet.tlp_format().unwrap();

        match tlp_type {
            TlpType::MemReadReq | TlpType::MemWriteReq |
            TlpType::MemReadLockReq |
            TlpType::DeferrableMemWriteReq |
            TlpType::IOReadReq | TlpType::IOWriteReq => {
                // data() returns &[u8] — no extra allocation at this call site;
                // new_mem_req takes impl Into<Vec<u8>> and may allocate internally.
                let mr = new_mem_req(packet.data(), &tlp_format).unwrap();
                println!("req_id=0x{:04X} ({})  tag=0x{:02X}  addr=0x{:X}",
                         mr.req_id(), mr.device_id(), mr.tag(), mr.address());
            }
            TlpType::FetchAddAtomicOpReq |
            TlpType::SwapAtomicOpReq |
            TlpType::CompareSwapAtomicOpReq => {
                let ar = new_atomic_req(&packet).unwrap();
                println!("atomic {:?} operand0=0x{:X}", ar.op(), ar.operand0());
            }
            TlpType::ConfType0ReadReq | TlpType::ConfType0WriteReq |
            TlpType::ConfType1ReadReq | TlpType::ConfType1WriteReq => {
                let cr = new_conf_req(packet.data()).unwrap();  // accepts &[u8] directly
                println!("config bus={} dev={} func={}",
                         cr.bus_nr(), cr.dev_nr(), cr.func_nr());
            }
            TlpType::Cpl | TlpType::CplData |
            TlpType::CplLocked | TlpType::CplDataLocked => {
                let cpl = new_cmpl_req(packet.data()).unwrap();
                println!("completion status={}", cpl.cmpl_stat());
            }
            TlpType::MsgReq | TlpType::MsgReqData => {
                let msg = new_msg_req(packet.data()).unwrap();
                println!("message code=0x{:02X}", msg.msg_code());
            }
            _ => println!("TLP type: {:?}", tlp_type),
        }
    }
    TlpMode::Flit => {
        // Use flit_type() for flit-mode packets
        println!("flit type: {:?}", packet.flit_type());
    }
    _ => {}
}
```

### Display Summaries

`TlpPacket` and `TlpPacketHeader` implement `Display` for compact trace and log
output:

```text
MRd32 len=1 req=0000 tag=20 addr=F620000C
MWr64 len=4 req=BEEF tag=A5 addr=100000000
CplD len=1 cpl=2001 req=0400 tag=AB stat=0 bc=252
Flit:MWr32 len=4 tc=0 ohc=0 attr=0 ts=0
Flit:NOP
```

Flit summaries always include the stable field set `len`, `tc`, `ohc`,
`attr`, and `ts`, even when optional values are zero. That keeps log columns
predictable for downstream parsers.

### Non-Posted Semantics

The library exposes `TlpType::is_non_posted()` to distinguish requests that
require a completion from posted writes:

```rust
use rtlp_lib::TlpType;

assert!( TlpType::MemReadReq.is_non_posted());
assert!( TlpType::DeferrableMemWriteReq.is_non_posted());
assert!(!TlpType::MemWriteReq.is_non_posted());   // posted
```

## Public API Overview

### Core Types (Non-Flit)

| Type | Description |
|---|---|
| `TlpPacket` | Full packet: DW0 header + remaining data bytes |
| `TlpPacketHeader` | DW0-only wrapper exposing selected header fields via public accessors |
| `TlpMode` | Framing mode: `NonFlit` (PCIe 1–5) or `Flit` (PCIe 6.x) |

**Key `TlpPacket` methods:**

| Method | Returns | Notes |
|---|---|---|
| `mode()` | `TlpMode` | Explicit framing mode; use to dispatch between API surfaces |
| `tlp_type()` | `Result<TlpType, TlpError>` | Non-flit only; returns `Err(NotImplemented)` for flit |
| `tlp_format()` | `Result<TlpFmt, TlpError>` | Non-flit only |
| `flit_type()` | `Option<FlitTlpType>` | Flit only; `None` for non-flit |
| `header()` | `&TlpPacketHeader` | Non-flit only (returns dummy zeros for flit) |
| `data()` | `&[u8]` | Payload bytes after DW0; borrows from the packet |

**Other core types:**

| Type | Description |
|---|---|
| `TlpFmt` | Format enum: `NoDataHeader3DW`, `NoDataHeader4DW`, `WithDataHeader3DW`, `WithDataHeader4DW`, `TlpPrefix` |
| `TlpType` | 21-variant enum covering all decoded non-flit TLP types |
| `TlpError` | `InvalidFormat`, `InvalidType`, `UnsupportedCombination`, `InvalidLength`, `NotImplemented`, `MissingMandatoryOhc` |
| `DeviceID` | Typed PCIe Bus/Device/Function identifier with raw `u16` conversion, `BB:DD.F` display formatting, and `FromStr` parsing |

### Flit Mode Types (PCIe 6.0 Base Spec)

| Type | Description |
|---|---|
| `FlitTlpType` | 13-variant enum for flit-mode type codes (`TryFrom<u8>`, `base_header_dw()`, `is_read_request()`) |
| `FlitDW0` | Parsed flit-mode DW0: `tlp_type`, `tc`, `ohc`, `ts`, `attr`, `length`; `from_dw0()`, `total_bytes()` |
| `FlitOhcA` | Parsed OHC-A word: `pasid`, `fdwbe`, `ldwbe`; `from_bytes()` |
| `FlitStreamWalker` | Iterator over a packed flit TLP byte stream; yields `(offset, FlitTlpType, size)` per TLP |

```rust
use rtlp_lib::{TlpPacket, TlpMode, FlitStreamWalker, FlitTlpType};

// Parse a single flit TLP
let nop_bytes = vec![0x00u8, 0x00, 0x00, 0x00];
let pkt = TlpPacket::new(nop_bytes, TlpMode::Flit).unwrap();
assert_eq!(pkt.flit_type(), Some(FlitTlpType::Nop));
assert_eq!(pkt.mode(), TlpMode::Flit);  // explicit mode check

// Walk a packed stream of back-to-back flit TLPs
let stream: &[u8] = &[/* packed bytes */];
for result in FlitStreamWalker::new(stream) {
    let (offset, typ, size) = result.unwrap();
    println!("TLP at offset {}: {:?} ({} bytes)", offset, typ, size);
}
```

### Request Traits and Constructors

| Trait | Fields | Constructor |
|---|---|---|
| `MemRequest` | `address()`, `req_id()`, `requester_id()`, `device_id()`, `tag()`, `ldwbe()`, `fdwbe()` | `new_mem_req(bytes, &fmt)` |
| `ConfigurationRequest` | `req_id()`, `requester_id()`, `tag()`, `bus_nr()`, `dev_nr()`, `func_nr()`, `ext_reg_nr()`, `reg_nr()` | `new_conf_req(bytes)` |
| `CompletionRequest` | `cmpl_id()`, `completer_id()`, `cmpl_stat()`, `bcm()`, `byte_cnt()`, `req_id()`, `requester_id()`, `tag()`, `laddr()` | `new_cmpl_req(bytes)` |
| `MessageRequest` | `req_id()`, `requester_id()`, `tag()`, `msg_code()`, `dw3()`, `dw4()` | `new_msg_req(bytes)` |
| `AtomicRequest` | `op()`, `width()`, `req_id()`, `requester_id()`, `tag()`, `address()`, `operand0()`, `operand1()` | `new_atomic_req(&pkt)` |

> **Note:** All `bytes` parameters accept `impl Into<Vec<u8>>` — you can pass `pkt.data()` (`&[u8]`)
> directly without calling `.to_vec()`. Only `new_mem_req` additionally requires `&TlpFmt`.

### Device IDs

`DeviceID` wraps the 16-bit Requester ID / Completer ID BDF encoding used in
TLP headers:

```rust
use rtlp_lib::DeviceID;

let id = DeviceID::from_u16(0x0218);
assert_eq!(id.bus(), 0x02);
assert_eq!(id.device(), 0x03);
assert_eq!(id.function(), 0x00);
assert_eq!(id.to_u16(), 0x0218);
assert_eq!(format!("{id}"), "02:03.0");

let parsed: DeviceID = "02:03.1".parse().unwrap();
assert_eq!(parsed.to_u16(), 0x0219);
```

Request traits keep their raw `u16` accessors and add parsed helpers such as
`MemRequest::device_id()`, `requester_id()`, and
`CompletionRequest::completer_id()`.

### Atomic-Specific Types

| Type | Variants |
|---|---|
| `AtomicOp` | `FetchAdd`, `Swap`, `CompareSwap` |
| `AtomicWidth` | `W32`, `W64` |

## Error Handling

Every decoding step returns `Result<_, TlpError>`:

| Error | Meaning |
|---|---|
| `InvalidFormat` | The 3-bit Fmt field does not match any known format |
| `InvalidType` | The 5-bit Type field does not match any known encoding |
| `UnsupportedCombination` | Valid Fmt + Type individually, but not a legal pair (e.g. DMWr with NoData) |
| `InvalidLength` | Byte slice is too short for the expected header + payload |
| `NotImplemented` | Feature exists in the API but is not yet implemented (e.g. `TlpPacketHeader::new` with `Flit`) |
| `MissingMandatoryOhc` | Flit TLP type requires an OHC word that was absent (IOWr/CfgWr) |

## Tests

The crate has **235 passing tests** in the default feature set (0 ignored):

| Category | File | Passes | Ignored |
|---|---|---|---|
| Unit tests | `src/lib.rs` | 74 | 0 |
| API contract tests | `tests/api_tests.rs` | 80 | 0 |
| DeviceID allocation guard | `tests/device_id_alloc_tests.rs` | 1 | 0 |
| Non-flit integration tests | `tests/non_flit_tests.rs` | 25 | 0 |
| Flit mode tests | `tests/flit_mode_tests.rs` | 45 | 0 |
| Doc tests | `src/lib.rs` | 10 | 0 |

```bash
cargo test                        # run all 235 default-feature tests
cargo test --lib                  # unit tests only
cargo test --test non_flit_tests  # non-flit integration tests only
cargo test --test flit_mode_tests # flit mode tests (all tiers)
cargo test --doc                  # doc examples only
```

See [TESTS.md](TESTS.md) for the full test structure and flit mode tier descriptions.

## Serde Support

Enable the `serde` feature to derive `Serialize`/`Deserialize` on public value types:

```toml
[dependencies]
rtlp-lib = { version = "0.5", features = ["serde"] }
```

**Supported types:** `TlpMode`, `TlpError`, `TlpFmt`, `TlpType`, `DeviceID`, `AtomicOp`, `AtomicWidth`, `FlitTlpType`, `FlitDW0`, `FlitOhcA`

**Not supported:** `TlpPacket` and `TlpPacketHeader` — these contain `TlpHeader`, which uses a bitfield macro that does not support serde derives. If you need to serialize parsed packet data, extract the relevant fields into your own serde-compatible struct.

> **Forward compatibility note:** `TlpMode` and `FlitTlpType` are `#[non_exhaustive]`. New variants added in future versions will serialize correctly on the new version, but deserializing a new variant on an older version will fail. If you persist serialized data to a schema, pin your `rtlp-lib` version accordingly.

## Documentation

- **[docs/api_guide.md](docs/api_guide.md)** — user-facing guide: parsing flow,
  mode dispatch, ownership/lifetimes, error handling, deprecated-API migration,
  and how to test your own code against the library.
- **[TESTS.md](TESTS.md)** — test structure, tier descriptions, FM_* byte-vector
  constants reference, and running individual test suites.
- **[docs/tlp_reference.md](docs/tlp_reference.md)** — byte-level TLP examples for both
  non-flit (PCIe 1–5) and flit mode (PCIe 6.0 Base Spec), DW0 layout diagrams, and test inventory.
- **[tlp.md](tlp.md)** — supplementary PCIe TLP encoding reference.
- **[docs.rs](https://docs.rs/rtlp-lib)** — published rustdoc for the released version.
- `cargo doc --open` — rustdoc for the current local build.

## License

Licensed under the 3-Clause BSD License — see [LICENSE](LICENSE).



