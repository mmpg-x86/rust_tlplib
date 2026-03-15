# rtlp-lib — Rust TLP Parsing Library

A Rust crate for parsing PCI Express Transaction Layer Packets (TLPs).

Decode raw TLP byte streams into strongly-typed structs and trait objects.
The library handles DW0 header decoding (format + type), per-type field
extraction (requester ID, tag, address, operands, …), and validates
format/type combinations according to the PCIe specification.

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
rtlp-lib = "0.4"
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

let tlp_type   = packet.get_tlp_type().unwrap();
let tlp_format = packet.get_tlp_format().unwrap();

match tlp_type {
    TlpType::MemReadReq | TlpType::MemWriteReq |
    TlpType::MemReadLockReq |
    TlpType::DeferrableMemWriteReq |
    TlpType::IOReadReq | TlpType::IOWriteReq => {
        let mr = new_mem_req(packet.get_data(), &tlp_format).unwrap();
        println!("req_id=0x{:04X}  tag=0x{:02X}  addr=0x{:X}",
                 mr.req_id(), mr.tag(), mr.address());
    }
    TlpType::FetchAddAtomicOpReq |
    TlpType::SwapAtomicOpReq |
    TlpType::CompareSwapAtomicOpReq => {
        let ar = new_atomic_req(&packet).unwrap();
        println!("atomic {:?} operand0=0x{:X}", ar.op(), ar.operand0());
    }
    TlpType::ConfType0ReadReq | TlpType::ConfType0WriteReq |
    TlpType::ConfType1ReadReq | TlpType::ConfType1WriteReq => {
        let cr = new_conf_req(packet.get_data(), &tlp_format);
        println!("config bus={} dev={} func={}",
                 cr.bus_nr(), cr.dev_nr(), cr.func_nr());
    }
    TlpType::Cpl | TlpType::CplData |
    TlpType::CplLocked | TlpType::CplDataLocked => {
        let cpl = new_cmpl_req(packet.get_data(), &tlp_format);
        println!("completion status={}", cpl.cmpl_stat());
    }
    TlpType::MsgReq | TlpType::MsgReqData => {
        let msg = new_msg_req(packet.get_data(), &tlp_format);
        println!("message code=0x{:02X}", msg.msg_code());
    }
    _ => println!("TLP type: {:?}", tlp_type),
}
```

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

### Core Types

| Type | Description |
|---|---|
| `TlpPacket` | Full packet: DW0 header + remaining data bytes |
| `TlpPacketHeader` | DW0-only wrapper with accessor methods for every header field |
| `TlpMode` | Framing mode: `NonFlit` (PCIe 1–5) or `Flit` (PCIe 6.x, stub) |
| `TlpFmt` | Format enum: `NoDataHeader3DW`, `NoDataHeader4DW`, `WithDataHeader3DW`, `WithDataHeader4DW`, `TlpPrefix` |
| `TlpType` | 21-variant enum covering all decoded non-flit TLP types |
| `TlpError` | `InvalidFormat`, `InvalidType`, `UnsupportedCombination`, `InvalidLength`, `NotImplemented`, `MissingMandatoryOhc` |
| `FlitTlpType` | 13-variant enum for PCIe 6.x flit-mode type codes (Tier 1+2) |
| `FlitDW0` | Parsed flit-mode DW0: `tlp_type`, `tc`, `ohc`, `ts`, `attr`, `length` |

### Request Traits and Constructors

| Trait | Fields | Constructor |
|---|---|---|
| `MemRequest` | `address()`, `req_id()`, `tag()`, `ldwbe()`, `fdwbe()` | `new_mem_req(bytes, &fmt)` |
| `ConfigurationRequest` | `req_id()`, `tag()`, `bus_nr()`, `dev_nr()`, `func_nr()`, `ext_reg_nr()`, `reg_nr()` | `new_conf_req(bytes, &fmt)` |
| `CompletionRequest` | `cmpl_id()`, `cmpl_stat()`, `bcm()`, `byte_cnt()`, `req_id()`, `tag()`, `laddr()` | `new_cmpl_req(bytes, &fmt)` |
| `MessageRequest` | `req_id()`, `tag()`, `msg_code()`, `dw3()`, `dw4()` | `new_msg_req(bytes, &fmt)` |
| `AtomicRequest` | `op()`, `width()`, `req_id()`, `tag()`, `address()`, `operand0()`, `operand1()` | `new_atomic_req(&pkt)` |

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
| `NotImplemented` | Feature exists in the API but is not yet implemented (e.g. `TlpMode::Flit`) |
| `MissingMandatoryOhc` | A flit-mode TLP type that requires a specific OHC is missing it |

## Tests

The crate has **166 passing tests** (plus 8 `#[ignore]` flit-mode placeholders):

| Category | File | Passes | Ignored |
|---|---|---|---|
| Unit tests | `src/lib.rs` | 48 | 0 |
| API contract tests | `tests/api_tests.rs` | 64 | 0 |
| Non-flit integration tests | `tests/non_flit_tests.rs` | 16 | 0 |
| Flit mode tests | `tests/flit_mode_tests.rs` | 32 | 8 |
| Doc tests | `src/lib.rs` | 6 | 0 |

```bash
cargo test                        # run all 166 non-ignored tests
cargo test --lib                  # unit tests only
cargo test --test non_flit_tests  # non-flit integration tests only
cargo test --test flit_mode_tests # flit mode Tier 0–3 tests (Tier 4–5 ignored)
cargo test --doc                  # doc examples only
```

See [TESTS.md](TESTS.md) for the full test structure and flit mode tier descriptions.

## Documentation

The documentation of the released version is available on
[docs.rs](https://docs.rs/rtlp-lib).
To generate current documentation locally: `cargo doc --open`

## License

Licensed under the 3-Clause BSD License — see [LICENSE](LICENSE).
