# Supported TLP Types — Encoding & Parsing Reference

This document lists every TLP type that `rtlp-lib` can currently decode,
the DW0 encoding used to identify it, which header fields the library
extracts, and a byte-level example taken from the test suite.

All byte values are big-endian (MSB-first within each DW), matching how
the library interprets raw buffers.

---

## DW0 Header — Common to All TLPs

```
Byte 0              Byte 1              Byte 2          Byte 3
┌───────┬───────┐  ┌──┬───┬──┬──┬──┬──┐ ┌──┬──┬──┬──┐  ┌──────────┐
│Fmt[2:0]│Typ[4:0]│  │T9│TC │T8│Ab│LN│TH│ │TD│EP│At│AT│  │Length[9:0]│
│ 3 bits │ 5 bits │  │  │3b │  │  │  │  │ │  │  │2b│2b│  │ 10 bits  │
└───────┴───────┘  └──┴───┴──┴──┴──┴──┘ └──┴──┴──┴──┘  └──────────┘
```

| Fmt bits | Name |
|---|---|
| `000` | 3DW header, no data |
| `001` | 4DW header, no data |
| `010` | 3DW header, with data |
| `011` | 4DW header, with data |
| `100` | TLP Prefix |

The **Type** field (5 bits) combined with the **Fmt** determines the `TlpType`.

---

## 1. Memory Requests

**Type encoding:** `00000` (5'b00000)

| Fmt | TlpType | Posted | Description |
|---|---|---|---|
| `000` | `MemReadReq` | No | Memory Read, 32-bit address |
| `001` | `MemReadReq` | No | Memory Read, 64-bit address |
| `010` | `MemWriteReq` | Yes | Memory Write, 32-bit address |
| `011` | `MemWriteReq` | Yes | Memory Write, 64-bit address |

**Trait:** `MemRequest` — fields: `req_id()`, `tag()`, `address()`, `ldwbe()`, `fdwbe()`

**Constructor:** `new_mem_req(packet.get_data(), &fmt)`

### Parsed header fields (DW1–DW2 for 3DW, DW1–DW3 for 4DW)

```
3DW (MemRequest3DW):
  Bits [15:0]   Requester ID
  Bits [23:16]  Tag
  Bits [27:24]  Last DW BE
  Bits [31:28]  First DW BE
  Bits [63:32]  Address (32-bit)

4DW (MemRequest4DW):
  Bits [15:0]   Requester ID
  Bits [23:16]  Tag
  Bits [27:24]  Last DW BE
  Bits [31:28]  First DW BE
  Bits [95:32]  Address (64-bit)
```

### Example: MemRead 3DW (from tests)

```
DW0: 00 00 20 01    Fmt=000, Type=00000 → MemReadReq, Length=1
DW1: 00 00 20 0F    req_id=0x0000, tag=0x20, BE=0x0F
DW2: F6 20 00 0C    address32=0xF620000C
```

```rust
let mr = MemRequest3DW([0x00, 0x00, 0x20, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);
assert_eq!(mr.tag(),     0x20);
assert_eq!(mr.address(), 0xF620000C);
```

### Example: MemWrite 4DW (from tests)

```
DW0: 60 00 90 01    Fmt=011, Type=00000 → MemWriteReq (64-bit)
DW1: 00 00 20 0F    req_id=0x0000, tag=0x20, BE=0x0F
DW2: 00 00 01 7F    address64 high
DW3: C0 00 00 00    address64 low → 0x0000017FC0000000
```

```rust
let mr = MemRequest4DW([0x00, 0x00, 0x20, 0x0F,
                        0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00]);
assert_eq!(mr.address(), 0x17fc0000000);
```

---

## 2. Memory Read Lock Requests

**Type encoding:** `00001` (5'b00001)

| Fmt | TlpType | Description |
|---|---|---|
| `000` | `MemReadLockReq` | Locked Memory Read, 32-bit |
| `001` | `MemReadLockReq` | Locked Memory Read, 64-bit |

WithData formats (`010`, `011`) are **rejected** → `UnsupportedCombination`.

**Trait:** `MemRequest` (same as Memory Requests)

---

## 3. IO Requests

**Type encoding:** `00010` (5'b00010)

| Fmt | TlpType | Description |
|---|---|---|
| `000` | `IOReadReq` | IO Read (3DW only) |
| `010` | `IOWriteReq` | IO Write (3DW only) |

4DW formats (`001`, `011`) are **rejected** → `UnsupportedCombination`.

**Trait:** `MemRequest` — IO requests share the same 3DW layout as 32-bit memory requests.

---

## 4. Configuration Requests

### Type 0

**Type encoding:** `00100` (5'b00100)

| Fmt | TlpType |
|---|---|
| `000` | `ConfType0ReadReq` |
| `010` | `ConfType0WriteReq` |

### Type 1

**Type encoding:** `00101` (5'b00101)

| Fmt | TlpType |
|---|---|
| `000` | `ConfType1ReadReq` |
| `010` | `ConfType1WriteReq` |

4DW formats are **rejected** for both Config types.

**Trait:** `ConfigurationRequest` — fields: `req_id()`, `tag()`, `bus_nr()`, `dev_nr()`, `func_nr()`, `ext_reg_nr()`, `reg_nr()`

**Constructor:** `new_conf_req(packet.get_data(), &fmt)`

### Parsed header fields (DW1–DW2, always 3DW)

```
  Bits [15:0]   Requester ID
  Bits [23:16]  Tag
  Bits [27:24]  Last DW BE
  Bits [31:28]  First DW BE
  Bits [39:32]  Bus Number
  Bits [44:40]  Device Number
  Bits [47:45]  Function Number
  Bits [55:52]  Ext Register Number
  Bits [61:56]  Register Number
```

### Example (from tests)

```rust
let conf_req = ConfigRequest([0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);
assert_eq!(conf_req.req_id(),     0x2001);
assert_eq!(conf_req.tag(),        0xFF);
assert_eq!(conf_req.bus_nr(),     0xC2);
assert_eq!(conf_req.dev_nr(),     0x10);
assert_eq!(conf_req.func_nr(),    0x01);
assert_eq!(conf_req.ext_reg_nr(), 0x0F);
assert_eq!(conf_req.reg_nr(),     0x04);
```

---

## 5. Completions

**Type encoding:** `01010` (Completion) / `01011` (Completion Locked)

| Type | Fmt | TlpType |
|---|---|---|
| `01010` | `000` | `Cpl` |
| `01010` | `010` | `CplData` |
| `01011` | `000` | `CplLocked` |
| `01011` | `010` | `CplDataLocked` |

4DW formats are **rejected** for completions.

**Trait:** `CompletionRequest` — fields: `cmpl_id()`, `cmpl_stat()`, `bcm()`, `byte_cnt()`, `req_id()`, `tag()`, `laddr()`

**Constructor:** `new_cmpl_req(packet.get_data(), &fmt)`

### Parsed header fields (DW1–DW2, always 3DW)

```
  Bits [15:0]   Completer ID
  Bits [18:16]  Completion Status
  Bits [19]     BCM
  Bits [31:20]  Byte Count
  Bits [47:32]  Requester ID
  Bits [55:48]  Tag
  Bits [63:58]  Lower Address
```

### Example (from tests)

```rust
let cmpl = CompletionReqDW23([0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);
assert_eq!(cmpl.cmpl_id(),   0x2001);
assert_eq!(cmpl.cmpl_stat(), 0x7);
assert_eq!(cmpl.bcm(),       0x1);
assert_eq!(cmpl.byte_cnt(),  0xF00);
assert_eq!(cmpl.req_id(),    0xC281);
assert_eq!(cmpl.tag(),       0xFF);
assert_eq!(cmpl.laddr(),     0x10);
```

---

## 6. Message Requests

**Type encoding:** varies by routing subtype (the library accepts all message type codes)

| Fmt | TlpType |
|---|---|
| `000`/`001` | `MsgReq` (no data) |
| `010`/`011` | `MsgReqData` (with data) |

**Trait:** `MessageRequest` — fields: `req_id()`, `tag()`, `msg_code()`, `dw3()`, `dw4()`

**Constructor:** `new_msg_req(packet.get_data(), &fmt)`

### Parsed header fields (DW1–DW4)

```
  Bits [15:0]   Requester ID
  Bits [23:16]  Tag
  Bits [31:24]  Message Code
  Bits [63:32]  DW3 (varies by message code)
  Bits [96:64]  DW4 (varies by message code)
```

---

## 7. Atomic Operation Requests

Three atomic operations are supported, each with its own type encoding:

| Type encoding | TlpType | Operation |
|---|---|---|
| `01100` (5'b01100) | `FetchAddAtomicOpReq` | Fetch and Add |
| `01101` (5'b01101) | `SwapAtomicOpReq` | Unconditional Swap |
| `01110` (5'b01110) | `CompareSwapAtomicOpReq` | Compare and Swap |

All three require **WithData** format. NoData formats are **rejected**.

| Fmt | Address width | Operand width |
|---|---|---|
| `010` (3DW w/ data) | 32-bit | 32-bit (W32) |
| `011` (4DW w/ data) | 64-bit | 64-bit (W64) |

**Trait:** `AtomicRequest` — fields: `op()`, `width()`, `req_id()`, `tag()`, `address()`, `operand0()`, `operand1()`

**Constructor:** `new_atomic_req(&pkt)` — takes a `&TlpPacket`, returns `Result<Box<dyn AtomicRequest>, TlpError>`

### Operand layout in payload (after header DWs)

| Operation | Operands | Payload size (W32) | Payload size (W64) |
|---|---|---|---|
| FetchAdd | `operand0` = addend | 4 bytes | 8 bytes |
| Swap | `operand0` = new value | 4 bytes | 8 bytes |
| CompareSwap | `operand0` = compare, `operand1` = swap | 8 bytes | 16 bytes |

### Example: FetchAdd 32-bit (3DW)

```
DW0: 4C 00 00 00    Fmt=010, Type=01100 → FetchAddAtomicOpReq
DW1: 12 34 56 00    req_id=0x1234, tag=0x56
DW2: 89 AB CD EF    address32=0x89ABCDEF
OP:  DE AD BE EF    operand0=0xDEADBEEF (addend, 32-bit)
```

```rust
let pkt = mk_pkt(0b010, 0b01100, &[
    0x12, 0x34, 0x56, 0x00,   // req_id, tag, BE
    0x89, 0xAB, 0xCD, 0xEF,   // address32
    0xDE, 0xAD, 0xBE, 0xEF,   // operand (W32)
]);
let a = new_atomic_req(&pkt).unwrap();
assert_eq!(a.op(),       AtomicOp::FetchAdd);
assert_eq!(a.width(),    AtomicWidth::W32);
assert_eq!(a.req_id(),   0x1234);
assert_eq!(a.tag(),      0x56);
assert_eq!(a.address(),  0x89ABCDEF);
assert_eq!(a.operand0(), 0xDEADBEEF);
assert_eq!(a.operand1(), None);
```

### Example: Swap 64-bit (4DW)

```
DW0: 6D 00 00 00    Fmt=011, Type=01101 → SwapAtomicOpReq
DW1: BE EF A5 00    req_id=0xBEEF, tag=0xA5
DW2: 11 22 33 44    address64 high
DW3: 55 66 77 88    address64 low → 0x1122334455667788
OP:  01 02 03 04    operand0 high
     05 06 07 08    operand0 low → 0x0102030405060708
```

```rust
let pkt = mk_pkt(0b011, 0b01101, &[
    0xBE, 0xEF, 0xA5, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
]);
let a = new_atomic_req(&pkt).unwrap();
assert_eq!(a.op(),       AtomicOp::Swap);
assert_eq!(a.width(),    AtomicWidth::W64);
assert_eq!(a.address(),  0x1122334455667788);
assert_eq!(a.operand0(), 0x0102030405060708);
assert_eq!(a.operand1(), None);
```

### Example: CompareSwap 32-bit (3DW)

```
DW0: 4E 00 00 00    Fmt=010, Type=01110 → CompareSwapAtomicOpReq
DW1: CA FE 11 00    req_id=0xCAFE, tag=0x11
DW2: 00 00 10 00    address32=0x00001000
OP0: 11 11 22 22    compare=0x11112222
OP1: 33 33 44 44    swap=0x33334444
```

```rust
let pkt = mk_pkt(0b010, 0b01110, &[
    0xCA, 0xFE, 0x11, 0x00,
    0x00, 0x00, 0x10, 0x00,
    0x11, 0x11, 0x22, 0x22,  // compare
    0x33, 0x33, 0x44, 0x44,  // swap
]);
let a = new_atomic_req(&pkt).unwrap();
assert_eq!(a.op(),       AtomicOp::CompareSwap);
assert_eq!(a.width(),    AtomicWidth::W32);
assert_eq!(a.operand0(), 0x11112222);
assert_eq!(a.operand1(), Some(0x33334444));
```

### Error: invalid operand length

```rust
// FetchAdd 3DW expects exactly 12 bytes (8 hdr + 4 operand).
// 14 bytes (8 hdr + 6 bytes) → InvalidLength
let pkt = mk_pkt(0b010, 0b01100, &[
    0x12, 0x34, 0x56, 0x00,
    0x89, 0xAB, 0xCD, 0xEF,
    1, 2, 3, 4, 5, 6,        // 6 bytes — not 4 or 8
]);
assert_eq!(new_atomic_req(&pkt).unwrap_err(), TlpError::InvalidLength);
```

---

## 8. Deferrable Memory Write (DMWr)

**Type encoding:** `11011` (5'b11011)

DMWr is a non-posted write (requires a Completion acknowledgement), defined
by the PCI-SIG ECN. It uses the same `MemRequest` header layout as
standard memory requests.

| Fmt | TlpType | Byte 0 |
|---|---|---|
| `010` (3DW w/ data) | `DeferrableMemWriteReq` | `0x5B` |
| `011` (4DW w/ data) | `DeferrableMemWriteReq` | `0x7B` |

NoData formats (`000`, `001`) are **rejected** → `UnsupportedCombination`.

**Trait:** `MemRequest` (same as memory requests)

**Semantics:** `TlpType::DeferrableMemWriteReq.is_non_posted()` returns `true`
(unlike `MemWriteReq` which is posted).

### Example: DMWr 3DW (from tests)

```
DW0: 5B 00 00 00    Fmt=010, Type=11011 → DeferrableMemWriteReq
DW1: AB CD 42 0F    req_id=0xABCD, tag=0x42, BE=0x0F
DW2: DE AD 00 00    address32=0xDEAD0000
```

```rust
let pkt = TlpPacket::new(vec![
    0x5B, 0x00, 0x00, 0x00,
    0xAB, 0xCD, 0x42, 0x0F,
    0xDE, 0xAD, 0x00, 0x00,
]).unwrap();
assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
let mr = new_mem_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
assert_eq!(mr.req_id(),  0xABCD);
assert_eq!(mr.tag(),     0x42);
assert_eq!(mr.address(), 0xDEAD_0000);
```

### Example: DMWr 4DW (from tests)

```
DW0: 7B 00 00 00    Fmt=011, Type=11011 → DeferrableMemWriteReq
DW1: BE EF A5 00    req_id=0xBEEF, tag=0xA5
DW2: 11 22 33 44    address64 high
DW3: 55 66 77 88    address64 low → 0x1122334455667788
```

```rust
let pkt = TlpPacket::new(vec![
    0x7B, 0x00, 0x00, 0x00,
    0xBE, 0xEF, 0xA5, 0x00,
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
]).unwrap();
assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
let mr = new_mem_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
assert_eq!(mr.address(), 0x1122_3344_5566_7788);
```

---

## 9. TLP Prefixes (decode only)

**Type encoding:** detected via `Fmt = 100` (TlpPrefix)

| TlpType | Description |
|---|---|
| `LocalTlpPrefix` | Local TLP Prefix |
| `EndToEndTlpPrefix` | End-to-End TLP Prefix |

> **Note:** Prefix types are identified in the `TlpType` enum but no field-level
> parsing trait is provided yet. This is a placeholder for future work.

---

## Non-Posted vs Posted Summary

`TlpType::is_non_posted()` returns `true` for types that require a Completion:

| Non-Posted (`true`) | Posted (`false`) |
|---|---|
| `MemReadReq` | `MemWriteReq` |
| `MemReadLockReq` | `MsgReq` |
| `IOReadReq`, `IOWriteReq` | `MsgReqData` |
| `ConfType0ReadReq`, `ConfType0WriteReq` | `Cpl`, `CplData` |
| `ConfType1ReadReq`, `ConfType1WriteReq` | `CplLocked`, `CplDataLocked` |
| `FetchAddAtomicOpReq` | `LocalTlpPrefix` |
| `SwapAtomicOpReq` | `EndToEndTlpPrefix` |
| `CompareSwapAtomicOpReq` | |
| `DeferrableMemWriteReq` | |

---

## DW0 Byte 0 Quick-Reference

The first byte of a TLP encodes `(Fmt << 5) | Type`. Here is a lookup table
for every supported combination:

| Byte 0 | Fmt | Type | TlpType |
|---|---|---|---|
| `0x00` | `000` | `00000` | `MemReadReq` |
| `0x20` | `001` | `00000` | `MemReadReq` (4DW) |
| `0x40` | `010` | `00000` | `MemWriteReq` |
| `0x60` | `011` | `00000` | `MemWriteReq` (4DW) |
| `0x01` | `000` | `00001` | `MemReadLockReq` |
| `0x21` | `001` | `00001` | `MemReadLockReq` (4DW) |
| `0x02` | `000` | `00010` | `IOReadReq` |
| `0x42` | `010` | `00010` | `IOWriteReq` |
| `0x04` | `000` | `00100` | `ConfType0ReadReq` |
| `0x44` | `010` | `00100` | `ConfType0WriteReq` |
| `0x05` | `000` | `00101` | `ConfType1ReadReq` |
| `0x45` | `010` | `00101` | `ConfType1WriteReq` |
| `0x0A` | `000` | `01010` | `Cpl` |
| `0x4A` | `010` | `01010` | `CplData` |
| `0x0B` | `000` | `01011` | `CplLocked` |
| `0x4B` | `010` | `01011` | `CplDataLocked` |
| `0x4C` | `010` | `01100` | `FetchAddAtomicOpReq` |
| `0x6C` | `011` | `01100` | `FetchAddAtomicOpReq` (4DW) |
| `0x4D` | `010` | `01101` | `SwapAtomicOpReq` |
| `0x6D` | `011` | `01101` | `SwapAtomicOpReq` (4DW) |
| `0x4E` | `010` | `01110` | `CompareSwapAtomicOpReq` |
| `0x6E` | `011` | `01110` | `CompareSwapAtomicOpReq` (4DW) |
| `0x5B` | `010` | `11011` | `DeferrableMemWriteReq` |
| `0x7B` | `011` | `11011` | `DeferrableMemWriteReq` (4DW) |
