# TLP Reference — rtlp-lib

Byte-level examples and test inventory for both PCIe framing modes.

---

## Contents

1. [DW0 Layout — Non-Flit vs Flit](#1-dw0-layout--non-flit-vs-flit)
2. [Non-Flit TLP Examples (PCIe 1.0–5.0)](#2-non-flit-tlp-examples-pcie-10-50)
3. [Flit-Mode TLP Examples (PCIe 6.0 Base Spec)](#3-flit-mode-tlp-examples-pcie-6x)
4. [Test Inventory](#4-test-inventory)

---

## 1. DW0 Layout — Non-Flit vs Flit

### Non-Flit (PCIe 1.0–5.0)

```text
Byte 0  │ Fmt[2:0] │ Type[4:0]           │
Byte 1  │ T9 │ TC[2:0] │ T8 │ Attr_b2 │ LN │ TH │
Byte 2  │ TD │ EP │ Attr[1:0] │ AT[1:0] │ Length[9:8] │
Byte 3  │ Length[7:0]                     │
```

| Fmt bits | Meaning |
|---|---|
| `0b000` | 3 DW header, no data |
| `0b001` | 4 DW header, no data |
| `0b010` | 3 DW header + payload |
| `0b011` | 4 DW header + payload |
| `0b100` | TLP Prefix |

### Flit Mode (PCIe 6.0 Base Spec)

```text
Byte 0  │ Type[7:0]                       │  ← flat 8-bit type code
Byte 1  │ TC[2:0] │ OHC[4:0]             │  ← OHC presence bitmap
Byte 2  │ TS[2:0] │ Attr[2:0] │ Length[9:8] │
Byte 3  │ Length[7:0]                     │
```

OHC (`Optional Header Content`) — each set bit adds 1 DW extension word after the base header:
- Bit 0 (`OHC-A`): PASID + byte enables — mandatory for IoWrite and CfgWrite0

---

## 2. Non-Flit TLP Examples (PCIe 1.0–5.0)

### Memory Read Request — 32-bit (MemRead3DW)

```text
Byte  │ Value │ Field
──────┼───────┼──────────────────────────────────────
DW0+0 │ 0x00  │ Fmt=000 (3DW no data) | Type=00000 (Memory)
DW0+1 │ 0x00  │ TC=0, T9=0, T8=0
DW0+2 │ 0x00  │ no EP/TD flags
DW0+3 │ 0x01  │ Length = 1 DW
DW1+0 │ 0x00  │ req_id[15:8] = bus 0
DW1+1 │ 0x00  │ req_id[7:0]  = dev 0 / fn 0
DW1+2 │ 0x20  │ tag = 0x20
DW1+3 │ 0x0F  │ last_dw_be=0, first_dw_be=0xF
DW2+0 │ 0xF6  │ address32[31:24]
DW2+1 │ 0x20  │ address32[23:16]
DW2+2 │ 0x00  │ address32[15:8]
DW2+3 │ 0x0C  │ address32[7:0]  → address = 0xF620_000C
```

```rust
let bytes = vec![
    0x00, 0x00, 0x00, 0x01,  // DW0: MemRead 3DW, length=1
    0x00, 0x00, 0x20, 0x0F,  // DW1: req_id=0x0000, tag=0x20, BE=0x0F
    0xF6, 0x20, 0x00, 0x0C,  // DW2: address32 = 0xF620_000C
];
let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
assert_eq!(pkt.tlp_type().unwrap(), TlpType::MemReadReq);
let mr = new_mem_req(pkt.data(), &pkt.tlp_format().unwrap()).unwrap();
assert_eq!(mr.address(), 0xF620_000C);
assert_eq!(mr.tag(), 0x20);
```

---

### Memory Write Request — 32-bit (MemWrite3DW)

`Fmt=0b010` (`0x40` in byte 0) + 4 bytes payload.

```text
40 00 00 01   00 00 20 0F   DE AD 00 00   DE AD BE EF
└──── DW0 ─┘ └──── DW1 ─┘ └──── DW2 ─┘ └─ payload ─┘
 Fmt=010      req_id=0x0000  address32=    data DW
 Type=00000   tag=0x20       0xDEAD0000
 Length=1     BE=0x0F
```

```rust
let bytes = vec![
    0x40, 0x00, 0x00, 0x01,  // DW0: MemWrite 3DW, length=1
    0x00, 0x00, 0x20, 0x0F,  // DW1: req_id=0x0000, tag=0x20, BE=0x0F
    0xDE, 0xAD, 0x00, 0x00,  // DW2: address32 = 0xDEAD_0000
    0xDE, 0xAD, 0xBE, 0xEF,  // payload
];
let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
assert_eq!(pkt.tlp_type().unwrap(), TlpType::MemWriteReq);
assert_eq!(pkt.tlp_format().unwrap(), TlpFmt::WithDataHeader3DW);
assert_eq!(pkt.data(), [0x00, 0x00, 0x20, 0x0F, 0xDE, 0xAD, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]);
```

---

### Memory Write Request — 64-bit (MemWrite4DW)

`Fmt=0b011` → byte 0 = `0x60`.

```text
60 00 90 01   BE EF A5 00   00 00 00 01   00 00 00 00   CA FE BA BE
└──── DW0 ─┘ └──── DW1 ─┘ └──── DW2 ─┘ └──── DW3 ─┘ └─ payload ─┘
 Fmt=011      req_id=0xBEEF  addr64 hi     addr64 lo    data DW
 Type=00000   tag=0xA5       0x0000_0001   0x0000_0000
 Length=1     BE=0x00
```

```rust
let bytes = vec![
    0x60, 0x00, 0x90, 0x01,  // DW0: MemWrite 4DW, TC=4, length=1
    0xBE, 0xEF, 0xA5, 0x00,  // DW1: req_id=0xBEEF, tag=0xA5, BE=0x00
    0x00, 0x00, 0x00, 0x01,  // DW2: address64 high = 0x0000_0001
    0x00, 0x00, 0x00, 0x00,  // DW3: address64 low  = 0x0000_0000
    0xCA, 0xFE, 0xBA, 0xBE,  // payload
];
let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
assert_eq!(pkt.tlp_type().unwrap(), TlpType::MemWriteReq);
assert_eq!(pkt.tlp_format().unwrap(), TlpFmt::WithDataHeader4DW);
let mr = new_mem_req(pkt.data(), &pkt.tlp_format().unwrap()).unwrap();
assert_eq!(mr.address(), 0x0000_0001_0000_0000);
```

---

### Configuration Type 0 Write Request

`Fmt=0b010`, `Type=0b00100` → byte 0 = `0x44`.

```text
44 00 00 01   00 01 00 0F   C2 08 00 10   44 33 22 11
└──── DW0 ─┘ └──── DW1 ─┘ └──── DW2 ─┘ └─ payload ─┘
 Fmt=010      req_id=0x0001  bus=0xC2      config data
 Type=00100   tag=0x00       dev=1 fn=0
 CfgWr0       BE=0x0F        reg=4
 Length=1
```

```rust
let bytes = vec![
    0x44, 0x00, 0x00, 0x01,  // DW0: ConfType0WriteReq, length=1
    0x00, 0x01, 0x00, 0x0F,  // DW1: req_id=0x0001, tag=0x00, BE=0x0F
    0xC2, 0x08, 0x00, 0x10,  // DW2: bus=0xC2, dev=1, fn=0, reg=4
    0x44, 0x33, 0x22, 0x11,  // payload (config write data)
];
let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
assert_eq!(pkt.tlp_type().unwrap(), TlpType::ConfType0WriteReq);
let cr = new_conf_req(pkt.data()).unwrap();
assert_eq!(cr.bus_nr(), 0xC2);
assert_eq!(cr.dev_nr(), 1);
```

---

### Completion With Data (CplD)

`Fmt=0b010`, `Type=0b01010` → byte 0 = `0x4A`.

```text
4A 00 20 40   20 01 00 40   12 34 AB 10   DE AD BE EF
└──── DW0 ─┘ └──── DW1 ─┘ └──── DW2 ─┘ └─ payload ─┘
 Fmt=010      cmpl_id=0x2001 req_id=0x1234  data DW
 Type=01010   bcnt=0x040     tag=0xAB
 CplWithData  status=OK      laddr=0x10
 Length=1
```

```rust
let bytes = vec![
    0x4A, 0x00, 0x20, 0x40,  // DW0: CplData, length=1
    0x20, 0x01, 0x00, 0x40,  // DW1: cmpl_id=0x2001, status=0, byte_cnt=0x040
    0x12, 0x34, 0xAB, 0x10,  // DW2: req_id=0x1234, tag=0xAB, laddr=0x10
    0xDE, 0xAD, 0xBE, 0xEF,  // payload (returned data)
];
let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
assert_eq!(pkt.tlp_type().unwrap(), TlpType::CplData);
let cpl = new_cmpl_req(pkt.data()).unwrap();
assert_eq!(cpl.cmpl_id(), 0x2001);
assert_eq!(cpl.req_id(), 0x1234);
assert_eq!(cpl.laddr(), 0x10);
```

---

### FetchAdd AtomicOp — 32-bit

`Fmt=0b010`, `Type=0b01100` → byte 0 = `0x4C`.

```text
4C 00 00 00   AB CD 01 00   00 00 10 00   00 00 00 04
└──── DW0 ─┘ └──── DW1 ─┘ └──── DW2 ─┘ └─ operand ─┘
 Fmt=010      req_id=0xABCD  addr32=        addend=4
 Type=01100   tag=0x01       0x0000_1000
 FetchAdd32   BE=0x00
```

```rust
let bytes = vec![
    0x4C, 0x00, 0x00, 0x00,  // DW0: FetchAdd 3DW
    0xAB, 0xCD, 0x01, 0x00,  // DW1: req_id=0xABCD, tag=0x01, BE=0x00
    0x00, 0x00, 0x10, 0x00,  // DW2: address32 = 0x0000_1000
    0x00, 0x00, 0x00, 0x04,  // operand: addend = 4
];
let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
let ar = new_atomic_req(&pkt).unwrap();
assert_eq!(ar.op(), AtomicOp::FetchAdd);
assert_eq!(ar.address(), 0x0000_1000);
assert_eq!(ar.operand0(), 4);
```

---

## 3. Flit-Mode TLP Examples (PCIe 6.0 Base Spec)

### Quick Reference

| Constant | Type code | Base hdr | OHC | Payload | Total |
|---|---:|---:|---:|---:|---:|
| `FM_NOP` | `0x00` | 1 DW | 0 | 0 DW | 4 B |
| `FM_MRD32_MIN` | `0x03` | 3 DW | 0 | 0 DW | 12 B |
| `FM_MRD32_A1_PASID` | `0x03` | 3 DW | 1 | 0 DW | 16 B |
| `FM_MWR32_MIN` | `0x40` | 3 DW | 0 | 1 DW | 16 B |
| `FM_MWR32_PARTIAL_A1` | `0x40` | 3 DW | 1 | 1 DW | 20 B |
| `FM_IOWR_A2` | `0x42` | 3 DW | 1 | 1 DW | 20 B |
| `FM_CFGWR0_A3` | `0x44` | 3 DW | 1 | 1 DW | 20 B |
| `FM_UIOMRD64_MIN` | `0x22` | 4 DW | 0 | 0 DW | 16 B |
| `FM_UIOMWR64_MIN` | `0x61` | 4 DW | 0 | 2 DW | 24 B |
| `FM_MSG_TO_RC` | `0x30` | 3 DW | 0 | 0 DW | 12 B |
| `FM_MSGD_TO_RC` | `0x70` | 3 DW | 0 | 1 DW | 16 B |
| `FM_FETCHADD32` | `0x4C` | 3 DW | 0 | 1 DW | 16 B |
| `FM_CAS32` | `0x4E` | 3 DW | 0 | 2 DW | 20 B |
| `FM_DMWR32` | `0x5B` | 3 DW | 0 | 1 DW | 16 B |
| `FM_STREAM_FRAGMENT_0` | mixed | mixed | mixed | mixed | 48 B |
| `FM_LOCAL_PREFIX_ONLY` | `0x8D` | 1 DW | 0 | 0 DW | 4 B |

All constants are defined in `tests/flit_mode_tests.rs`.

---

### FM_NOP — NOP (1 DW)

```text
00 00 00 00
```

```rust
let pkt = TlpPacket::new(vec![0x00, 0x00, 0x00, 0x00], TlpMode::Flit).unwrap();
assert_eq!(pkt.flit_type(), Some(FlitTlpType::Nop));
assert!(pkt.data().is_empty());
```

---

### FM_MRD32_MIN — Memory Read 32-bit (12 B)

Length=1 DW but read requests carry **no payload**.

```text
03 00 00 01   00 00 00 00   00 00 00 00
└──── DW0 ─┘ └──── DW1 ─┘ └──── DW2 ─┘
 Type=MRd32   req/addr      req/addr
 TC=0 OHC=0
 Length=1
```

```rust
let pkt = TlpPacket::new(vec![
    0x03, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
], TlpMode::Flit).unwrap();
assert_eq!(pkt.flit_type(), Some(FlitTlpType::MemRead32));
assert!(pkt.data().is_empty()); // read request — no payload
```

---

### FM_MRD32_A1_PASID — Memory Read with OHC-A1 (16 B)

OHC-A1 word carries PASID=`0x12345`, fdwbe=`0xF`, ldwbe=`0x0`.

```text
03 01 00 01   00 00 00 00   00 00 00 00   01 23 45 0F
└──── DW0 ─┘ └──── DW1 ─┘ └──── DW2 ─┘ └─ OHC-A1 ─┘
 Type=MRd32   base header   base header   PASID=0x12345
 OHC=0x01                               fdwbe=0xF
```

```rust
let dw0 = FlitDW0::from_dw0(&[0x03, 0x01, 0x00, 0x01]).unwrap();
assert_eq!(dw0.ohc_count(), 1);
let ohc = FlitOhcA::from_bytes(&[0x01, 0x23, 0x45, 0x0F]).unwrap();
assert_eq!(ohc.pasid, 0x12345);
assert_eq!(ohc.fdwbe, 0xF);
```

---

### FM_MWR32_MIN — Memory Write 32-bit (16 B)

```text
40 00 00 01   00 00 00 00   00 00 00 00   DE AD BE EF
└──── DW0 ─┘ └──── DW1 ─┘ └──── DW2 ─┘ └─ payload ─┘
 Type=MWr32
 OHC=0
 Length=1
```

```rust
let pkt = TlpPacket::new(vec![
    0x40, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF,
], TlpMode::Flit).unwrap();
assert_eq!(pkt.flit_type(), Some(FlitTlpType::MemWrite32));
assert_eq!(pkt.data(), [0xDE, 0xAD, 0xBE, 0xEF]);
```

---

### FM_MWR32_PARTIAL_A1 — Partial Memory Write with OHC-A1 (20 B)

OHC-A1 with fdwbe=`0x3` signals a partial first-DW write.

```text
40 01 00 01   00 00 00 00   00 00 00 00   00 00 00 03   AA BB CC DD
 Type=MWr32   base header   base header   fdwbe=3       payload
 OHC=0x01
```

---

### FM_IOWR_A2 — I/O Write (mandatory OHC-A2) (20 B)

IoWrite **requires** OHC bit 0 set or `TlpPacket::new` returns `MissingMandatoryOhc`.

```text
42 01 00 01   00 00 00 00   00 00 00 00   00 00 00 0F   10 20 30 40
 Type=IOWr    base header   base header   fdwbe=0xF     data
 OHC=0x01 ← mandatory
```

```rust
// Missing OHC → error
let bad = vec![0x42, 0x00, 0x00, 0x01, 0,0,0,0, 0,0,0,0];
assert_eq!(TlpPacket::new(bad, TlpMode::Flit).err().unwrap(),
           TlpError::MissingMandatoryOhc);
```

---

### FM_CFGWR0_A3 — Config Type 0 Write (mandatory OHC-A3) (20 B)

```text
44 01 00 01   00 00 00 00   00 00 00 00   00 00 00 0F   44 33 22 11
 Type=CfgWr0  base header   base header   fdwbe=0xF     config data
 OHC=0x01 ← mandatory
```

---

### FM_UIOMRD64_MIN — UIO Memory Read 64-bit (16 B)

4 DW base header (64-bit address). No payload even with Length=2.

```text
22 00 00 02   00 00 00 00   00 00 00 00   00 00 00 00
 Type=UIOrd   DW1           DW2           DW3
 OHC=0
 Length=2 ← completion hint, not request payload
```

---

### FM_UIOMWR64_MIN — UIO Memory Write 64-bit (24 B)

4 DW header + 2 DW payload.

```text
61 00 00 02   00 00 00 00   00 00 00 00   00 00 00 00   11 22 33 44   55 66 77 88
 Type=UIOMWr  DW1           DW2           DW3           payload       payload
```

```rust
let pkt = TlpPacket::new(FM_UIOMWR64_MIN.to_vec(), TlpMode::Flit).unwrap();
assert_eq!(pkt.flit_type(), Some(FlitTlpType::UioMemWrite));
assert_eq!(pkt.data(), [0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88]);
```

---

### FM_FETCHADD32 — FetchAdd AtomicOp (16 B)

```text
4C 00 00 01   00 00 00 00   00 00 00 00   01 00 00 00
 Type=FAdd32  base header   base header   addend=0x01000000
```

---

### FM_CAS32 — Compare-and-Swap AtomicOp (20 B)

2 DW payload: compare value then swap value.

```text
4E 00 00 02   00 00 00 00   00 00 00 00   11 11 11 11   22 22 22 22
 Type=CAS32   base header   base header   compare=0x1111_1111  swap=0x2222_2222
```

```rust
let pkt = TlpPacket::new(FM_CAS32.to_vec(), TlpMode::Flit).unwrap();
let data = pkt.data();
let compare = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
let swap    = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
assert_eq!(compare, 0x1111_1111);
assert_eq!(swap,    0x2222_2222);
```

---

### FM_DMWR32 — Deferrable Memory Write (16 B)

```text
5B 00 00 01   00 00 00 00   00 00 00 00   C0 FF EE 00
 Type=DMWr32  base header   base header   payload
```

---

### FM_STREAM_FRAGMENT_0 — Packed stream of 4 TLPs (48 B)

```text
Offset  0: 00 00 00 00                           (NOP,    4 B)
Offset  4: 03 00 00 01  00 00 00 00  00 00 00 00 (MRd32, 12 B)
Offset 16: 40 00 00 01  00 00 00 00  00 00 00 00  DE AD BE EF (MWr32, 16 B)
Offset 32: 22 00 00 02  00 00 00 00  00 00 00 00  00 00 00 00 (UIOMRd, 16 B)
```

```rust
let entries: Vec<_> = FlitStreamWalker::new(&FM_STREAM_FRAGMENT_0)
    .collect::<Result<Vec<_>, _>>().unwrap();
assert_eq!(entries[0], (0,  FlitTlpType::Nop,       4));
assert_eq!(entries[1], (4,  FlitTlpType::MemRead32, 12));
assert_eq!(entries[2], (16, FlitTlpType::MemWrite32, 16));
assert_eq!(entries[3], (32, FlitTlpType::UioMemRead, 16));
```

---

### FM_LOCAL_PREFIX_ONLY — Local TLP Prefix (4 B)

```text
8D 00 00 00
 Type=LocalTlpPrefix
 1 DW base header, no payload
```

---

## 4. Test Inventory

### Unit Tests — `src/lib.rs` (56 tests)

Internal tests using private `TlpHeader` bitfield.

| Category | Count | What's covered |
|---|---:|---|
| Bitfield field extraction | 3 | all-zeros, all-ones, bit-position verification |
| TLP type decode — happy path | 2 | all 21 TlpType variants, all legal Fmt×Type pairs |
| TLP type decode — errors | 3 | `InvalidFormat` (3 reserved Fmt values), `InvalidType`, `UnsupportedCombination` |
| DMWr specific | 5 | 3DW/4DW decode, NoData rejection |
| Atomic operand parsing | 10 | FetchAdd/Swap/CAS W32+W64, bad operand length |
| Completion `laddr` | 4 | all 7 bits, bit-6 regression |
| Message DW3/DW4 | 4 | upper-16-bit preservation |
| Flit mode | 8 | NOP, MRd32, MWr32, flit/non-flit None, TlpPacketHeader NotImplemented |
| `TlpMode` traits | 2 | Debug/PartialEq, Copy/Clone |
| `mode()` | 1 | returns NonFlit/Flit correctly |
| `is_non_posted()` | 4 | all 21 TlpType variants exhaustive check |
| Debug impls | 3 | TlpPacket, TlpPacketHeader, flit variant |

---

### API Contract Tests — `tests/api_tests.rs` (77 tests)

Public API surface verification — fails to **compile** if any type or function is removed.

| Category | Count | What's covered |
|---|---:|---|
| `TlpError` | 6 | all 6 variants, Debug, PartialEq, Display, `std::error::Error` |
| `TlpMode` | 4 | variants, Debug/Clone/Copy/PartialEq, flit `new()`, header NotImplemented |
| `TlpFmt` | 3 | variants, `TryFrom<u32>` valid/invalid |
| `TlpType` | 3 | all 21 variants, Debug, PartialEq |
| `TlpPacket` | 11 | constructor, `tlp_type/format/data/mode()`, error paths |
| `TlpPacketHeader` | 2 | constructor, `tlp_type()` |
| `MemRequest` trait | 5 | 3DW/4DW structs, method return types |
| `ConfigurationRequest` trait | 3 | struct, trait, method types |
| `CompletionRequest` trait | 3 | struct, trait, method types |
| `MessageRequest` trait | 3 | struct, trait, method types |
| `AtomicOp` / `AtomicWidth` | 4 | variants, Debug, PartialEq |
| Factory functions | 6 | `new_mem_req`, `new_conf_req`, `new_cmpl_req`, `new_msg_req`, `new_atomic_req` |
| API stability | 1 | all public types importable (compile-time contract) |
| `mode()` | 2 | correct value, consistent with `flit_type().is_some()` |
| Deprecated aliases | 5 | `get_tlp_type/format/flit_type/header/data` delegate correctly |
| `Debug` trait | 3 | TlpPacket, TlpPacket (flit), TlpPacketHeader |
| Edge cases | 3 | minimum size, empty data, payload preservation |

---

### Non-Flit Integration Tests — `tests/non_flit_tests.rs` (25 tests)

End-to-end tests via the public API using `TlpMode::NonFlit`.

| Test | What it verifies |
|---|---|
| `test_tlp_packet` | Header/data split, ConfType0ReadReq decode |
| `test_complreq_trait` | All 7 CompletionRequest fields |
| `test_configreq_trait` | All 7 ConfigurationRequest fields |
| `memreq_tag_field_3dw_and_4dw` | Tag extraction from 3DW and 4DW headers |
| `memreq_3dw_address_field` | 32-bit address parsing |
| `memreq_4dw_address_field` | 64-bit address parsing |
| `tlp_packet_header_constructs_from_bytes` | TlpPacketHeader::new |
| `test_tlp_packet_invalid_type` | InvalidType error propagation |
| `atomic_fetchadd_3dw_32_parses_operands` | FetchAdd W32 operand |
| `atomic_swap_4dw_64_parses_operands` | Swap W64 operand |
| `atomic_cas_3dw_32_parses_operands` | CAS W32 two operands |
| `atomic_fetchadd_rejects_invalid_operand_length` | Bad operand size → InvalidLength |
| `dmwr32/64_decode_via_tlppacket` | DMWr type and format decode |
| `dmwr_rejects_nodata_formats` | DMWr with NoData → UnsupportedCombination |
| `dmwr_is_non_posted` | DMWr is non-posted; MemWrite is posted |
| `msg_req_*` (4 tests) | Message routing subtypes, MsgReqData, end-to-end |
| `local/end_to_end_tlp_prefix_*` (3 tests) | TLP Prefix decode, Type[4] discrimination |
| `prefix_types_are_not_non_posted` | Prefix is_non_posted() = false |

---

### Flit Mode Tests — `tests/flit_mode_tests.rs` (45 tests, 0 ignored)

Tiered test suite covering all flit mode features. All tiers implemented in v0.5.0.

| Tier | Tests | What's covered |
|---|---:|---|
| 0 — Regression guards | 4 | `TlpPacket::new(Flit)` works; `TlpPacketHeader::new(Flit)` returns NotImplemented; parser-driven type + OHC checks for all FM_* constants |
| 1 — DW0 field extraction | 8 | `FlitDW0::from_dw0()` for each FM_* vector; TC, OHC, Length, ts, attr fields |
| 2 — Header + size validation | 15 | `base_header_dw()`, `ohc_count()`, `total_bytes()`, `has_data_payload()`, `is_read_request()`; Length=0 encodes 1024 DW |
| 3 — OHC parsing + mandatory OHC | 6 | `FlitOhcA::from_bytes()` PASID/fdwbe/ldwbe; IoWrite + CfgWrite0 require OHC (positive + negative) |
| 4 — Stream walking | 3 | `FlitStreamWalker` over `FM_STREAM_FRAGMENT_0`; truncated stream error; end-of-stream None |
| 5 — End-to-end pipeline | 10 | `TlpPacket::new(bytes, TlpMode::Flit)` for 8 FM_* vectors; operand values in FetchAdd + CAS payloads |

---

### Documentation Tests — `src/lib.rs` (9 tests)

Doc examples embedded in public API comments — verified by `cargo test --doc`.

| Doc example | What it demonstrates |
|---|---|
| `TlpPacket` struct | Full non-flit decode pipeline |
| `TlpPacket::mode()` | Mode dispatch pattern with `match pkt.mode()` |
| `TlpType::is_posted()` | Posted/non-posted classification |
| `new_mem_req` | MemRequest trait from `pkt.data()` |
| `new_conf_req` | ConfigurationRequest from `pkt.data()` |
| `new_cmpl_req` | CompletionRequest trait usage |
| `new_msg_req` | MessageRequest trait usage |
| `new_atomic_req` | Full atomic operand parsing |
| `FlitStreamWalker` | Stream walking with NOP vector |


