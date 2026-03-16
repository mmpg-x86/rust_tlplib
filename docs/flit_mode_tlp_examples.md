# flit_mode_tlp_examples.md

This file collects **Flit Mode TLP byte vectors** intended for parser-oriented unit tests in `rust_tlplib`.

These examples are **TLP byte streams as they appear inside the TLP region of a PCIe 6.x FLIT**. They are **not full 256-byte FLIT containers** and therefore do **not** include DLP, CRC, or FEC bytes.

## Scope and verification notes

What is checked here:

- Flit Mode uses a fully decoded `Type[7:0]` field.
- The examples below only use public Type encodings that are visible in publicly available PCIe 6.x material.
- `DW0` is encoded as:
  - `Byte 0 = Type[7:0]`
  - `Byte 1 = TC[2:0] | OHC[4:0]`
  - `Byte 2 = TS[2:0] | Attr[2:0] | Length[9:8]`
  - `Byte 3 = Length[7:0]`
- All examples use `TC=0`, `TS=0`, `Attr=0`.
- OHC presence encoding used here:
  - `0x00` => no OHC
  - `0x01` => OHC-A present
- `OHC-A1` is used only when we want explicit byte enables and/or PASID.
- `OHC-A2` is used for I/O Request examples.
- `OHC-A3` is used for Configuration Request examples.
- The UIO examples are included as a **PCIe 6.1+ / UIO-ECN** extension test case.

Important constraint:

Publicly available sources are good enough to validate the **Type code**, **header-base size**, **mandatory OHC rules**, and the **OHC word layout** used below. Public sources do **not** expose every normative bit slice for every non-`DW0` base-header field as completely as the licensed PCIe Base Specification tables do.

Because of that, many examples intentionally keep `DW1` and the route words zero-filled. This still gives you useful, parser-stable vectors for:

- Flit `Type[7:0]` decoding
- header-base size selection
- OHC presence / OHC count handling
- mandatory-OHC validation
- payload-length handling
- total-TLP-size calculation in a packed byte stream

I intentionally did **not** freeze `Cpl/CplD/UIORdCplD` golden vectors here because I could not justify the full non-`DW0` completion-field packing from public material strongly enough for a “golden” unit-test document.

## Conventions used below

- Byte order is the on-the-wire byte order: `DW0`, then `DW1`, then `DW2`, ...
- For address-routed examples, address/route words are often all zero to keep the vector independent of exact non-public field slicing while still remaining parser-usable.
- Payload bytes are arbitrary and chosen for easy visual recognition.

## Quick reference

| Name | Type | Base header | OHC | Payload | Total bytes | Notes |
|---|---:|---:|---:|---:|---:|---|
| `FM_NOP` | `0x00` | 1 DW | 0 DW | 0 DW | 4 | Flit-mode NOP |
| `FM_MRD32_MIN` | `0x03` | 3 DW | 0 DW | 0 DW | 12 | Minimal 32-bit Memory Read |
| `FM_MRD32_A1_PASID` | `0x03` | 3 DW | 1 DW | 0 DW | 16 | Memory Read with OHC-A1 + PASID |
| `FM_MWR32_MIN` | `0x40` | 3 DW | 0 DW | 1 DW | 16 | Minimal 32-bit Memory Write |
| `FM_MWR32_PARTIAL_A1` | `0x40` | 3 DW | 1 DW | 1 DW | 20 | Partial-byte Memory Write using OHC-A1 |
| `FM_IOWR_A2` | `0x42` | 3 DW | 1 DW | 1 DW | 20 | I/O Write, mandatory OHC-A2 |
| `FM_CFGWR0_A3` | `0x44` | 3 DW | 1 DW | 1 DW | 20 | Type0 Config Write, mandatory OHC-A3 |
| `FM_UIOMRD64_MIN` | `0x22` | 4 DW | 0 DW | 0 DW | 16 | UIO Memory Read, 64-bit header |
| `FM_UIOMWR64_MIN` | `0x61` | 4 DW | 0 DW | 2 DW | 24 | UIO Memory Write, 64-bit header |
| `FM_MSG_TO_RC` | `0x30` | 3 DW | 0 DW | 0 DW | 12 | Message routed to RC |
| `FM_MSGD_TO_RC` | `0x70` | 3 DW | 0 DW | 1 DW | 16 | Message with Data routed to RC |
| `FM_FETCHADD32` | `0x4C` | 3 DW | 0 DW | 1 DW | 16 | 32-bit FetchAdd AtomicOp |
| `FM_CAS32` | `0x4E` | 3 DW | 0 DW | 2 DW | 20 | 32-bit Compare-and-Swap AtomicOp |
| `FM_DMWR32` | `0x5B` | 3 DW | 0 DW | 1 DW | 16 | 32-bit Deferrable Memory Write |
| `FM_STREAM_FRAGMENT_0` | mixed | mixed | mixed | mixed | 48 | Back-to-back TLP stream fragment |

---

## 1) `FM_NOP`

**What it is**

A Flit Mode `NOP` TLP. Useful as the smallest possible header-base object in a packed stream.

- Type: `NOP`
- Type code: `0x00`
- Base header: `1 DW`
- Length: `0 DW`
- OHC: none

**Bytes**

```text
00 00 00 00
```

**Rust**

```rust
pub const FM_NOP: [u8; 4] = [
    0x00, 0x00, 0x00, 0x00,
];
```

**Suggested parser checks**

- flit type == `NOP`
- base header size == `1 DW`
- no payload
- total size == `4 bytes`

---

## 2) `FM_MRD32_MIN`

**What it is**

A minimal **32-bit Memory Read Request** with `Length=1 DW`, no OHC, and zero-filled route/requester fields.

This is useful for checking that a read request with non-zero `Length` still has **no data payload**.

- Type: `MRd` (32-bit)
- Type code: `0x03`
- Base header: `3 DW`
- Length: `1 DW`
- OHC: none

**Bytes**

```text
03 00 00 01  00 00 00 00  00 00 00 00
```

**Rust**

```rust
pub const FM_MRD32_MIN: [u8; 12] = [
    0x03, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];
```

**Suggested parser checks**

- flit type == `MRd32`
- base header size == `3 DW`
- OHC count == `0`
- length field == `1 DW`
- payload length == `0 bytes`
- total size == `12 bytes`

---

## 3) `FM_MRD32_A1_PASID`

**What it is**

A 32-bit Memory Read Request carrying **OHC-A1**.

This vector is useful because it exercises:

- `OHC-A` presence in `DW0`
- `OHC-A1` parsing
- PASID extraction
- explicit byte-enable extraction

Here the OHC-A1 word is encoded as:

- flags (`NW/PV/PMR/ER`) = `0`
- PASID = `0x12345`
- First DW BE = `0xF`
- Last DW BE = `0x0`

**Bytes**

```text
03 01 00 01  00 00 00 00  00 00 00 00  01 23 45 0F
```

**Rust**

```rust
pub const FM_MRD32_A1_PASID: [u8; 16] = [
    0x03, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x23, 0x45, 0x0F,
];
```

**Suggested parser checks**

- flit type == `MRd32`
- OHC-A present
- OHC-A1 PASID == `0x12345`
- first DW BE == `0xF`
- last DW BE == `0x0`
- total size == `16 bytes`

---

## 4) `FM_MWR32_MIN`

**What it is**

A minimal **32-bit Memory Write Request** with a single `DW` payload and no OHC.

Because `OHC-A1` is absent, this is the clean “default full-byte-enable” write case.

- Type: `MWr` (32-bit)
- Type code: `0x40`
- Base header: `3 DW`
- Length: `1 DW`
- OHC: none
- Payload: `DE AD BE EF`

**Bytes**

```text
40 00 00 01  00 00 00 00  00 00 00 00  DE AD BE EF
```

**Rust**

```rust
pub const FM_MWR32_MIN: [u8; 16] = [
    0x40, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF,
];
```

**Suggested parser checks**

- flit type == `MWr32`
- base header size == `3 DW`
- payload length == `4 bytes`
- total size == `16 bytes`

---

## 5) `FM_MWR32_PARTIAL_A1`

**What it is**

A 32-bit Memory Write Request with **OHC-A1** used to carry explicit byte enables for a **partial first-DW write**.

`OHC-A1 = 00 00 00 03` means:

- PASID = `0`
- First DW BE = `0x3`
- Last DW BE = `0x0`

This is a good parser test for “Memory Request + OHC-A1 present”.

**Bytes**

```text
40 01 00 01  00 00 00 00  00 00 00 00  00 00 00 03  AA BB CC DD
```

**Rust**

```rust
pub const FM_MWR32_PARTIAL_A1: [u8; 20] = [
    0x40, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03,
    0xAA, 0xBB, 0xCC, 0xDD,
];
```

**Suggested parser checks**

- flit type == `MWr32`
- OHC-A present
- OHC-A1 first DW BE == `0x3`
- payload length == `4 bytes`
- total size == `20 bytes`

---

## 6) `FM_IOWR_A2`

**What it is**

An **I/O Write Request** with the required **OHC-A2**.

This is an important validation case because **I/O Requests require OHC-A2** in Flit Mode.

Here the OHC-A2 word is:

- reserved bytes = `0`
- Last DW BE = `0x0`
- First DW BE = `0xF`

**Bytes**

```text
42 01 00 01  00 00 00 00  00 00 00 00  00 00 00 0F  10 20 30 40
```

**Rust**

```rust
pub const FM_IOWR_A2: [u8; 20] = [
    0x42, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0F,
    0x10, 0x20, 0x30, 0x40,
];
```

**Suggested parser checks**

- flit type == `IOWr`
- OHC-A present
- parser infers `OHC-A2` from I/O Request type
- first DW BE == `0xF`
- total size == `20 bytes`

**Easy negative test mutation**

Set `DW0[1]` from `0x01` to `0x00`. That should become an **invalid I/O Request** because the required `OHC-A2` is missing.

---

## 7) `FM_CFGWR0_A3`

**What it is**

A **Type 0 Configuration Write Request** with required **OHC-A3**.

This is another mandatory-OHC validation vector.

The OHC-A3 word is zero-filled except for full-byte-enable encoding:

- Destination Segment = `0`
- DSV = `0`
- Last DW BE = `0x0`
- First DW BE = `0xF`

**Bytes**

```text
44 01 00 01  00 00 00 00  00 00 00 00  00 00 00 0F  44 33 22 11
```

**Rust**

```rust
pub const FM_CFGWR0_A3: [u8; 20] = [
    0x44, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0F,
    0x44, 0x33, 0x22, 0x11,
];
```

**Suggested parser checks**

- flit type == `CfgWr0`
- OHC-A present
- parser infers `OHC-A3` from Configuration Request type
- total size == `20 bytes`

**Easy negative test mutation**

Set `DW0[1]` from `0x01` to `0x00`. That should become an **invalid Configuration Request** because the required `OHC-A3` is missing.

---

## 8) `FM_UIOMRD64_MIN`

**What it is**

A minimal **UIO Memory Read Request**.

UIO is a newer extension (PCIe 6.1+ / UIO ECN), and address-routed UIO requests use the **64-bit address format**, so this example uses a `4 DW` base header.

This vector is intentionally minimal and zero-filled outside `DW0`.

- Type: `UIOMRd`
- Type code: `0x22`
- Base header: `4 DW`
- Length: `2 DW`
- OHC: none

**Bytes**

```text
22 00 00 02  00 00 00 00  00 00 00 00  00 00 00 00
```

**Rust**

```rust
pub const FM_UIOMRD64_MIN: [u8; 16] = [
    0x22, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];
```

**Suggested parser checks**

- flit type == `UIOMRd`
- base header size == `4 DW`
- no payload even though `Length=2 DW`
- total size == `16 bytes`

---

## 9) `FM_UIOMWR64_MIN`

**What it is**

A minimal **UIO Memory Write Request**.

This is the requested new UIO-family test case for the library.

- Type: `UIOMWr`
- Type code: `0x61`
- Base header: `4 DW`
- Length: `2 DW`
- OHC: none
- Payload: `11 22 33 44 55 66 77 88`

**Bytes**

```text
61 00 00 02  00 00 00 00  00 00 00 00  00 00 00 00  11 22 33 44  55 66 77 88
```

**Rust**

```rust
pub const FM_UIOMWR64_MIN: [u8; 24] = [
    0x61, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
];
```

**Suggested parser checks**

- flit type == `UIOMWr`
- base header size == `4 DW`
- payload length == `8 bytes`
- total size == `24 bytes`

---

## 10) `FM_MSG_TO_RC`

**What it is**

A Message Request with no data, using the **“routed to RC”** flit-mode Type code.

- Type: `Msg, route to RC`
- Type code: `0x30`
- Base header: `3 DW`
- Length: `0 DW`

**Bytes**

```text
30 00 00 00  00 00 00 00  00 00 00 00
```

**Rust**

```rust
pub const FM_MSG_TO_RC: [u8; 12] = [
    0x30, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];
```

**Suggested parser checks**

- flit type == `MsgToRc`
- no payload
- total size == `12 bytes`

---

## 11) `FM_MSGD_TO_RC`

**What it is**

A Message Request **with data**, routed to the RC.

- Type: `MsgD, route to RC`
- Type code: `0x70`
- Base header: `3 DW`
- Length: `1 DW`
- Payload: `AA 55 AA 55`

**Bytes**

```text
70 00 00 01  00 00 00 00  00 00 00 00  AA 55 AA 55
```

**Rust**

```rust
pub const FM_MSGD_TO_RC: [u8; 16] = [
    0x70, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xAA, 0x55, 0xAA, 0x55,
];
```

**Suggested parser checks**

- flit type == `MsgDToRc`
- payload length == `4 bytes`
- total size == `16 bytes`

---

## 12) `FM_FETCHADD32`

**What it is**

A 32-bit **FetchAdd AtomicOp Request**.

- Type: `FetchAdd` (32-bit)
- Type code: `0x4C`
- Base header: `3 DW`
- Length: `1 DW`
- Payload operand: `01 00 00 00`

**Bytes**

```text
4C 00 00 01  00 00 00 00  00 00 00 00  01 00 00 00
```

**Rust**

```rust
pub const FM_FETCHADD32: [u8; 16] = [
    0x4C, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
];
```

**Suggested parser checks**

- flit type == `FetchAdd32`
- payload length == `4 bytes`
- total size == `16 bytes`

---

## 13) `FM_CAS32`

**What it is**

A 32-bit **Compare-and-Swap AtomicOp Request**.

`CAS` is useful because it carries a `2 DW` payload.

- Type: `CAS` (32-bit)
- Type code: `0x4E`
- Base header: `3 DW`
- Length: `2 DW`
- Payload: compare value then swap value

**Bytes**

```text
4E 00 00 02  00 00 00 00  00 00 00 00  11 11 11 11  22 22 22 22
```

**Rust**

```rust
pub const FM_CAS32: [u8; 20] = [
    0x4E, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x11, 0x11, 0x11, 0x11,
    0x22, 0x22, 0x22, 0x22,
];
```

**Suggested parser checks**

- flit type == `CAS32`
- payload length == `8 bytes`
- total size == `20 bytes`

---

## 14) `FM_DMWR32`

**What it is**

A **32-bit Deferrable Memory Write Request**.

This is worth keeping because your current crate already has `DMWr` support on the non-flit side, so it is a natural flit-mode parser target too.

- Type: `DMWr` (32-bit)
- Type code: `0x5B`
- Base header: `3 DW`
- Length: `1 DW`
- Payload: `C0 FF EE 00`

**Bytes**

```text
5B 00 00 01  00 00 00 00  00 00 00 00  C0 FF EE 00
```

**Rust**

```rust
pub const FM_DMWR32: [u8; 16] = [
    0x5B, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xC0, 0xFF, 0xEE, 0x00,
];
```

**Suggested parser checks**

- flit type == `DMWr32`
- payload length == `4 bytes`
- total size == `16 bytes`

---

## 15) `FM_STREAM_FRAGMENT_0`

**What it is**

A **packed byte stream fragment** containing multiple back-to-back flit-mode TLPs.

This is not a full FLIT container. It is meant to test the parser’s ability to walk a packed TLP stream using:

- decoded `Type[7:0]`
- base header size
- OHC count
- payload length

Contained sequence:

1. `FM_NOP`
2. `FM_MRD32_MIN`
3. `FM_MWR32_MIN`
4. `FM_UIOMRD64_MIN`

**Bytes**

```text
00 00 00 00
03 00 00 01  00 00 00 00  00 00 00 00
40 00 00 01  00 00 00 00  00 00 00 00  DE AD BE EF
22 00 00 02  00 00 00 00  00 00 00 00  00 00 00 00
```

**Rust**

```rust
pub const FM_STREAM_FRAGMENT_0: [u8; 48] = [
    0x00, 0x00, 0x00, 0x00,

    0x03, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0x40, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF,

    0x22, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];
```

**Suggested parser checks**

- first object parsed as `NOP`, size `4`
- second object starts at offset `4`, parsed as `MRd32`, size `12`
- third object starts at offset `16`, parsed as `MWr32`, size `16`
- fourth object starts at offset `32`, parsed as `UIOMRd`, size `16`
- end offset == `48`

---

## Appendix A) Prefix token for later parser work

This one is useful if you later add flit-prefix parsing. It is **not** a stand-alone request/completion transaction by itself; it is a prefix object.

### `FM_LOCAL_PREFIX_ONLY`

- Type: `FlitMode Local TLP Prefix`
- Type code: `0x8D`
- Base header: `1 DW`
- No payload in this minimal token example

```text
8D 00 00 00
```

```rust
pub const FM_LOCAL_PREFIX_ONLY: [u8; 4] = [
    0x8D, 0x00, 0x00, 0x00,
];
```

---

## Negative-test ideas derived from the valid vectors

These are straightforward parser-negative cases you can create by mutating the valid vectors above:

1. `FM_IOWR_A2` with `DW0[1]=0x00`
   - should fail mandatory `OHC-A2` validation

2. `FM_CFGWR0_A3` with `DW0[1]=0x00`
   - should fail mandatory `OHC-A3` validation

3. `FM_MWR32_PARTIAL_A1` with the OHC word removed but `DW0[1]=0x00`
   - should fail if your semantic validator insists that explicit partial-byte memory accesses require `OHC-A1`

4. `FM_UIOMRD64_MIN` re-typed to a non-64b request form
   - should fail a UIO-specific validator if you enforce the 64-bit-address requirement for address-routed UIO requests

5. Truncate the final payload byte from `FM_UIOMWR64_MIN`
   - should fail total-size / payload-length checks

---

## Not frozen yet

I would **not** use the following as golden vectors until you validate them against the exact PCIe Base Spec revision you target:

- `Cpl`
- `CplD`
- `UIORdCplD`
- vectors using `OHC-A5`
- vectors using `OHC-B` / `OHC-C`
- IDE trailer examples
- non-zero 10-bit / 14-bit Tag packing tests

Those are all reasonable next additions once you are ready to lock the exact bit-level layout for the remaining flit-mode fields.

