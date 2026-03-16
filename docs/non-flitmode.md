# API Proposal: Non-Flit Mode / Flit Mode Split

**Status:** Draft — for review and discussion
**Original target release:** 0.4.0 or 0.5.0 (see [Decision Points](#decision-points))

---

## Background

The current library was built explicitly for **non-flit mode** TLPs (PCIe 1.0–5.0).
PCIe 6.0 introduced **flit mode**, where TLPs are carried inside fixed 256-byte
flit containers with different framing, CRC, and packing rules.

The TLP header fields themselves are largely unchanged between modes — what differs
is how raw bytes are extracted and validated before header parsing begins. This
proposal introduces a `TlpMode` abstraction at the entry point so the library can
support both modes without breaking callers again in a future release.

---

## Problem with the current API

```rust
TlpPacket::new(bytes: Vec<u8>) -> Result<TlpPacket, TlpError>
```

`TlpPacket::new` takes raw bytes with no concept of where they came from or how
they should be interpreted. Adding flit mode later would require either:

- A new constructor (`TlpPacket::new_flit(...)`) — inconsistent, hard to use generically
- A breaking change to the existing constructor — forces another major bump
- A wrapper type that duplicates the existing API

All three options are worse than introducing `TlpMode` now while 0.4.0 is already
a breaking release.

---

## Proposed Changes

### 1. New `TlpMode` enum

```rust
/// Selects the framing mode used to interpret the raw byte buffer.
///
/// Non-flit mode covers PCIe 1.0 through 5.0. Flit mode was introduced
/// in PCIe 6.0 and uses fixed 256-byte containers.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlpMode {
    /// Standard non-flit TLP framing (PCIe 1.0 – 5.0).
    /// Bytes are interpreted directly as a TLP header followed by optional payload.
    NonFlit,

    /// Flit-mode TLP framing (PCIe 6.0+).
    /// Not yet implemented — returns `Err(TlpError::NotImplemented)`.
    Flit,
}
```

`#[non_exhaustive]` is important here — it prevents downstream `match` arms from
being exhaustive, so adding future variants (e.g. `FlitCompressed`) is not a
breaking change.

---

### 2. Updated `TlpPacket::new`

```rust
impl TlpPacket {
    pub fn new(bytes: Vec<u8>, mode: TlpMode) -> Result<TlpPacket, TlpError> {
        match mode {
            TlpMode::NonFlit => Self::new_non_flit(bytes),
            TlpMode::Flit => Err(TlpError::NotImplemented),
        }
    }
}
```

Current behavior moves into `new_non_flit` unchanged. Callers update to:

```rust
// before (0.4.0)
let pkt = TlpPacket::new(bytes).unwrap();

// after (proposed)
let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
```

---

### 3. New `TlpError` variant

```rust
pub enum TlpError {
    InvalidFormat,
    InvalidType,
    InvalidLength,
    UnsupportedCombination,
    NotImplemented,   // ← new: feature exists in the API but not yet implemented
}
```

---

### 4. Factory functions — no change needed

`new_mem_req`, `new_conf_req`, `new_cmpl_req`, `new_msg_req`, `new_atomic_req`
all operate on pre-extracted bytes passed in by the caller. They are mode-agnostic
at this level — the mode only affects how `TlpPacket` unpacks the raw buffer.
No changes required to these signatures.

---

### 5. `TlpPacketHeader::new` — same treatment

```rust
impl TlpPacketHeader {
    pub fn new(bytes: Vec<u8>, mode: TlpMode) -> Result<TlpPacketHeader, TlpError>
}
```

Mirrors `TlpPacket::new` for consistency.

---

## What flit mode implementation would look like (future)

When `TlpMode::Flit` is eventually implemented, `new_non_flit` / `new_flit`
become separate parse paths under the same public constructor:

```
Flit container (256 bytes)
  └── Flit header (8 bytes: slot count, CRC, ...)
  └── Slot 0: TLP bytes  ──→  existing header parsing (DW0..DWn)
  └── Slot 1: TLP bytes  ──→  existing header parsing
  └── Null padding
```

The per-TLP header parsing (everything below `TlpPacket`) is reused unchanged.
Only the framing/extraction layer differs.

---

## Migration guide (0.4.0 → proposed)

| Before | After |
|---|---|
| `TlpPacket::new(bytes)` | `TlpPacket::new(bytes, TlpMode::NonFlit)` |
| `TlpPacketHeader::new(bytes)` | `TlpPacketHeader::new(bytes, TlpMode::NonFlit)` |
| `TlpError` match arms | Add `TlpError::NotImplemented` arm (or use `_`) |

All other public API (`TlpFmt`, `TlpType`, all traits, all factory functions)
is unchanged.

---

## Decision Points

### Should this land in 0.4.0 or 0.5.0?

**0.4.0 (recommended):**
- 0.4.0 is already a breaking release — the additional migration cost is two
  call sites per constructor, trivially mechanical
- Avoids a 0.5.0 break immediately after 0.4.0
- `TlpMode::Flit` can stub out as `NotImplemented` with no implementation risk

**0.5.0:**
- Gives more time to validate the `TlpMode` design against real flit-mode specs
- Keeps 0.4.0 diff smaller and easier to review
- Acceptable if flit mode is genuinely far off and the `TlpMode` shape might change

### Should `TlpMode` be a constructor parameter or a type parameter?

The proposal uses a runtime parameter. An alternative is a type-level split:

```rust
// type-parameter approach
TlpPacket<NonFlit>
TlpPacket<Flit>
```

This has appeal for zero-cost mode dispatch and makes it impossible to mix modes
at compile time. However it propagates the type parameter into every trait bound
and factory function signature, which is significant API complexity. The runtime
parameter is simpler and sufficient given the modes are not performance-critical.

### Should callers ever need to handle flit unpacking themselves?

If the library only does TLP parsing and not flit container parsing, callers on
PCIe 6.0 would be expected to extract TLP bytes from flits themselves before
calling `TlpPacket::new(bytes, TlpMode::NonFlit)`. This is a valid design since
flit framing is a layer below TLP semantics.

Alternatively, the library could expose a `FlitContainer` type that yields an
iterator of `TlpPacket`s. This is more ambitious and should be a separate
design discussion.

---

## Open Questions

1. Should `TlpMode::Flit` return `NotImplemented` or should the variant simply
   not exist until the implementation is ready?
2. Is flit container parsing in scope for this library at all, or out of scope
   by design?
3. Are there PCIe 6.0 traces available to validate flit parsing against?

