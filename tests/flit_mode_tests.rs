//! Flit Mode Tests (PCIe 6.x)
//!
//! Scope: parser tests for TLP byte streams as they appear inside a PCIe 6.x FLIT.
//! These are NOT full 256-byte FLIT containers — no DLP, CRC or FEC bytes.
//!
//! # Tier structure
//!
//! | Tier | Status | Unlock condition |
//! |------|--------|-----------------|
//! | 0 | ✅ passes today | N/A — permanent stub regression guard |
//! | 1 | ✅ passes today | `FlitDW0::from_dw0()` ← **implemented** |
//! | 2 | ✅ passes today | `FlitTlpType::base_header_dw()` ← **implemented** |
//! | 3 | ✅ passes today | `FlitOhcA` + `validate_mandatory_ohc()` ← **implemented** |
//! | 4 | ✅ passes today | `FlitStreamWalker` ← **implemented** |
//! | 5 | ✅ passes today | `TlpPacket::new_flit()` ← **implemented** |
//!
//! For non-flit tests see `tests/non_flit_tests.rs`.
//! For API surface tests see `tests/api_tests.rs`.
//! Design rationale: `docs/flit_mode_test_plan.md`.

use rtlp_lib::*;

// ============================================================================
// FM_* test vectors — from docs/flit_mode_tlp_examples.md
//
// DW0 flit-mode encoding:
//   Byte 0 = Type[7:0]   (flat 8-bit type code, NOT non-flit fmt+type)
//   Byte 1 = TC[2:0] | OHC[4:0]
//   Byte 2 = TS[2:0] | Attr[2:0] | Length[9:8]
//   Byte 3 = Length[7:0]
// ============================================================================

/// Flit-mode NOP. Smallest possible header-base object (1 DW, no payload).
pub const FM_NOP: [u8; 4] = [
    0x00, 0x00, 0x00, 0x00,
];

/// Minimal 32-bit Memory Read Request. Length=1 DW, no OHC, no payload.
pub const FM_MRD32_MIN: [u8; 12] = [
    0x03, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// 32-bit Memory Read Request with OHC-A1 carrying PASID=0x12345, fdwbe=0xF, ldwbe=0x0.
pub const FM_MRD32_A1_PASID: [u8; 16] = [
    0x03, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x23, 0x45, 0x0F,
];

/// Minimal 32-bit Memory Write Request. Length=1 DW, no OHC, payload=0xDEADBEEF.
pub const FM_MWR32_MIN: [u8; 16] = [
    0x40, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF,
];

/// 32-bit Memory Write Request with OHC-A1. fdwbe=0x3 (partial-byte write).
pub const FM_MWR32_PARTIAL_A1: [u8; 20] = [
    0x40, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03,
    0xAA, 0xBB, 0xCC, 0xDD,
];

/// I/O Write Request with mandatory OHC-A2. fdwbe=0xF.
pub const FM_IOWR_A2: [u8; 20] = [
    0x42, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0F,
    0x10, 0x20, 0x30, 0x40,
];

/// Type0 Configuration Write Request with mandatory OHC-A3. fdwbe=0xF.
pub const FM_CFGWR0_A3: [u8; 20] = [
    0x44, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x0F,
    0x44, 0x33, 0x22, 0x11,
];

/// Minimal UIO Memory Read Request (PCIe 6.1+ UIO). 4 DW base header, Length=2 DW, no payload.
pub const FM_UIOMRD64_MIN: [u8; 16] = [
    0x22, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// Minimal UIO Memory Write Request (PCIe 6.1+ UIO). 4 DW base header, 2 DW payload.
pub const FM_UIOMWR64_MIN: [u8; 24] = [
    0x61, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88,
];

/// Message routed to RC, no data.
pub const FM_MSG_TO_RC: [u8; 12] = [
    0x30, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// Message with data, routed to RC.
pub const FM_MSGD_TO_RC: [u8; 16] = [
    0x70, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xAA, 0x55, 0xAA, 0x55,
];

/// 32-bit FetchAdd AtomicOp Request. Operand = 0x01000000.
pub const FM_FETCHADD32: [u8; 16] = [
    0x4C, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
];

/// 32-bit Compare-and-Swap AtomicOp Request. Compare=0x11111111, Swap=0x22222222.
pub const FM_CAS32: [u8; 20] = [
    0x4E, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x11, 0x11, 0x11, 0x11,
    0x22, 0x22, 0x22, 0x22,
];

/// 32-bit Deferrable Memory Write Request.
pub const FM_DMWR32: [u8; 16] = [
    0x5B, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xC0, 0xFF, 0xEE, 0x00,
];

/// Packed stream fragment: NOP + MRd32 + MWr32 + UIOMRd64 back-to-back.
pub const FM_STREAM_FRAGMENT_0: [u8; 48] = [
    // NOP (4 bytes, offset 0)
    0x00, 0x00, 0x00, 0x00,
    // MRd32 (12 bytes, offset 4)
    0x03, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // MWr32 (16 bytes, offset 16)
    0x40, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xDE, 0xAD, 0xBE, 0xEF,
    // UIOMRd64 (16 bytes, offset 32)
    0x22, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// Local TLP Prefix token (Appendix A — not a standalone transaction).
pub const FM_LOCAL_PREFIX_ONLY: [u8; 4] = [
    0x8D, 0x00, 0x00, 0x00,
];

// ============================================================================
// Tier 0 — Regression guards
//
// These tests verify the core flit parsing entry points and two
// parser-driven correctness checks for all FM_* byte-vector constants.
//
// Note: `TlpPacketHeader::new(Flit)` intentionally remains `NotImplemented` —
// the flit header format is fundamentally different from non-flit DW0 and
// a separate parser path has not been implemented for `TlpPacketHeader`.
// ============================================================================

#[test]
fn flit_packet_new_succeeds_for_valid_flit() {
    // TlpMode::Flit pipeline: MRd32 (3 DW base header, no payload despite Length=1)
    let pkt = TlpPacket::new(FM_MRD32_MIN.to_vec(), TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::MemRead32));
    assert!(pkt.data().is_empty()); // read request — no payload in the request packet
}

#[test]
fn flit_header_new_returns_not_implemented() {
    // TlpPacketHeader::new() with Flit intentionally returns NotImplemented.
    // Flit DW0 uses a flat 8-bit type code incompatible with TlpHeader bitfield.
    let bytes = FM_MRD32_MIN.to_vec();
    assert_eq!(
        TlpPacketHeader::new(bytes, TlpMode::Flit).err().unwrap(),
        TlpError::NotImplemented
    );
}

/// Parser-driven check: every FM_* constant decodes to the expected FlitTlpType.
/// Unlike asserting FM_NOP[0] == 0x00 (which only checks a constant against itself),
/// this test actually exercises the library's type-decode path.
#[test]
fn flit_all_fm_vectors_parse_to_expected_type() {
    let cases: &[(&[u8], FlitTlpType)] = &[
        (&FM_NOP,               FlitTlpType::Nop),
        (&FM_MRD32_MIN,         FlitTlpType::MemRead32),
        (&FM_MRD32_A1_PASID,    FlitTlpType::MemRead32),
        (&FM_MWR32_MIN,         FlitTlpType::MemWrite32),
        (&FM_MWR32_PARTIAL_A1,  FlitTlpType::MemWrite32),
        (&FM_IOWR_A2,           FlitTlpType::IoWrite),
        (&FM_CFGWR0_A3,         FlitTlpType::CfgWrite0),
        (&FM_UIOMRD64_MIN,      FlitTlpType::UioMemRead),
        (&FM_UIOMWR64_MIN,      FlitTlpType::UioMemWrite),
        (&FM_MSG_TO_RC,         FlitTlpType::MsgToRc),
        (&FM_MSGD_TO_RC,        FlitTlpType::MsgDToRc),
        (&FM_FETCHADD32,        FlitTlpType::FetchAdd32),
        (&FM_CAS32,             FlitTlpType::CompareSwap32),
        (&FM_DMWR32,            FlitTlpType::DeferrableMemWrite32),
        (&FM_LOCAL_PREFIX_ONLY, FlitTlpType::LocalTlpPrefix),
    ];
    for (bytes, expected) in cases {
        let dw0 = FlitDW0::from_dw0(bytes)
            .unwrap_or_else(|e| panic!("FM_* failed to parse: {:?} (byte0={:#04x})", e, bytes[0]));
        assert_eq!(dw0.tlp_type, *expected,
            "byte0={:#04x} decoded to {:?}, expected {:?}", bytes[0], dw0.tlp_type, expected);
    }
}

/// Parser-driven OHC check: every FM_* constant decodes the OHC presence bitmap correctly.
#[test]
fn flit_all_fm_vectors_parse_with_correct_ohc() {
    // (vector, expected OHC bitmap value)
    let cases: &[(&[u8], u8, &str)] = &[
        (&FM_NOP,               0, "FM_NOP"),
        (&FM_MRD32_MIN,         0, "FM_MRD32_MIN"),
        (&FM_MWR32_MIN,         0, "FM_MWR32_MIN"),
        (&FM_MRD32_A1_PASID,    1, "FM_MRD32_A1_PASID"),   // OHC-A1
        (&FM_MWR32_PARTIAL_A1,  1, "FM_MWR32_PARTIAL_A1"), // OHC-A1
        (&FM_IOWR_A2,           1, "FM_IOWR_A2"),           // OHC-A2
        (&FM_CFGWR0_A3,         1, "FM_CFGWR0_A3"),         // OHC-A3
    ];
    for (bytes, expected_ohc, name) in cases {
        let dw0 = FlitDW0::from_dw0(bytes).unwrap();
        assert_eq!(dw0.ohc, *expected_ohc, "{} ohc mismatch", name);
        assert_eq!(dw0.ohc_count(), (*expected_ohc).count_ones() as u8,
            "{} ohc_count mismatch", name);
    }
}

// ============================================================================
// Tier 1 — Flit DW0 field extraction (FlitDW0::from_dw0)
// ============================================================================

#[test]
fn flit_t1_nop_dw0_fields() {
    let dw0 = FlitDW0::from_dw0(&FM_NOP).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::Nop);
    assert_eq!(dw0.tc,     0);
    assert_eq!(dw0.ohc,    0);
    assert_eq!(dw0.ts,     0);
    assert_eq!(dw0.attr,   0);
    assert_eq!(dw0.length, 0);
}

#[test]
fn flit_t1_mrd32_dw0_fields() {
    // FM_MRD32_MIN = [0x03, 0x00, 0x00, 0x01]
    let dw0 = FlitDW0::from_dw0(&FM_MRD32_MIN).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::MemRead32);
    assert_eq!(dw0.tc,     0);
    assert_eq!(dw0.ohc,    0);
    assert_eq!(dw0.length, 1); // Length field = 1 DW (but no actual payload — it's a read)
}

#[test]
fn flit_t1_mrd32_a1_dw0_ohc_present() {
    // FM_MRD32_A1_PASID = [0x03, 0x01, 0x00, 0x01]
    let dw0 = FlitDW0::from_dw0(&FM_MRD32_A1_PASID).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::MemRead32);
    assert_eq!(dw0.ohc, 0x01); // OHC-A1 bit set
    assert_eq!(dw0.ohc_count(), 1);
    assert_eq!(dw0.length, 1);
}

#[test]
fn flit_t1_mwr32_dw0_fields() {
    // FM_MWR32_MIN = [0x40, 0x00, 0x00, 0x01]
    let dw0 = FlitDW0::from_dw0(&FM_MWR32_MIN).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::MemWrite32);
    assert_eq!(dw0.tc,     0);
    assert_eq!(dw0.ohc,    0);
    assert_eq!(dw0.length, 1);
}

#[test]
fn flit_t1_uiomrd64_dw0_fields() {
    // FM_UIOMRD64_MIN = [0x22, 0x00, 0x00, 0x02]
    let dw0 = FlitDW0::from_dw0(&FM_UIOMRD64_MIN).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::UioMemRead);
    assert_eq!(dw0.ohc,    0);
    assert_eq!(dw0.length, 2);
}

#[test]
fn flit_t1_cas32_dw0_length_is_2() {
    // FM_CAS32 = [0x4E, 0x00, 0x00, 0x02] — 2 DW payload (compare + swap)
    let dw0 = FlitDW0::from_dw0(&FM_CAS32).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::CompareSwap32);
    assert_eq!(dw0.length, 2);
}

#[test]
fn flit_t1_unknown_type_returns_invalid_type_error() {
    // Type code 0xFF is not in the known table
    let bad_type = [0xFF, 0x00, 0x00, 0x00];
    assert_eq!(
        FlitDW0::from_dw0(&bad_type).err().unwrap(),
        TlpError::InvalidType
    );
}

#[test]
fn flit_t1_short_slice_returns_invalid_length_error() {
    assert_eq!(
        FlitDW0::from_dw0(&[0x03, 0x00, 0x00]).err().unwrap(),
        TlpError::InvalidLength
    );
}

// ============================================================================
// Tier 2 — Per-vector header + total size validation
// ============================================================================

#[test]
fn flit_t2_nop_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_NOP).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::Nop);
    assert_eq!(dw0.tlp_type.base_header_dw(), 1);
    assert_eq!(dw0.ohc_count(), 0);
    assert_eq!(dw0.total_bytes(), 4); // 1 DW header, no payload
}

// Length=0 encodes 1024 DW per PCIe spec — not "0 DW"
#[test]
fn flit_t2_total_bytes_length_zero_encodes_1024dw() {
    // MWr32 (write, so it has payload) with Length=0 → 1024 DW = 4096 bytes payload
    // DW0: type=0x40 (MemWrite32), ohc=0, length=0
    let dw0 = FlitDW0::from_dw0(&[0x40, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(dw0.length, 0);
    // 3 DW base header + 1024 DW payload = 1027 DW = 4108 bytes
    assert_eq!(dw0.total_bytes(), 3 * 4 + 1024 * 4);
}

#[test]
fn flit_t2_total_bytes_length_zero_read_still_no_payload() {
    // Read requests carry no payload even with length=0 encoding (which means 1024 DW)
    // DW0: type=0x03 (MemRead32), ohc=0, length=0
    let dw0 = FlitDW0::from_dw0(&[0x03, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(dw0.length, 0);
    // 3 DW base header, no payload (read request)
    assert_eq!(dw0.total_bytes(), 3 * 4);
}

#[test]
fn flit_t2_mrd32_min_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_MRD32_MIN).unwrap();
    assert_eq!(dw0.tlp_type.base_header_dw(), 3);
    assert_eq!(dw0.ohc_count(), 0);
    assert_eq!(dw0.length, 1);
    // Read request: no payload bytes even though Length=1
    assert_eq!(dw0.total_bytes(), 12);
}

#[test]
fn flit_t2_mrd32_a1_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_MRD32_A1_PASID).unwrap();
    assert_eq!(dw0.tlp_type.base_header_dw(), 3);
    assert_eq!(dw0.ohc_count(), 1); // OHC-A1 adds 1 DW
    // Read: no payload. Total = (3+1)*4 = 16
    assert_eq!(dw0.total_bytes(), 16);
}

#[test]
fn flit_t2_mwr32_min_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_MWR32_MIN).unwrap();
    assert_eq!(dw0.tlp_type.base_header_dw(), 3);
    assert_eq!(dw0.ohc_count(), 0);
    assert_eq!(dw0.length, 1);
    // Write: 1 DW payload. Total = 3*4 + 1*4 = 16
    assert_eq!(dw0.total_bytes(), 16);
}

#[test]
fn flit_t2_mwr32_partial_a1_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_MWR32_PARTIAL_A1).unwrap();
    assert_eq!(dw0.tlp_type.base_header_dw(), 3);
    assert_eq!(dw0.ohc_count(), 1);
    assert_eq!(dw0.length, 1);
    // Total = (3+1)*4 + 1*4 = 20
    assert_eq!(dw0.total_bytes(), 20);
}

#[test]
fn flit_t2_iowr_a2_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_IOWR_A2).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::IoWrite);
    assert_eq!(dw0.tlp_type.base_header_dw(), 3);
    assert_eq!(dw0.ohc_count(), 1);
    assert_eq!(dw0.length, 1);
    assert_eq!(dw0.total_bytes(), 20);
}

#[test]
fn flit_t2_cfgwr0_a3_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_CFGWR0_A3).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::CfgWrite0);
    assert_eq!(dw0.tlp_type.base_header_dw(), 3);
    assert_eq!(dw0.ohc_count(), 1);
    assert_eq!(dw0.length, 1);
    assert_eq!(dw0.total_bytes(), 20);
}

#[test]
fn flit_t2_uiomrd64_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_UIOMRD64_MIN).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::UioMemRead);
    assert_eq!(dw0.tlp_type.base_header_dw(), 4); // 4DW header (64-bit address)
    assert_eq!(dw0.ohc_count(), 0);
    assert_eq!(dw0.length, 2);
    // Read: no payload. Total = 4*4 = 16
    assert_eq!(dw0.total_bytes(), 16);
}

#[test]
fn flit_t2_uiomwr64_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_UIOMWR64_MIN).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::UioMemWrite);
    assert_eq!(dw0.tlp_type.base_header_dw(), 4);
    assert_eq!(dw0.ohc_count(), 0);
    assert_eq!(dw0.length, 2);
    // Write: 2 DW payload. Total = 4*4 + 2*4 = 24
    assert_eq!(dw0.total_bytes(), 24);
}

#[test]
fn flit_t2_cas32_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_CAS32).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::CompareSwap32);
    assert_eq!(dw0.tlp_type.base_header_dw(), 3);
    assert_eq!(dw0.ohc_count(), 0);
    assert_eq!(dw0.length, 2);
    // 2 DW payload (compare + swap). Total = 3*4 + 2*4 = 20
    assert_eq!(dw0.total_bytes(), 20);
}

#[test]
fn flit_t2_dmwr32_type_and_sizes() {
    let dw0 = FlitDW0::from_dw0(&FM_DMWR32).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::DeferrableMemWrite32);
    assert_eq!(dw0.tlp_type.base_header_dw(), 3);
    assert_eq!(dw0.ohc_count(), 0);
    assert_eq!(dw0.length, 1);
    assert_eq!(dw0.total_bytes(), 16);
}

#[test]
fn flit_t2_read_request_predicate() {
    // MemRead32 and UioMemRead are read requests — no payload
    assert!(FlitTlpType::MemRead32.is_read_request());
    assert!(FlitTlpType::UioMemRead.is_read_request());

    // Writes and atomics are NOT read requests
    assert!(!FlitTlpType::MemWrite32.is_read_request());
    assert!(!FlitTlpType::IoWrite.is_read_request());
    assert!(!FlitTlpType::CfgWrite0.is_read_request());
    assert!(!FlitTlpType::FetchAdd32.is_read_request());
    assert!(!FlitTlpType::CompareSwap32.is_read_request());
    assert!(!FlitTlpType::DeferrableMemWrite32.is_read_request());
    assert!(!FlitTlpType::Nop.is_read_request());
}

#[test]
fn flit_t2_local_prefix_base_header_is_1dw() {
    let dw0 = FlitDW0::from_dw0(&FM_LOCAL_PREFIX_ONLY).unwrap();
    assert_eq!(dw0.tlp_type, FlitTlpType::LocalTlpPrefix);
    assert_eq!(dw0.tlp_type.base_header_dw(), 1);
    assert_eq!(dw0.total_bytes(), 4);
}

// ============================================================================
// Tier 3 — OHC field parsing and mandatory OHC validation
// ============================================================================

#[test]
fn flit_t3_mrd32_a1_pasid_extraction() {
    // FM_MRD32_A1_PASID: 3 DW base header → OHC-A word starts at byte 12
    // OHC-A1 word = [0x01, 0x23, 0x45, 0x0F]
    let dw0 = FlitDW0::from_dw0(&FM_MRD32_A1_PASID).unwrap();
    let ohc_offset = dw0.tlp_type.base_header_dw() as usize * 4; // = 12
    let ohc = FlitOhcA::from_bytes(&FM_MRD32_A1_PASID[ohc_offset..]).unwrap();
    assert_eq!(ohc.pasid, 0x12345);
    assert_eq!(ohc.fdwbe, 0xF);
    assert_eq!(ohc.ldwbe, 0x0);
}

#[test]
fn flit_t3_mwr32_partial_a1_be_extraction() {
    // FM_MWR32_PARTIAL_A1: OHC-A1 word = [0x00, 0x00, 0x00, 0x03]
    let dw0 = FlitDW0::from_dw0(&FM_MWR32_PARTIAL_A1).unwrap();
    let ohc_offset = dw0.tlp_type.base_header_dw() as usize * 4; // = 12
    let ohc = FlitOhcA::from_bytes(&FM_MWR32_PARTIAL_A1[ohc_offset..]).unwrap();
    assert_eq!(ohc.pasid, 0);
    assert_eq!(ohc.fdwbe, 0x3); // partial-byte write
    assert_eq!(ohc.ldwbe, 0x0);
}

#[test]
fn flit_t3_iowr_a2_mandatory_ohc_present() {
    // FM_IOWR_A2: OHC-A2 present (byte1 bit0=1) → validation succeeds
    let dw0 = FlitDW0::from_dw0(&FM_IOWR_A2).unwrap();
    assert!(dw0.validate_mandatory_ohc().is_ok());
    // Also verify OHC-A2 word content
    let ohc_offset = dw0.tlp_type.base_header_dw() as usize * 4; // = 12
    let ohc = FlitOhcA::from_bytes(&FM_IOWR_A2[ohc_offset..]).unwrap();
    assert_eq!(ohc.fdwbe, 0xF);
    assert_eq!(ohc.ldwbe, 0x0);
}

#[test]
fn flit_t3_iowr_missing_mandatory_ohc_a2() {
    // FM_IOWR_A2 with byte1 cleared → missing mandatory OHC-A2 → error
    let mut bad = FM_IOWR_A2.to_vec();
    bad[1] = 0x00; // clear OHC flags
    let dw0 = FlitDW0::from_dw0(&bad).unwrap();
    assert_eq!(
        dw0.validate_mandatory_ohc(),
        Err(TlpError::MissingMandatoryOhc)
    );
}

#[test]
fn flit_t3_cfgwr0_a3_mandatory_ohc_present() {
    // FM_CFGWR0_A3: OHC-A3 present (byte1 bit0=1) → validation succeeds
    let dw0 = FlitDW0::from_dw0(&FM_CFGWR0_A3).unwrap();
    assert!(dw0.validate_mandatory_ohc().is_ok());
    // Also verify OHC-A3 word content
    let ohc_offset = dw0.tlp_type.base_header_dw() as usize * 4; // = 12
    let ohc = FlitOhcA::from_bytes(&FM_CFGWR0_A3[ohc_offset..]).unwrap();
    assert_eq!(ohc.fdwbe, 0xF);
    assert_eq!(ohc.ldwbe, 0x0);
}

#[test]
fn flit_t3_cfgwr_missing_mandatory_ohc_a3() {
    // FM_CFGWR0_A3 with byte1 cleared → missing mandatory OHC-A3 → error
    let mut bad = FM_CFGWR0_A3.to_vec();
    bad[1] = 0x00; // clear OHC flags
    let dw0 = FlitDW0::from_dw0(&bad).unwrap();
    assert_eq!(
        dw0.validate_mandatory_ohc(),
        Err(TlpError::MissingMandatoryOhc)
    );
}

// ============================================================================
// Tier 4 -- Packed stream walking
// ============================================================================

#[test]
fn flit_t4_stream_fragment_0_offsets() {
    // FM_STREAM_FRAGMENT_0 contains 4 back-to-back TLPs:
    //   NOP (4B) + MRd32 (12B) + MWr32 (16B) + UIOMRd (16B) = 48B total
    let entries: Vec<_> = FlitStreamWalker::new(&FM_STREAM_FRAGMENT_0)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0], (0,  FlitTlpType::Nop,       4));
    assert_eq!(entries[1], (4,  FlitTlpType::MemRead32, 12));
    assert_eq!(entries[2], (16, FlitTlpType::MemWrite32, 16));
    assert_eq!(entries[3], (32, FlitTlpType::UioMemRead, 16));
}

#[test]
fn flit_t4_stream_walker_returns_none_at_end() {
    // Walker stops cleanly after the last TLP
    let mut walker = FlitStreamWalker::new(&FM_NOP);
    assert!(walker.next().is_some()); // NOP
    assert!(walker.next().is_none()); // end of stream
}

#[test]
fn flit_t4_stream_truncated_payload_error() {
    // FM_UIOMWR64_MIN with last byte removed -- payload is truncated
    let mut truncated = FM_UIOMWR64_MIN.to_vec();
    truncated.pop();
    let result: Result<Vec<_>, _> = FlitStreamWalker::new(&truncated).collect();
    assert_eq!(result.err().unwrap(), TlpError::InvalidLength);
}

// ============================================================================
// Tier 5 -- End-to-end TlpMode::Flit pipeline
// ============================================================================

#[test]
fn flit_t5_end_to_end_mrd32_min() {
    // MRd32 flit: 3 DW base header, no payload despite Length=1
    let pkt = TlpPacket::new(FM_MRD32_MIN.to_vec(), TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::MemRead32));
    assert!(pkt.data().is_empty());
}

#[test]
fn flit_t5_end_to_end_mwr32_min() {
    // MWr32 flit: 3 DW header + 1 DW payload
    let pkt = TlpPacket::new(FM_MWR32_MIN.to_vec(), TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::MemWrite32));
    assert_eq!(pkt.data(), [0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn flit_t5_end_to_end_cas32() {
    // CAS32 flit: 3 DW header + 2 DW payload (compare + swap)
    let pkt = TlpPacket::new(FM_CAS32.to_vec(), TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::CompareSwap32));
    assert_eq!(pkt.data(), [
        0x11, 0x11, 0x11, 0x11, // compare
        0x22, 0x22, 0x22, 0x22, // swap
    ]);
}

#[test]
fn flit_t5_end_to_end_dmwr32() {
    // DMWr32 flit: 3 DW header + 1 DW payload
    let pkt = TlpPacket::new(FM_DMWR32.to_vec(), TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::DeferrableMemWrite32));
    assert_eq!(pkt.data(), [0xC0, 0xFF, 0xEE, 0x00]);
}

#[test]
fn flit_t5_end_to_end_uiomwr64() {
    // UIOMWr64 flit: 4 DW header + 2 DW payload
    let pkt = TlpPacket::new(FM_UIOMWR64_MIN.to_vec(), TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::UioMemWrite));
    assert_eq!(pkt.data(), [
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
    ]);
}

#[test]
fn flit_t5_nop_has_no_data() {
    // NOP flit: 1 DW header, no payload
    let pkt = TlpPacket::new(FM_NOP.to_vec(), TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::Nop));
    assert!(pkt.data().is_empty());
}

#[test]
fn flit_t5_nonflit_packet_get_flit_type_returns_none() {
    // Non-flit packets must return None from get_flit_type()
    let pkt = TlpPacket::new(vec![0x00, 0x00, 0x00, 0x01], TlpMode::NonFlit).unwrap();
    assert_eq!(pkt.get_flit_type(), None);
}

// ============================================================================
// Tier 5 atomic operand value verification
// Verifies the actual operand bytes in FM_FETCHADD32 and FM_CAS32 are correct.
// Note: new_atomic_req() requires NonFlit packets; here we verify operand bytes
// directly from data() since flit mode doesn't yet expose an atomic parser.
// ============================================================================

#[test]
fn flit_t5_fetchadd32_operand_value_in_payload() {
    // FM_FETCHADD32 operand = 0x01000000 (comment says "Operand = 0x01000000")
    // Verify: parse the flit packet and check that data() contains the operand bytes
    let pkt = TlpPacket::new(FM_FETCHADD32.to_vec(), TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::FetchAdd32));
    // Payload = 3 DW header consumed, remaining = [0x01, 0x00, 0x00, 0x00]
    assert_eq!(pkt.data().len(), 4, "FetchAdd32 has 1 DW operand");
    let operand = u32::from_be_bytes([pkt.data()[0], pkt.data()[1], pkt.data()[2], pkt.data()[3]]);
    assert_eq!(operand, 0x01000000, "FM_FETCHADD32 addend should be 0x01000000");
}

#[test]
fn flit_t5_cas32_operand_values_in_payload() {
    // FM_CAS32: Compare=0x11111111, Swap=0x22222222 (as documented in the constant)
    let pkt = TlpPacket::new(FM_CAS32.to_vec(), TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::CompareSwap32));
    // Payload = 3 DW header consumed, remaining = 8 bytes (compare + swap)
    assert_eq!(pkt.data().len(), 8, "CAS32 has 2 DW payload (compare + swap)");
    let compare = u32::from_be_bytes([pkt.data()[0], pkt.data()[1], pkt.data()[2], pkt.data()[3]]);
    let swap    = u32::from_be_bytes([pkt.data()[4], pkt.data()[5], pkt.data()[6], pkt.data()[7]]);
    assert_eq!(compare, 0x11111111, "FM_CAS32 compare operand");
    assert_eq!(swap,    0x22222222, "FM_CAS32 swap operand");
}
