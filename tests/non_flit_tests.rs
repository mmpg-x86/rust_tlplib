//! Non-Flit Mode Integration Tests (PCIe 1.0 – 5.0)
//!
//! Scope: functional behavior of the library when using `TlpMode::NonFlit`.
//! Every `TlpPacket::new` and `TlpPacketHeader::new` call in this file must
//! pass `TlpMode::NonFlit` explicitly.
//!
//! For flit mode (PCIe 6.x) tests see `tests/flit_mode_tests.rs`.
//! For API surface / stability tests see `tests/api_tests.rs`.

use rtlp_lib::*;

// ── helpers ───────────────────────────────────────────────────────────────

fn mk_pkt(dw0_fmt: u8, dw0_type: u8, data: &[u8]) -> TlpPacket {
    let mut v = Vec::with_capacity(4 + data.len());
    v.push((dw0_fmt << 5) | (dw0_type & 0x1f));
    v.push(0);
    v.push(0);
    v.push(0);
    v.extend_from_slice(data);
    TlpPacket::new(v, TlpMode::NonFlit).unwrap()
}

/// Structural split test: verifies that TlpPacket correctly identifies DW0 type
/// and separates the remaining bytes into data().
///
/// Note: per PCIe §2.2.4, Configuration Read Requests carry **no data payload** —
/// this packet would be invalid on a real PCIe link. The library performs structural
/// parsing only (split at byte 4) and does not enforce semantic payload rules.
#[test]
fn test_tlp_packet() {
    let d = vec![
        0x04, 0x00, 0x00, 0x01, 0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10,
    ];
    let tlp = TlpPacket::new(d, TlpMode::NonFlit).unwrap();

    assert_eq!(tlp.tlp_type().unwrap(), TlpType::ConfType0ReadReq);
    // DW0 consumed as header; bytes[4..12] go into data() for downstream parsing
    assert_eq!(tlp.data(), [0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);
}

#[test]
fn test_complreq_trait() {
    let cmpl_req = CompletionReqDW23([0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);

    assert_eq!(0x2001, cmpl_req.cmpl_id());
    assert_eq!(0x7, cmpl_req.cmpl_stat());
    assert_eq!(0x1, cmpl_req.bcm());
    assert_eq!(0xF00, cmpl_req.byte_cnt());
    assert_eq!(0xC281, cmpl_req.req_id());
    assert_eq!(0xFF, cmpl_req.tag());
    assert_eq!(0x10, cmpl_req.laddr());
}

#[test]
fn test_configreq_trait() {
    let conf_req = ConfigRequest([0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);

    assert_eq!(0x2001, conf_req.req_id());
    assert_eq!(0xFF, conf_req.tag());
    assert_eq!(0xC2, conf_req.bus_nr());
    assert_eq!(0x10, conf_req.dev_nr());
    assert_eq!(0x01, conf_req.func_nr());
    assert_eq!(0x0F, conf_req.ext_reg_nr());
    assert_eq!(0x04, conf_req.reg_nr());
}

#[test]
fn memreq_tag_field_3dw_and_4dw() {
    let mr3dw1 = MemRequest3DW([0x00, 0x00, 0x20, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);
    let mr3dw2 = MemRequest3DW([0x00, 0x00, 0x01, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);
    let mr3dw3 = MemRequest3DW([0x00, 0x00, 0x10, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);
    let mr3dw4 = MemRequest3DW([0x00, 0x00, 0x81, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);

    assert_eq!(0x20, mr3dw1.tag());
    assert_eq!(0x01, mr3dw2.tag());
    assert_eq!(0x10, mr3dw3.tag());
    assert_eq!(0x81, mr3dw4.tag());

    let mr4dw1 = MemRequest4DW([
        0x00, 0x00, 0x01, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00,
    ]);
    let mr4dw2 = MemRequest4DW([
        0x00, 0x00, 0x10, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00,
    ]);
    let mr4dw3 = MemRequest4DW([
        0x00, 0x00, 0x81, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00,
    ]);
    let mr4dw4 = MemRequest4DW([
        0x00, 0x00, 0xFF, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00,
    ]);
    let mr4dw5 = MemRequest4DW([
        0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00,
    ]);

    assert_eq!(0x01, mr4dw1.tag());
    assert_eq!(0x10, mr4dw2.tag());
    assert_eq!(0x81, mr4dw3.tag());
    assert_eq!(0xFF, mr4dw4.tag());
    assert_eq!(0x00, mr4dw5.tag());
}

#[test]
fn memreq_3dw_address_field() {
    // DW1+DW2 bytes: req_id=0x0000, tag=0x20, BE=0x0F, address32=0xF620000C
    let memreq_3dw = [0x00, 0x00, 0x20, 0x0F, 0xF6, 0x20, 0x00, 0x0C];
    let mr = MemRequest3DW(memreq_3dw);

    assert_eq!(0xF620000C, mr.address());
}

#[test]
fn memreq_4dw_address_field() {
    // DW1+DW2+DW3 bytes: address64 = 0x17FC0000000
    let memreq_4dw = [
        0x00, 0x00, 0x20, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00,
    ];
    let mr = MemRequest4DW(memreq_4dw);

    assert_eq!(0x17fc0000000, mr.address());
}

#[test]
fn tlp_packet_header_constructs_from_bytes() {
    // MemRead32 bytes: DW0=0x00 (Fmt=000, Type=00000), TC/flags, Length=1
    // Followed by DW1+DW2 (req_id, tag, BE, address)
    let memrd32_header = [
        0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x20, 0x0F, 0xF6, 0x20, 0x00, 0x0C,
    ];

    let mr = TlpPacketHeader::new(memrd32_header.to_vec(), TlpMode::NonFlit).unwrap();
    assert_eq!(mr.tlp_type().unwrap(), TlpType::MemReadReq);
}

#[test]
fn test_tlp_packet_invalid_type() {
    // Test that TlpPacket::tlp_type properly returns error
    let invalid_data = vec![0x0f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(invalid_data, TlpMode::NonFlit).unwrap();
    let result = packet.tlp_type();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlpError::InvalidType);
}

// ============================================================================
// Tier-B: Atomic operand parsing via new_atomic_req()
// ============================================================================

#[test]
fn atomic_fetchadd_3dw_32_parses_operands() {
    const FMT_3DW_WITH_DATA: u8 = 0b010;
    const TY_ATOM_FETCH: u8 = 0b01100;

    // DW1+DW2 header bytes as MemRequest3DW expects:
    // req_id=0x1234, tag=0x56, address32=0x89ABCDEF
    let hdr = [0x12, 0x34, 0x56, 0x00, 0x89, 0xAB, 0xCD, 0xEF];

    // 32-bit operand (BE) = 0xDEADBEEF
    let operand = [0xDE, 0xAD, 0xBE, 0xEF];

    let mut data = Vec::new();
    data.extend_from_slice(&hdr);
    data.extend_from_slice(&operand);

    let pkt = mk_pkt(FMT_3DW_WITH_DATA, TY_ATOM_FETCH, &data);
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::FetchAddAtomicOpReq);

    let a = new_atomic_req(&pkt).unwrap();
    assert_eq!(a.op(), AtomicOp::FetchAdd);
    assert_eq!(a.width(), AtomicWidth::W32);
    assert_eq!(a.req_id(), 0x1234);
    assert_eq!(a.tag(), 0x56);
    assert_eq!(a.address(), 0x89ABCDEF);
    assert_eq!(a.operand0(), 0xDEADBEEF);
    assert_eq!(a.operand1(), None);
}

#[test]
fn atomic_swap_4dw_64_parses_operands() {
    const FMT_4DW_WITH_DATA: u8 = 0b011;
    const TY_ATOM_SWAP: u8 = 0b01101;

    // MemRequest4DW-like header in data:
    // req_id=0xBEEF, tag=0xA5, address64=0x1122334455667788
    let hdr = [
        0xBE, 0xEF, 0xA5, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];

    // 64-bit operand = 0x0102030405060708 (BE)
    let operand = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    let mut data = Vec::new();
    data.extend_from_slice(&hdr);
    data.extend_from_slice(&operand);

    let pkt = mk_pkt(FMT_4DW_WITH_DATA, TY_ATOM_SWAP, &data);
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::SwapAtomicOpReq);

    let a = new_atomic_req(&pkt).unwrap();
    assert_eq!(a.op(), AtomicOp::Swap);
    assert_eq!(a.width(), AtomicWidth::W64);
    assert_eq!(a.req_id(), 0xBEEF);
    assert_eq!(a.tag(), 0xA5);
    assert_eq!(a.address(), 0x1122334455667788);
    assert_eq!(a.operand0(), 0x0102030405060708);
    assert_eq!(a.operand1(), None);
}

#[test]
fn atomic_cas_3dw_32_parses_operands() {
    const FMT_3DW_WITH_DATA: u8 = 0b010;
    const TY_ATOM_CAS: u8 = 0b01110;

    let hdr = [
        0xCA, 0xFE, 0x11, 0x00, 0x00, 0x00, 0x10, 0x00, // address32 = 0x00001000
    ];

    // compare=0x11112222, swap=0x33334444
    let payload = [0x11, 0x11, 0x22, 0x22, 0x33, 0x33, 0x44, 0x44];

    let mut data = Vec::new();
    data.extend_from_slice(&hdr);
    data.extend_from_slice(&payload);

    let pkt = mk_pkt(FMT_3DW_WITH_DATA, TY_ATOM_CAS, &data);
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::CompareSwapAtomicOpReq);

    let a = new_atomic_req(&pkt).unwrap();
    assert_eq!(a.op(), AtomicOp::CompareSwap);
    assert_eq!(a.width(), AtomicWidth::W32);
    assert_eq!(a.req_id(), 0xCAFE);
    assert_eq!(a.tag(), 0x11);
    assert_eq!(a.address(), 0x00001000);
    assert_eq!(a.operand0(), 0x11112222);
    assert_eq!(a.operand1(), Some(0x33334444));
}

#[test]
fn atomic_fetchadd_rejects_invalid_operand_length() {
    const FMT_3DW_WITH_DATA: u8 = 0b010;
    const TY_ATOM_FETCH: u8 = 0b01100;

    let hdr = [0x12, 0x34, 0x56, 0x00, 0x89, 0xAB, 0xCD, 0xEF];

    // 6 bytes is invalid (not 4 or 8)
    let bad_operand = [1, 2, 3, 4, 5, 6];

    let mut data = Vec::new();
    data.extend_from_slice(&hdr);
    data.extend_from_slice(&bad_operand);

    let pkt = mk_pkt(FMT_3DW_WITH_DATA, TY_ATOM_FETCH, &data);
    assert_eq!(new_atomic_req(&pkt).unwrap_err(), TlpError::InvalidLength);
}

// ============================================================================
// DMWr: Deferrable Memory Write Request
// ============================================================================

#[test]
fn dmwr32_decode_via_tlppacket() {
    // DMWr32: fmt=010, type=11011 → byte0 = 0x5B
    let data = vec![0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let pkt = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
    assert_eq!(pkt.tlp_format().unwrap(), TlpFmt::WithDataHeader3DW);
}

#[test]
fn dmwr64_decode_via_tlppacket() {
    // DMWr64: fmt=011, type=11011 → byte0 = 0x7B
    let data = vec![0x7B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let pkt = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
    assert_eq!(pkt.tlp_format().unwrap(), TlpFmt::WithDataHeader4DW);
}

#[test]
fn dmwr_rejects_nodata_formats() {
    // NoData 3DW: fmt=000, type=11011 → byte0 = 0x1B
    let pkt1 = TlpPacket::new(
        vec![0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        TlpMode::NonFlit,
    )
    .unwrap();
    assert_eq!(
        pkt1.tlp_type().unwrap_err(),
        TlpError::UnsupportedCombination
    );

    // NoData 4DW: fmt=001, type=11011 → byte0 = 0x3B
    let pkt2 = TlpPacket::new(
        vec![0x3B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        TlpMode::NonFlit,
    )
    .unwrap();
    assert_eq!(
        pkt2.tlp_type().unwrap_err(),
        TlpError::UnsupportedCombination
    );
}

#[test]
fn dmwr_is_non_posted() {
    assert!(TlpType::DeferrableMemWriteReq.is_non_posted());
    // Normal MemWrite is posted (not non-posted)
    assert!(!TlpType::MemWriteReq.is_non_posted());
}

// ============================================================================
// Message TLP decode (was previously broken — Type[4:3]=10 = message)
// ============================================================================

#[test]
fn msg_req_decode_route_to_rc_3dw_no_data() {
    // Fmt=000 (3DW no data), Type=10000 (route to RC) → byte0 = 0x10
    let pkt = TlpPacket::new(
        vec![0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        TlpMode::NonFlit,
    )
    .unwrap();
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::MsgReq);
}

#[test]
fn msg_req_data_decode_route_to_rc_3dw_with_data() {
    // Fmt=010 (3DW with data), Type=10000 (route to RC) → byte0 = 0x50
    let pkt = TlpPacket::new(
        vec![0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        TlpMode::NonFlit,
    )
    .unwrap();
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::MsgReqData);
}

#[test]
#[allow(clippy::identity_op)] // 0b000 << 5 == 0 is intentional: documents the Fmt=000 field
fn msg_req_all_six_routing_subtypes_decode() {
    // Verify all 6 message routing sub-types decode to MsgReq (no-data Fmt=000)
    // Type[4:0]: 10000=routeRC, 10001=routeAddr, 10010=routeID,
    //            10011=broadcast, 10100=local, 10101=gathered
    for routing_bits in 0b10000u8..=0b10101u8 {
        let byte0 = (0b000 << 5) | (routing_bits & 0x1f); // Fmt=000
        let pkt = TlpPacket::new(
            vec![byte0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            TlpMode::NonFlit,
        )
        .unwrap();
        assert_eq!(
            pkt.tlp_type().unwrap(),
            TlpType::MsgReq,
            "Routing sub-type {:#07b} should decode to MsgReq",
            routing_bits
        );
    }
}

#[test]
fn msg_req_data_all_six_routing_subtypes_decode() {
    // Verify all 6 routing sub-types with Fmt=010 decode to MsgReqData
    for routing_bits in 0b10000u8..=0b10101u8 {
        let byte0 = (0b010 << 5) | (routing_bits & 0x1f); // Fmt=010
        let pkt = TlpPacket::new(
            vec![byte0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            TlpMode::NonFlit,
        )
        .unwrap();
        assert_eq!(
            pkt.tlp_type().unwrap(),
            TlpType::MsgReqData,
            "Routing sub-type {:#07b} with WithData3DW should decode to MsgReqData",
            routing_bits
        );
    }
}

#[test]
fn msg_req_end_to_end_path_with_new_msg_req() {
    // Full end-to-end: packet decode -> tlp_type() -> new_msg_req(pkt.data()) -> field access
    // Fmt=001 (4DW no data), Type=10000 (route to RC) → byte0 = 0x30
    // DW1: req_id=0xBEEF, tag=0xA5, msg_code=0x7E
    // DW2-DW3: route words (zero) — 4DW gives 12 bytes in pkt.data(), satisfying new_msg_req
    let pkt_bytes = vec![
        0x30, 0x00, 0x00, 0x00, // DW0: MsgReq 4DW route-to-RC
        0xBE, 0xEF, 0xA5, 0x7E, // DW1: req_id=0xBEEF, tag=0xA5, msg_code=0x7E
        0x00, 0x00, 0x00, 0x00, // DW2: route word
        0x00, 0x00, 0x00, 0x00, // DW3: route word
    ];
    let pkt = TlpPacket::new(pkt_bytes, TlpMode::NonFlit).unwrap();
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::MsgReq);

    let msg = new_msg_req(pkt.data()).unwrap();
    assert_eq!(msg.req_id(), 0xBEEF);
    assert_eq!(msg.tag(), 0xA5);
    assert_eq!(msg.msg_code(), 0x7E);
}

// ============================================================================
// TLP Prefix decode (was previously broken — Fmt=0b100)
// ============================================================================

#[test]
fn local_tlp_prefix_decode_type4_zero() {
    // Fmt=100 (TlpPrefix), Type[4]=0 → LocalTlpPrefix
    // byte0 = (0b100 << 5) | 0b00000 = 0x80
    let pkt = TlpPacket::new(vec![0x80, 0x00, 0x00, 0x00], TlpMode::NonFlit).unwrap();
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::LocalTlpPrefix);
}

#[test]
fn end_to_end_tlp_prefix_decode_type4_one() {
    // Fmt=100 (TlpPrefix), Type[4]=1 → EndToEndTlpPrefix
    // byte0 = (0b100 << 5) | 0b10000 = 0x90
    let pkt = TlpPacket::new(vec![0x90, 0x00, 0x00, 0x00], TlpMode::NonFlit).unwrap();
    assert_eq!(pkt.tlp_type().unwrap(), TlpType::EndToEndTlpPrefix);
}

#[test]
fn tlp_prefix_local_and_end_to_end_distinguished_by_bit4() {
    // All Type values with bit 4=0 → LocalTlpPrefix
    for type_bits in [0b00000u8, 0b00001, 0b00010, 0b00100, 0b01010] {
        let byte0 = (0b100u8 << 5) | (type_bits & 0x1f);
        let pkt = TlpPacket::new(vec![byte0, 0x00, 0x00, 0x00], TlpMode::NonFlit).unwrap();
        assert_eq!(
            pkt.tlp_type().unwrap(),
            TlpType::LocalTlpPrefix,
            "byte0={:#04x} (Type[4]=0) should be LocalTlpPrefix",
            byte0
        );
    }
    // All Type values with bit 4=1 → EndToEndTlpPrefix
    for type_bits in [0b10000u8, 0b10001, 0b10010, 0b11011] {
        let byte0 = (0b100u8 << 5) | (type_bits & 0x1f);
        let pkt = TlpPacket::new(vec![byte0, 0x00, 0x00, 0x00], TlpMode::NonFlit).unwrap();
        assert_eq!(
            pkt.tlp_type().unwrap(),
            TlpType::EndToEndTlpPrefix,
            "byte0={:#04x} (Type[4]=1) should be EndToEndTlpPrefix",
            byte0
        );
    }
}

#[test]
fn prefix_types_are_not_non_posted() {
    // Prefix objects are not transactions — is_non_posted() is false
    assert!(!TlpType::LocalTlpPrefix.is_non_posted());
    assert!(!TlpType::EndToEndTlpPrefix.is_non_posted());
}
