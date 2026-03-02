use rtlp_lib::*;

// ── helpers ───────────────────────────────────────────────────────────────

fn mk_pkt(dw0_fmt: u8, dw0_type: u8, data: &[u8]) -> TlpPacket {
    let mut v = Vec::with_capacity(4 + data.len());
    v.push((dw0_fmt << 5) | (dw0_type & 0x1f));
    v.push(0);
    v.push(0);
    v.push(0);
    v.extend_from_slice(data);
    TlpPacket::new(v)
}

#[test]
fn test_tlp_packet() {
    let d = vec![0x04, 0x00, 0x00, 0x01, 0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10];
    let tlp = TlpPacket::new(d);

    assert_eq!(tlp.get_tlp_type().unwrap(), TlpType::ConfType0ReadReq);
    assert_eq!(tlp.get_data(), vec![0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);
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
fn is_memreq_tag_works() {
    let mr3dw1 = MemRequest3DW([0x00, 0x00, 0x20, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);
    let mr3dw2 = MemRequest3DW([0x00, 0x00, 0x01, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);
    let mr3dw3 = MemRequest3DW([0x00, 0x00, 0x10, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);
    let mr3dw4 = MemRequest3DW([0x00, 0x00, 0x81, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);

    assert_eq!(0x20, mr3dw1.tag());
    assert_eq!(0x01, mr3dw2.tag());
    assert_eq!(0x10, mr3dw3.tag());
    assert_eq!(0x81, mr3dw4.tag());

    let mr4dw1 = MemRequest4DW([0x00, 0x00, 0x01, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00]);
    let mr4dw2 = MemRequest4DW([0x00, 0x00, 0x10, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00]);
    let mr4dw3 = MemRequest4DW([0x00, 0x00, 0x81, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00]);
    let mr4dw4 = MemRequest4DW([0x00, 0x00, 0xFF, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00]);
    let mr4dw5 = MemRequest4DW([0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00]);

    assert_eq!(0x01, mr4dw1.tag());
    assert_eq!(0x10, mr4dw2.tag());
    assert_eq!(0x81, mr4dw3.tag());
    assert_eq!(0xFF, mr4dw4.tag());
    assert_eq!(0x00, mr4dw5.tag());
}

#[test]
fn is_memreq_3dw_address_works() {
    let memreq_3dw = [0x00, 0x00, 0x20, 0x0F, 0xF6, 0x20, 0x00, 0x0C];
    let mr = MemRequest3DW(memreq_3dw);

    assert_eq!(0xF620000C, mr.address());
}

#[test]
fn is_memreq_4dw_address_works() {
    let memreq_4dw = [0x00, 0x00, 0x20, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00];
    let mr = MemRequest4DW(memreq_4dw);

    assert_eq!(0x17fc0000000, mr.address());
}

#[test]
fn is_tlppacket_creates() {
    let memrd32_header = [0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x20, 0x0F, 0xF6, 0x20, 0x00, 0x0C];

    let mr = TlpPacketHeader::new(memrd32_header.to_vec());
    assert_eq!(mr.get_tlp_type().unwrap(), TlpType::MemReadReq);
}

#[test]
fn test_tlp_packet_invalid_type() {
    // Test that TlpPacket::get_tlp_type properly returns error
    let invalid_data = vec![0x0f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(invalid_data);
    let result = packet.get_tlp_type();
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
    let hdr = [
        0x12, 0x34, 0x56, 0x00,
        0x89, 0xAB, 0xCD, 0xEF,
    ];

    // 32-bit operand (BE) = 0xDEADBEEF
    let operand = [0xDE, 0xAD, 0xBE, 0xEF];

    let mut data = Vec::new();
    data.extend_from_slice(&hdr);
    data.extend_from_slice(&operand);

    let pkt = mk_pkt(FMT_3DW_WITH_DATA, TY_ATOM_FETCH, &data);
    assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::FetchAddAtomicOpReq);

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
        0xBE, 0xEF, 0xA5, 0x00,
        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
    ];

    // 64-bit operand = 0x0102030405060708 (BE)
    let operand = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08];

    let mut data = Vec::new();
    data.extend_from_slice(&hdr);
    data.extend_from_slice(&operand);

    let pkt = mk_pkt(FMT_4DW_WITH_DATA, TY_ATOM_SWAP, &data);
    assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::SwapAtomicOpReq);

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
        0xCA, 0xFE, 0x11, 0x00,
        0x00, 0x00, 0x10, 0x00,  // address32 = 0x00001000
    ];

    // compare=0x11112222, swap=0x33334444
    let payload = [0x11,0x11,0x22,0x22, 0x33,0x33,0x44,0x44];

    let mut data = Vec::new();
    data.extend_from_slice(&hdr);
    data.extend_from_slice(&payload);

    let pkt = mk_pkt(FMT_3DW_WITH_DATA, TY_ATOM_CAS, &data);
    assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::CompareSwapAtomicOpReq);

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

    let hdr = [
        0x12, 0x34, 0x56, 0x00,
        0x89, 0xAB, 0xCD, 0xEF,
    ];

    // 6 bytes is invalid (not 4 or 8)
    let bad_operand = [1,2,3,4,5,6];

    let mut data = Vec::new();
    data.extend_from_slice(&hdr);
    data.extend_from_slice(&bad_operand);

    let pkt = mk_pkt(FMT_3DW_WITH_DATA, TY_ATOM_FETCH, &data);
    assert_eq!(new_atomic_req(&pkt).unwrap_err(), TlpError::InvalidLength);
}
