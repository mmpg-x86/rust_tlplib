/// API Contract Tests
///
/// These tests verify the public API surface and contracts.
/// They should catch any breaking changes to the library's interface.
use rtlp_lib::*;

// ============================================================================
// DeviceID API Tests
// ============================================================================

#[test]
fn device_id_type_exists_and_is_public() {
    let id = DeviceID::from_u16(0x0218);
    assert_eq!(id.bus(), 0x02);
    assert_eq!(id.device(), 0x03);
    assert_eq!(id.function(), 0x00);
    assert_eq!(id.to_u16(), 0x0218);
}

#[test]
fn device_id_implements_display_fromstr_and_conversions() {
    let id: DeviceID = "02:03.1".parse().unwrap();
    assert_eq!(format!("{id}"), "02:03.1");
    assert_eq!(u16::from(id), 0x0219);
    assert_eq!(DeviceID::from(0x0219), id);
}

#[test]
fn device_id_parse_error_is_public_std_error() {
    let err = "02:20.0".parse::<DeviceID>().unwrap_err();
    let boxed: Box<dyn std::error::Error> = Box::new(err);
    assert!(!boxed.to_string().is_empty());
}

// ============================================================================
// Error Type API Tests
// ============================================================================

#[test]
fn error_type_exists_and_is_public() {
    // Ensure TlpError is accessible and has expected variants
    let _err1: TlpError = TlpError::InvalidFormat;
    let _err2: TlpError = TlpError::InvalidType;
    let _err3: TlpError = TlpError::UnsupportedCombination;
    let _err4: TlpError = TlpError::InvalidLength;
    let _err5: TlpError = TlpError::NotImplemented;
    let _err6: TlpError = TlpError::MissingMandatoryOhc;
}

#[test]
fn error_type_implements_debug() {
    let err = TlpError::InvalidFormat;
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("InvalidFormat"));
}

#[test]
fn error_type_implements_partialeq() {
    assert_eq!(TlpError::InvalidFormat, TlpError::InvalidFormat);
    assert_ne!(TlpError::InvalidFormat, TlpError::InvalidType);
}

#[test]
fn error_type_implements_display() {
    // Verify all variants produce non-empty human-readable messages
    let variants = [
        TlpError::InvalidFormat,
        TlpError::InvalidType,
        TlpError::UnsupportedCombination,
        TlpError::InvalidLength,
        TlpError::NotImplemented,
        TlpError::MissingMandatoryOhc,
    ];
    for e in &variants {
        let s = format!("{e}");
        assert!(!s.is_empty(), "Display for {e:?} must not be empty");
    }
}

#[test]
fn error_type_implements_std_error() {
    // TlpError must be usable as Box<dyn std::error::Error>
    fn returns_box_error() -> Result<(), Box<dyn std::error::Error>> {
        let _ = TlpPacket::new(vec![], TlpMode::NonFlit)?;
        Ok(())
    }
    let err = returns_box_error().unwrap_err();
    // The Display message should be meaningful
    assert!(!err.to_string().is_empty());
}

#[test]
fn error_not_implemented_exists_and_is_distinct() {
    let e = TlpError::NotImplemented;
    assert_eq!(e, TlpError::NotImplemented);
    assert_ne!(e, TlpError::InvalidFormat);
    assert_ne!(e, TlpError::InvalidType);
    assert_ne!(e, TlpError::UnsupportedCombination);
    assert_ne!(e, TlpError::InvalidLength);
    let s = format!("{:?}", e);
    assert!(s.contains("NotImplemented"));
}

// ============================================================================
// TlpMode Enum API Tests
// ============================================================================

#[test]
fn tlp_mode_enum_has_expected_variants() {
    let _m1: TlpMode = TlpMode::NonFlit;
    let _m2: TlpMode = TlpMode::Flit;
}

#[test]
#[allow(clippy::clone_on_copy)]
fn tlp_mode_implements_debug_clone_copy_partialeq() {
    assert_eq!(TlpMode::NonFlit, TlpMode::NonFlit);
    assert_ne!(TlpMode::NonFlit, TlpMode::Flit);

    let m = TlpMode::NonFlit;
    let m2 = m; // Copy
    let m3 = m.clone(); // Clone
    assert_eq!(m2, TlpMode::NonFlit);
    assert_eq!(m3, TlpMode::NonFlit);

    let s = format!("{:?}", TlpMode::NonFlit);
    assert!(s.contains("NonFlit"));
    let s2 = format!("{:?}", TlpMode::Flit);
    assert!(s2.contains("Flit"));
}

#[test]
fn tlp_mode_flit_packet_new_succeeds() {
    // TlpMode::Flit is now implemented -- NOP flit (type 0x00, 1 DW header)
    let bytes = vec![0x00u8; 4];
    let pkt = TlpPacket::new(bytes, TlpMode::Flit).unwrap();
    assert_eq!(pkt.flit_type(), Some(FlitTlpType::Nop));
    assert!(pkt.data().is_empty());
}

#[test]
fn tlp_mode_flit_returns_not_implemented_for_header() {
    // TlpPacketHeader::new() with Flit still returns NotImplemented
    let bytes = vec![0x00u8; 4];
    assert_eq!(
        TlpPacketHeader::new(bytes, TlpMode::Flit).err().unwrap(),
        TlpError::NotImplemented
    );
}

// ============================================================================
// TlpFmt Enum API Tests
// ============================================================================

#[test]
fn tlp_fmt_enum_has_expected_variants() {
    let _fmt1: TlpFmt = TlpFmt::NoDataHeader3DW;
    let _fmt2: TlpFmt = TlpFmt::NoDataHeader4DW;
    let _fmt3: TlpFmt = TlpFmt::WithDataHeader3DW;
    let _fmt4: TlpFmt = TlpFmt::WithDataHeader4DW;
    let _fmt5: TlpFmt = TlpFmt::TlpPrefix;
}

#[test]
fn tlp_fmt_try_from_u8_valid_values() {
    assert!(TlpFmt::try_from(0b000).is_ok());
    assert!(TlpFmt::try_from(0b001).is_ok());
    assert!(TlpFmt::try_from(0b010).is_ok());
    assert!(TlpFmt::try_from(0b011).is_ok());
    assert!(TlpFmt::try_from(0b100).is_ok());
}

#[test]
fn tlp_fmt_try_from_u8_invalid_values() {
    assert!(TlpFmt::try_from(0b101).is_err());
    assert!(TlpFmt::try_from(0b110).is_err());
    assert!(TlpFmt::try_from(0b111).is_err());
    assert!(TlpFmt::try_from(8).is_err());
}

// ============================================================================
// TlpType Enum API Tests
// ============================================================================

#[test]
fn tlp_type_enum_has_all_expected_variants() {
    // Memory requests
    let _t1: TlpType = TlpType::MemReadReq;
    let _t2: TlpType = TlpType::MemReadLockReq;
    let _t3: TlpType = TlpType::MemWriteReq;

    // IO requests
    let _t4: TlpType = TlpType::IOReadReq;
    let _t5: TlpType = TlpType::IOWriteReq;

    // Configuration requests
    let _t6: TlpType = TlpType::ConfType0ReadReq;
    let _t7: TlpType = TlpType::ConfType0WriteReq;
    let _t8: TlpType = TlpType::ConfType1ReadReq;
    let _t9: TlpType = TlpType::ConfType1WriteReq;

    // Messages
    let _t10: TlpType = TlpType::MsgReq;
    let _t11: TlpType = TlpType::MsgReqData;

    // Completions
    let _t12: TlpType = TlpType::Cpl;
    let _t13: TlpType = TlpType::CplData;
    let _t14: TlpType = TlpType::CplLocked;
    let _t15: TlpType = TlpType::CplDataLocked;

    // Atomic operations
    let _t16: TlpType = TlpType::FetchAddAtomicOpReq;
    let _t17: TlpType = TlpType::SwapAtomicOpReq;
    let _t18: TlpType = TlpType::CompareSwapAtomicOpReq;

    // Deferrable Memory Write
    let _t19: TlpType = TlpType::DeferrableMemWriteReq;

    // Prefixes
    let _t20: TlpType = TlpType::LocalTlpPrefix;
    let _t21: TlpType = TlpType::EndToEndTlpPrefix;
}

#[test]
fn tlp_type_implements_partialeq() {
    assert_eq!(TlpType::MemReadReq, TlpType::MemReadReq);
    assert_ne!(TlpType::MemReadReq, TlpType::MemWriteReq);
}

#[test]
fn tlp_type_implements_debug() {
    let tlp_type = TlpType::MemReadReq;
    let debug_str = format!("{:?}", tlp_type);
    assert!(debug_str.contains("MemReadReq"));
}

// ============================================================================
// TlpPacket API Tests
// ============================================================================

#[test]
fn tlp_packet_new_constructor_exists() {
    let data = vec![0x00; 12];
    let _packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
}

#[test]
fn tlp_packet_tlp_type_returns_result() {
    let data = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    let result: Result<TlpType, TlpError> = packet.tlp_type();
    assert!(result.is_ok());
}

#[test]
fn tlp_packet_tlp_type_valid_mem_read() {
    let data = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    assert_eq!(packet.tlp_type().unwrap(), TlpType::MemReadReq);
}

#[test]
fn tlp_packet_tlp_type_valid_mem_write() {
    let data = vec![0x40, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    assert_eq!(packet.tlp_type().unwrap(), TlpType::MemWriteReq);
}

#[test]
fn tlp_packet_tlp_type_valid_config_type0_read() {
    let data = vec![0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    assert_eq!(packet.tlp_type().unwrap(), TlpType::ConfType0ReadReq);
}

#[test]
fn tlp_packet_tlp_type_error_invalid_format() {
    let data = vec![0xa0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    let result = packet.tlp_type();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlpError::InvalidFormat);
}

#[test]
fn tlp_packet_tlp_type_error_invalid_type() {
    let data = vec![0x0f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    let result = packet.tlp_type();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), TlpError::InvalidType);
}

#[test]
fn tlp_packet_tlp_format_exists() {
    let data = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    let format: Result<TlpFmt, _> = packet.tlp_format();
    assert!(format.is_ok());
}

/// API contract test: `get_data()` is deprecated but must continue to work
/// until it is fully removed in a future semver break.
/// See also `tlp_packet_data_method_exists` for the new non-allocating form.
#[test]
#[allow(deprecated)]
fn tlp_packet_get_data_exists() {
    let data = vec![0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
    let packet = TlpPacket::new(data.clone(), TlpMode::NonFlit).unwrap();
    let returned_data = packet.get_data(); // deprecated — tests backward compat
    assert_eq!(returned_data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn tlp_packet_data_method_exists() {
    // Preferred non-allocating form: data() returns &[u8]
    let data = vec![0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    assert_eq!(packet.data(), [0xAA, 0xBB, 0xCC, 0xDD]);
}

// ============================================================================
// TlpPacketHeader API Tests
// ============================================================================

#[test]
fn tlp_packet_header_new_constructor_exists() {
    let data = vec![0x00; 12];
    let _header = TlpPacketHeader::new(data, TlpMode::NonFlit).unwrap();
}

#[test]
fn tlp_packet_header_tlp_type_returns_result() {
    let data = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let header = TlpPacketHeader::new(data, TlpMode::NonFlit).unwrap();
    let result: Result<TlpType, TlpError> = header.tlp_type();
    assert!(result.is_ok());
}

// ============================================================================
// MemRequest Trait API Tests
// ============================================================================

#[test]
fn memrequest_trait_exists_and_is_public() {
    // Test that MemRequest trait methods are accessible
    let mr3dw = MemRequest3DW([0x00, 0x00, 0x20, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);
    let _req_id = mr3dw.req_id();
    let _tag = mr3dw.tag();
    let _last_be = mr3dw.ldwbe();
    let _first_be = mr3dw.fdwbe();
    let _addr = mr3dw.address();
}

#[test]
fn memrequest_3dw_struct_is_public() {
    let _mr = MemRequest3DW([0; 8]);
}

#[test]
fn memrequest_4dw_struct_is_public() {
    let _mr = MemRequest4DW([0; 12]);
}

#[test]
fn memrequest_3dw_trait_methods_return_expected_types() {
    let mr = MemRequest3DW([0x00, 0x00, 0x20, 0x0F, 0xF6, 0x20, 0x00, 0x0C]);
    let _req_id: u16 = mr.req_id();
    let _tag: u8 = mr.tag();
    let _last_be: u8 = mr.ldwbe();
    let _first_be: u8 = mr.fdwbe();
    let _addr: u64 = mr.address();
}

#[test]
fn memrequest_4dw_trait_methods_return_expected_types() {
    let mr = MemRequest4DW([
        0x00, 0x00, 0x20, 0x0F, 0x00, 0x00, 0x01, 0x7f, 0xc0, 0x00, 0x00, 0x00,
    ]);
    let _req_id: u16 = mr.req_id();
    let _tag: u8 = mr.tag();
    let _last_be: u8 = mr.ldwbe();
    let _first_be: u8 = mr.fdwbe();
    let _addr: u64 = mr.address();
}

// ============================================================================
// ConfigurationRequest Trait API Tests
// ============================================================================

#[test]
fn configuration_request_trait_exists() {
    let conf = ConfigRequest([0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);
    let _req_id = conf.req_id();
    let _tag = conf.tag();
    let _bus_nr = conf.bus_nr();
    let _dev_nr = conf.dev_nr();
    let _func_nr = conf.func_nr();
    let _ext_reg_nr = conf.ext_reg_nr();
    let _reg_nr = conf.reg_nr();
}

#[test]
fn configuration_request_struct_is_public() {
    let _conf = ConfigRequest([0; 8]);
}

#[test]
fn configuration_request_trait_methods_return_expected_types() {
    let conf = ConfigRequest([0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);
    let _req_id: u16 = conf.req_id();
    let _tag: u8 = conf.tag();
    let _bus_nr: u8 = conf.bus_nr();
    let _dev_nr: u8 = conf.dev_nr();
    let _func_nr: u8 = conf.func_nr();
    let _ext_reg_nr: u8 = conf.ext_reg_nr();
    let _reg_nr: u8 = conf.reg_nr();
}

// ============================================================================
// CompletionRequest Trait API Tests
// ============================================================================

#[test]
fn completion_request_trait_exists() {
    let cmpl = CompletionReqDW23([0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);
    let _cmpl_id = cmpl.cmpl_id();
    let _cmpl_stat = cmpl.cmpl_stat();
    let _bcm = cmpl.bcm();
    let _byte_cnt = cmpl.byte_cnt();
    let _req_id = cmpl.req_id();
    let _tag = cmpl.tag();
    let _laddr = cmpl.laddr();
}

#[test]
fn completion_request_struct_is_public() {
    let _cmpl = CompletionReqDW23([0; 8]);
}

#[test]
fn completion_request_trait_methods_return_expected_types() {
    let cmpl = CompletionReqDW23([0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10]);
    let _cmpl_id: u16 = cmpl.cmpl_id();
    let _cmpl_stat: u8 = cmpl.cmpl_stat();
    let _bcm: u8 = cmpl.bcm();
    let _byte_cnt: u16 = cmpl.byte_cnt();
    let _req_id: u16 = cmpl.req_id();
    let _tag: u8 = cmpl.tag();
    let _laddr: u8 = cmpl.laddr();
}

// ============================================================================
// MessageRequest Trait API Tests
// ============================================================================

#[test]
fn message_request_trait_exists() {
    let msg = MessageReqDW24([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    ]);
    let _req_id = msg.req_id();
    let _msg_code = msg.msg_code();
    let _tag = msg.tag();
}

#[test]
fn message_request_struct_is_public() {
    let _msg = MessageReqDW24([0; 12]);
}

#[test]
fn message_request_trait_methods_return_expected_types() {
    let msg = MessageReqDW24([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    ]);
    let _req_id: u16 = msg.req_id();
    let _msg_code: u8 = msg.msg_code();
    let _tag: u8 = msg.tag();
}

// ============================================================================
// Factory Functions API Tests
// ============================================================================

#[test]
fn new_mem_req_factory_exists() {
    let bytes = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let format = TlpFmt::NoDataHeader3DW;
    let result: Result<Box<dyn MemRequest>, TlpError> = new_mem_req(bytes, &format);
    assert!(result.is_ok());
    let result = result.unwrap();
    // Factory returns Box<dyn MemRequest>, verify it has the expected methods
    let _req_id = result.req_id();
    let _addr = result.address();
}

#[test]
fn new_conf_req_factory_exists() {
    let bytes = vec![0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let result = new_conf_req(bytes).unwrap();
    // Factory returns Box<dyn ConfigurationRequest>, verify it has the expected methods
    let _req_id = result.req_id();
    let _bus_nr = result.bus_nr();
}

#[test]
fn new_cmpl_req_factory_exists() {
    let bytes = vec![0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = new_cmpl_req(bytes).unwrap();
    // Factory returns Box<dyn CompletionRequest>, verify it has the expected methods
    let _req_id = result.req_id();
    let _cmpl_stat = result.cmpl_stat();
}

#[test]
fn new_msg_req_factory_exists() {
    let bytes = vec![
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = new_msg_req(bytes).unwrap();
    // Factory returns Box<dyn MessageRequest>, verify it has the expected methods
    let _req_id = result.req_id();
    let _msg_code = result.msg_code();
}

#[test]
fn new_atomic_req_factory_exists() {
    // FetchAdd 3DW: DW0 + 8-byte header + 4-byte W32 operand
    // DW0: fmt=0b010 (WithData3DW), type=0b01100 (FetchAdd) → byte0 = 0x4C
    let mut bytes = vec![0x4C, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&[0u8; 12]); // 8-byte hdr + 4-byte operand
    let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
    let result = new_atomic_req(&pkt);
    assert!(result.is_ok());
    let ar = result.unwrap();
    let _op = ar.op();
    let _width = ar.width();
    let _rid = ar.req_id();
    let _tag = ar.tag();
    let _addr = ar.address();
    let _op0 = ar.operand0();
    let _op1 = ar.operand1();
}

// ============================================================================
// AtomicOp / AtomicWidth / AtomicRequest API Tests
// ============================================================================

#[test]
fn atomic_op_enum_exists_and_is_public() {
    let _op1: AtomicOp = AtomicOp::FetchAdd;
    let _op2: AtomicOp = AtomicOp::Swap;
    let _op3: AtomicOp = AtomicOp::CompareSwap;
}

#[test]
fn atomic_op_implements_debug_and_partialeq() {
    assert_eq!(AtomicOp::FetchAdd, AtomicOp::FetchAdd);
    assert_ne!(AtomicOp::FetchAdd, AtomicOp::Swap);
    let s = format!("{:?}", AtomicOp::CompareSwap);
    assert!(s.contains("CompareSwap"));
}

#[test]
fn atomic_width_enum_exists_and_is_public() {
    let _w1: AtomicWidth = AtomicWidth::W32;
    let _w2: AtomicWidth = AtomicWidth::W64;
}

#[test]
fn atomic_width_implements_debug_and_partialeq() {
    assert_eq!(AtomicWidth::W32, AtomicWidth::W32);
    assert_ne!(AtomicWidth::W32, AtomicWidth::W64);
    let s = format!("{:?}", AtomicWidth::W64);
    assert!(s.contains("W64"));
}

#[test]
fn atomic_req_returns_err_for_non_atomic_type() {
    // MemRead 3DW NoData: fmt=0b000, type=0b00000 → byte0 = 0x00
    let mut bytes = vec![0x00, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&[0u8; 16]);
    let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
    let result = new_atomic_req(&pkt);
    assert_eq!(result.err().unwrap(), TlpError::UnsupportedCombination);
}

#[test]
fn atomic_req_returns_err_for_nodata_format() {
    // Swap type with NoData3DW fmt: fmt=0b000, type=0b01101 → byte0 = 0x0D
    // tlp_type() returns UnsupportedCombination for this combo
    let mut bytes = vec![0x0D, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&[0u8; 16]);
    let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
    let result = new_atomic_req(&pkt);
    assert_eq!(result.err().unwrap(), TlpError::UnsupportedCombination);
}

#[test]
fn atomic_req_returns_err_for_short_payload() {
    // FetchAdd 3DW: DW0 + only 4 bytes of data (needs 12)
    // fmt=0b010, type=0b01100 → byte0 = 0x4C
    let mut bytes = vec![0x4C, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&[0u8; 4]);
    let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
    let result = new_atomic_req(&pkt);
    assert_eq!(result.err().unwrap(), TlpError::InvalidLength);
}

// ============================================================================
// API Stability Tests - Ensure no accidental changes
// ============================================================================

#[test]
fn api_all_expected_public_types_are_available() {
    // This test will fail to compile if any public type is removed or renamed
    use rtlp_lib::{
        AtomicOp,
        AtomicWidth,
        CompletionReqDW23,
        ConfigRequest,
        FlitDW0,
        FlitOhcA,
        // Flit mode public API
        FlitTlpType,
        MemRequest3DW,
        MemRequest4DW,
        MessageReqDW24,
        TlpError,
        TlpFmt,
        TlpMode,
        TlpPacket,
        TlpPacketHeader,
        TlpType,
        new_atomic_req,
        new_cmpl_req,
        new_conf_req,
        new_mem_req,
        new_msg_req,
    };

    // Use types to prevent unused warnings
    let _: Option<TlpError> = None;
    let _: Option<TlpFmt> = None;
    let _: Option<TlpType> = None;
    let _: Option<TlpMode> = None;
    let _: Option<TlpPacket> = None;
    let _: Option<TlpPacketHeader> = None;
    // Bitfield structs have generic parameters, use with concrete type
    let _: Option<MemRequest3DW<[u8; 8]>> = None;
    let _: Option<MemRequest4DW<[u8; 12]>> = None;
    let _: Option<ConfigRequest<[u8; 8]>> = None;
    let _: Option<CompletionReqDW23<[u8; 8]>> = None;
    let _: Option<MessageReqDW24<[u8; 12]>> = None;

    // All four factory functions accept impl Into<Vec<u8>>.
    // Calling with an empty Vec<u8> satisfies inference and proves importability.
    let _ = new_mem_req(vec![0u8; 0], &TlpFmt::NoDataHeader3DW);
    let _ = new_conf_req(vec![0u8; 0]);
    let _ = new_cmpl_req(vec![0u8; 0]);
    let _ = new_msg_req(vec![0u8; 0]);
    let _ = new_atomic_req;
    let _: Option<AtomicOp> = None;
    let _: Option<AtomicWidth> = None;

    // Flit mode public API — will fail to compile if removed or renamed
    let _: Option<FlitTlpType> = None;
    let _: Option<FlitDW0> = None;
    let _: Option<FlitOhcA> = None;
}

#[test]
fn flit_ohc_a_struct_is_public_and_constructible() {
    // OHC-A word [0x01, 0x23, 0x45, 0x0F]: PASID=0x12345, fdwbe=0xF, ldwbe=0x0
    let ohc = FlitOhcA::from_bytes(&[0x01, 0x23, 0x45, 0x0F]).unwrap();
    let _: u32 = ohc.pasid;
    let _: u8 = ohc.fdwbe;
    let _: u8 = ohc.ldwbe;
    assert_eq!(ohc.pasid, 0x12345);
    assert_eq!(ohc.fdwbe, 0xF);
    assert_eq!(ohc.ldwbe, 0x0);
}

#[test]
fn flit_ohc_a_short_slice_returns_invalid_length() {
    assert_eq!(
        FlitOhcA::from_bytes(&[0x00, 0x00, 0x00]).err().unwrap(),
        TlpError::InvalidLength
    );
}

#[test]
fn flit_missing_mandatory_ohc_error_is_distinct() {
    let e = TlpError::MissingMandatoryOhc;
    assert_eq!(e, TlpError::MissingMandatoryOhc);
    assert_ne!(e, TlpError::NotImplemented);
    assert_ne!(e, TlpError::InvalidType);
    let s = format!("{:?}", e);
    assert!(s.contains("MissingMandatoryOhc"));
}

#[test]
fn flit_validate_mandatory_ohc_non_mandatory_types_always_pass() {
    // Non-mandatory types succeed even without OHC
    let nop_dw0 = FlitDW0::from_dw0(&[0x00, 0x00, 0x00, 0x00]).unwrap(); // Nop, ohc=0
    assert!(nop_dw0.validate_mandatory_ohc().is_ok());

    let mwr_dw0 = FlitDW0::from_dw0(&[0x40, 0x00, 0x00, 0x01]).unwrap(); // MemWrite32, ohc=0
    assert!(mwr_dw0.validate_mandatory_ohc().is_ok());
}

// ============================================================================
// FlitTlpType API Tests
// ============================================================================

#[test]
fn flit_tlp_type_enum_has_expected_variants() {
    let _: FlitTlpType = FlitTlpType::Nop;
    let _: FlitTlpType = FlitTlpType::MemRead32;
    let _: FlitTlpType = FlitTlpType::UioMemRead;
    let _: FlitTlpType = FlitTlpType::MsgToRc;
    let _: FlitTlpType = FlitTlpType::MemWrite32;
    let _: FlitTlpType = FlitTlpType::IoWrite;
    let _: FlitTlpType = FlitTlpType::CfgWrite0;
    let _: FlitTlpType = FlitTlpType::FetchAdd32;
    let _: FlitTlpType = FlitTlpType::CompareSwap32;
    let _: FlitTlpType = FlitTlpType::DeferrableMemWrite32;
    let _: FlitTlpType = FlitTlpType::UioMemWrite;
    let _: FlitTlpType = FlitTlpType::MsgDToRc;
    let _: FlitTlpType = FlitTlpType::LocalTlpPrefix;
}

#[test]
fn flit_tlp_type_implements_debug_and_partialeq() {
    assert_eq!(FlitTlpType::Nop, FlitTlpType::Nop);
    assert_ne!(FlitTlpType::Nop, FlitTlpType::MemRead32);
    let s = format!("{:?}", FlitTlpType::MemRead32);
    assert!(s.contains("MemRead32"));
}

#[test]
fn flit_tlp_type_try_from_u8_valid_type_codes() {
    assert!(FlitTlpType::try_from(0x00u8).is_ok()); // Nop
    assert!(FlitTlpType::try_from(0x03u8).is_ok()); // MemRead32
    assert!(FlitTlpType::try_from(0x40u8).is_ok()); // MemWrite32
    assert!(FlitTlpType::try_from(0x4Eu8).is_ok()); // CompareSwap32
    assert!(FlitTlpType::try_from(0x8Du8).is_ok()); // LocalTlpPrefix
}

#[test]
fn flit_tlp_type_try_from_u8_unknown_returns_invalid_type() {
    assert_eq!(
        FlitTlpType::try_from(0xFFu8).err().unwrap(),
        TlpError::InvalidType
    );
    assert_eq!(
        FlitTlpType::try_from(0x01u8).err().unwrap(),
        TlpError::InvalidType
    );
}

#[test]
fn flit_dw0_struct_is_public_and_constructible() {
    let dw0 = FlitDW0::from_dw0(&[0x00, 0x00, 0x00, 0x00]).unwrap();
    let _: FlitTlpType = dw0.tlp_type;
    let _: u8 = dw0.tc;
    let _: u8 = dw0.ohc;
    let _: u8 = dw0.ts;
    let _: u8 = dw0.attr;
    let _: u16 = dw0.length;
    let _: u8 = dw0.ohc_count();
    let _: usize = dw0.total_bytes();
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn tlp_packet_mode_returns_correct_mode() {
    let non_flit = TlpPacket::new(vec![0x00, 0x00, 0x00, 0x00], TlpMode::NonFlit).unwrap();
    assert_eq!(non_flit.mode(), TlpMode::NonFlit);

    let flit = TlpPacket::new(vec![0x00, 0x00, 0x00, 0x00], TlpMode::Flit).unwrap();
    assert_eq!(flit.mode(), TlpMode::Flit);
}

/// mode() is the idiomatic dispatch predicate — flit_type().is_some() is equivalent
/// but less readable; verify both agree.
#[test]
fn tlp_packet_mode_consistent_with_flit_type() {
    let nf = TlpPacket::new(vec![0x00; 4], TlpMode::NonFlit).unwrap();
    assert_eq!(nf.mode() == TlpMode::Flit, nf.flit_type().is_some());

    let fl = TlpPacket::new(vec![0x00; 4], TlpMode::Flit).unwrap();
    assert_eq!(fl.mode() == TlpMode::Flit, fl.flit_type().is_some());
}

#[test]
fn tlp_packet_handles_minimum_size() {
    // 4-byte header minimum
    let data = vec![0x00, 0x00, 0x00, 0x00];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    assert!(packet.tlp_type().is_ok());
}

#[test]
fn tlp_packet_handles_empty_data_section() {
    let data = vec![0x00, 0x00, 0x00, 0x01];
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    assert!(packet.data().is_empty());
}

#[test]
fn tlp_packet_preserves_data_payload() {
    let payload = [0xDE, 0xAD, 0xBE, 0xEF];
    let mut data = vec![0x00, 0x00, 0x00, 0x01];
    data.extend_from_slice(&payload);
    let packet = TlpPacket::new(data, TlpMode::NonFlit).unwrap();
    assert_eq!(packet.data(), payload);
}

// ============================================================================
// Backward Compatibility Tests — deprecated get_* aliases
// ============================================================================

/// Verify that all deprecated `get_*` aliases still compile and return the
/// same values as their replacement methods. One test per deprecated method.
#[test]
#[allow(deprecated)]
fn deprecated_get_tlp_type_on_packet_delegates_to_tlp_type() {
    let pkt = TlpPacket::new(
        vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        TlpMode::NonFlit,
    )
    .unwrap();
    assert_eq!(pkt.get_tlp_type(), pkt.tlp_type());
}

#[test]
#[allow(deprecated)]
fn deprecated_get_tlp_format_delegates_to_tlp_format() {
    let pkt = TlpPacket::new(
        vec![0x40, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        TlpMode::NonFlit,
    )
    .unwrap();
    assert_eq!(pkt.get_tlp_format(), pkt.tlp_format());
}

#[test]
#[allow(deprecated)]
fn deprecated_get_flit_type_delegates_to_flit_type() {
    let pkt = TlpPacket::new(vec![0x00, 0x00, 0x00, 0x00], TlpMode::Flit).unwrap();
    assert_eq!(pkt.get_flit_type(), pkt.flit_type());
}

#[test]
#[allow(deprecated)]
fn deprecated_get_header_delegates_to_header() {
    let pkt = TlpPacket::new(
        vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        TlpMode::NonFlit,
    )
    .unwrap();
    // Both return the same TlpPacketHeader; compare via tlp_type() since the
    // struct does not implement PartialEq.
    let via_old = pkt.get_header().tlp_type().unwrap();
    let via_new = pkt.header().tlp_type().unwrap();
    assert_eq!(via_old, via_new);
}

#[test]
#[allow(deprecated)]
fn deprecated_get_tlp_type_on_header_delegates_to_tlp_type() {
    let hdr = TlpPacketHeader::new(vec![0x04, 0x00, 0x00, 0x01], TlpMode::NonFlit).unwrap();
    assert_eq!(hdr.get_tlp_type(), hdr.tlp_type());
}

// ============================================================================
// Debug trait Tests
// ============================================================================

#[test]
fn tlp_packet_implements_debug() {
    let pkt = TlpPacket::new(
        vec![0x40, 0x00, 0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF],
        TlpMode::NonFlit,
    )
    .unwrap();
    let s = format!("{:?}", pkt);
    assert!(s.contains("TlpPacket"), "expected 'TlpPacket' in: {s}");
    assert!(s.contains("data_len"), "expected 'data_len' in: {s}");
}

#[test]
fn tlp_packet_implements_debug_flit() {
    let pkt = TlpPacket::new(vec![0x00, 0x00, 0x00, 0x00], TlpMode::Flit).unwrap();
    let s = format!("{:?}", pkt);
    assert!(s.contains("TlpPacket"), "expected 'TlpPacket' in: {s}");
    assert!(s.contains("flit_dw0"), "expected 'flit_dw0' in: {s}");
}

#[test]
fn tlp_packet_header_implements_debug() {
    let hdr = TlpPacketHeader::new(vec![0x00, 0x00, 0x20, 0x01], TlpMode::NonFlit).unwrap();
    let s = format!("{:?}", hdr);
    assert!(
        s.contains("TlpPacketHeader"),
        "expected 'TlpPacketHeader' in: {s}"
    );
    assert!(s.contains("format"), "expected 'format' in: {s}");
    assert!(s.contains("length"), "expected 'length' in: {s}");
}
