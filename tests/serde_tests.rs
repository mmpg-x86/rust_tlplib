#![cfg(feature = "serde")]

use rtlp_lib::*;

#[test]
fn roundtrip_device_id() {
    let id = DeviceID::from_parts(0xC2, 0x1F, 0x07).unwrap();
    let json = serde_json::to_string(&id).unwrap();
    let back: DeviceID = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn roundtrip_tlp_mode() {
    let mode = TlpMode::Flit;
    let json = serde_json::to_string(&mode).unwrap();
    let back: TlpMode = serde_json::from_str(&json).unwrap();
    assert_eq!(mode, back);
}

#[test]
fn roundtrip_tlp_error() {
    let err = TlpError::InvalidLength;
    let json = serde_json::to_string(&err).unwrap();
    let back: TlpError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn roundtrip_tlp_fmt() {
    for fmt in [
        TlpFmt::NoDataHeader3DW,
        TlpFmt::NoDataHeader4DW,
        TlpFmt::WithDataHeader3DW,
        TlpFmt::WithDataHeader4DW,
        TlpFmt::TlpPrefix,
    ] {
        let json = serde_json::to_string(&fmt).unwrap();
        let back: TlpFmt = serde_json::from_str(&json).unwrap();
        assert_eq!(fmt, back);
    }
}

#[test]
fn roundtrip_tlp_type() {
    let t = TlpType::MemReadReq;
    let json = serde_json::to_string(&t).unwrap();
    let back: TlpType = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn roundtrip_atomic_op() {
    for op in [AtomicOp::FetchAdd, AtomicOp::Swap, AtomicOp::CompareSwap] {
        let json = serde_json::to_string(&op).unwrap();
        let back: AtomicOp = serde_json::from_str(&json).unwrap();
        assert_eq!(op, back);
    }
}

#[test]
fn roundtrip_atomic_width() {
    for w in [AtomicWidth::W32, AtomicWidth::W64] {
        let json = serde_json::to_string(&w).unwrap();
        let back: AtomicWidth = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }
}

#[test]
fn roundtrip_flit_tlp_type() {
    let t = FlitTlpType::MemWrite32;
    let json = serde_json::to_string(&t).unwrap();
    let back: FlitTlpType = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn roundtrip_flit_dw0() {
    let dw0 = FlitDW0::from_dw0(&[0x40, 0x00, 0x00, 0x04]).unwrap();
    let json = serde_json::to_string(&dw0).unwrap();
    let back: FlitDW0 = serde_json::from_str(&json).unwrap();
    assert_eq!(dw0, back);
}

#[test]
fn roundtrip_flit_ohc_a() {
    let ohc = FlitOhcA::from_bytes(&[0x0A, 0xBC, 0xDE, 0xF3]).unwrap();
    let json = serde_json::to_string(&ohc).unwrap();
    let back: FlitOhcA = serde_json::from_str(&json).unwrap();
    assert_eq!(ohc, back);
}

#[test]
fn json_output_readable() {
    let dw0 = FlitDW0::from_dw0(&[0x40, 0x00, 0x00, 0x04]).unwrap();
    let json = serde_json::to_string_pretty(&dw0).unwrap();
    assert!(json.contains("\"tlp_type\""));
    assert!(json.contains("\"MemWrite32\""));
    assert!(json.contains("\"length\""));
    assert!(json.contains(": 4"));
}
