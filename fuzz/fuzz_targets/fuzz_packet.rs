#![no_main]

use libfuzzer_sys::fuzz_target;
use rtlp_lib::*;

fuzz_target!(|data: &[u8]| {
    // TlpPacket::new must never panic — it should return Ok or Err
    let pkt = match TlpPacket::new(data.to_vec()) {
        Ok(p) => p,
        Err(_) => return,
    };

    // If parsing succeeded, none of these should panic
    let _ = pkt.get_tlp_type();
    let _ = pkt.get_tlp_format();
    let _ = pkt.get_header().get_tlp_type();

    // Header field accessors must not panic
    let hdr = pkt.get_header();
    let _ = hdr.get_format();
    let _ = hdr.get_type();
    let _ = hdr.get_t9();
    let _ = hdr.get_tc();
    let _ = hdr.get_t8();
    let _ = hdr.get_attr_b2();
    let _ = hdr.get_ln();
    let _ = hdr.get_th();
    let _ = hdr.get_td();
    let _ = hdr.get_ep();
    let _ = hdr.get_attr();
    let _ = hdr.get_at();
    let _ = hdr.get_length();

    // get_data() must not panic
    let _ = pkt.get_data();

    // TlpPacketHeader::new must not panic
    if data.len() >= 4 {
        let _ = TlpPacketHeader::new(data[..4].to_vec());
    }
});
