#![no_main]

use libfuzzer_sys::fuzz_target;
use rtlp_lib::*;

// Fuzz all type-specific constructors with arbitrary bytes and format combinations.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let bytes = data.to_vec();

    // Memory request — new_mem_req is the only factory that takes &TlpFmt
    let formats = [
        TlpFmt::NoDataHeader3DW,
        TlpFmt::NoDataHeader4DW,
        TlpFmt::WithDataHeader3DW,
        TlpFmt::WithDataHeader4DW,
        TlpFmt::TlpPrefix,
    ];

    for fmt in &formats {
        if let Ok(mr) = new_mem_req(bytes.clone(), fmt) {
            let _ = mr.req_id();
            let _ = mr.tag();
            let _ = mr.address();
            let _ = mr.fdwbe();
            let _ = mr.ldwbe();
        }
    }

    // Config / completion / message: bitfield views read fixed sizes from the
    // provided buffer and will panic if the buffer is too short. Guards ensure
    // the fuzzer never crashes on short inputs — it simply skips those paths.

    // ConfigRequest reads up to byte 7 (64-bit field) — requires 8 bytes.
    if let Ok(cr) = new_conf_req(bytes.clone()) {
        let _ = cr.req_id();
        let _ = cr.tag();
        let _ = cr.bus_nr();
        let _ = cr.dev_nr();
        let _ = cr.func_nr();
        let _ = cr.ext_reg_nr();
        let _ = cr.reg_nr();
    }

    // CompletionReqDW23 reads laddr at bits[63:57] — requires 8 bytes.
    if let Ok(cpl) = new_cmpl_req(bytes.clone()) {
        let _ = cpl.cmpl_id();
        let _ = cpl.cmpl_stat();
        let _ = cpl.bcm();
        let _ = cpl.byte_cnt();
        let _ = cpl.req_id();
        let _ = cpl.tag();
        let _ = cpl.laddr();
    }

    // MessageReqDW24 reads dw4 at bits[95:64] — requires 12 bytes.
    if let Ok(msg) = new_msg_req(bytes.clone()) {
        let _ = msg.req_id();
        let _ = msg.tag();
        let _ = msg.msg_code();
        let _ = msg.dw3();
        let _ = msg.dw4();
    }

    // Atomic request — needs a full TlpPacket (non-flit only)
    if let Ok(pkt) = TlpPacket::new(bytes, TlpMode::NonFlit) {
        if let Ok(ar) = new_atomic_req(&pkt) {
            let _ = ar.op();
            let _ = ar.width();
            let _ = ar.req_id();
            let _ = ar.tag();
            let _ = ar.address();
            let _ = ar.operand0();
            let _ = ar.operand1();
            // Debug formatting must not panic
            let _ = format!("{:?}", ar);
        }
    }
});
