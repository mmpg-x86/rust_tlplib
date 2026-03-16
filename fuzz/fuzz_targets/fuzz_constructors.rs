#![no_main]

use libfuzzer_sys::fuzz_target;
use rtlp_lib::*;

/// Fuzz all type-specific constructors with arbitrary bytes and format combinations.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let bytes = data.to_vec();

    // Try each format with each constructor — none should panic
    let formats = [
        TlpFmt::NoDataHeader3DW,
        TlpFmt::NoDataHeader4DW,
        TlpFmt::WithDataHeader3DW,
        TlpFmt::WithDataHeader4DW,
        TlpFmt::TlpPrefix,
    ];

    for fmt in &formats {
        // Memory request
        match new_mem_req(bytes.clone(), fmt) {
            Ok(mr) => {
                let _ = mr.req_id();
                let _ = mr.tag();
                let _ = mr.address();
                let _ = mr.fdwbe();
                let _ = mr.ldwbe();
            }
            Err(_) => {}
        }

        // Config request
        match new_conf_req(bytes.clone(), fmt) {
            Ok(cr) => {
                let _ = cr.req_id();
                let _ = cr.tag();
                let _ = cr.bus_nr();
                let _ = cr.dev_nr();
                let _ = cr.func_nr();
                let _ = cr.ext_reg_nr();
                let _ = cr.reg_nr();
            }
            Err(_) => {}
        }

        // Completion request
        match new_cmpl_req(bytes.clone(), fmt) {
            Ok(cpl) => {
                let _ = cpl.cmpl_id();
                let _ = cpl.cmpl_stat();
                let _ = cpl.bcm();
                let _ = cpl.byte_cnt();
                let _ = cpl.req_id();
                let _ = cpl.tag();
                let _ = cpl.laddr();
            }
            Err(_) => {}
        }

        // Message request
        match new_msg_req(bytes.clone(), fmt) {
            Ok(msg) => {
                let _ = msg.req_id();
                let _ = msg.tag();
                let _ = msg.msg_code();
                let _ = msg.dw3();
                let _ = msg.dw4();
            }
            Err(_) => {}
        }
    }

    // Atomic request — needs a full TlpPacket
    if let Ok(pkt) = TlpPacket::new(bytes) {
        match new_atomic_req(&pkt) {
            Ok(ar) => {
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
            Err(_) => {}
        }
    }
});
