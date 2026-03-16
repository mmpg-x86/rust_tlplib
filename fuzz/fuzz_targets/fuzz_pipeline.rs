#![no_main]

use libfuzzer_sys::fuzz_target;
use rtlp_lib::*;

/// Fuzz the full decode pipeline: parse packet, then decode type-specific
/// fields based on the resolved TLP type. This exercises the complete
/// code path a real user would follow.
fuzz_target!(|data: &[u8]| {
    let pkt = match TlpPacket::new(data.to_vec()) {
        Ok(p) => p,
        Err(_) => return,
    };

    let tlp_type = match pkt.get_tlp_type() {
        Ok(t) => t,
        Err(_) => return,
    };

    let fmt = match pkt.get_tlp_format() {
        Ok(f) => f,
        Err(_) => return,
    };

    let pkt_data = pkt.get_data();

    // TlpType display and query
    let _ = format!("{}", tlp_type);
    let _ = tlp_type.is_non_posted();
    let _ = format!("{}", fmt);

    // Decode based on type — mirrors real usage pattern
    match tlp_type {
        TlpType::MemReadReq
        | TlpType::MemReadLockReq
        | TlpType::MemWriteReq
        | TlpType::DeferrableMemWriteReq
        | TlpType::IOReadReq
        | TlpType::IOWriteReq => {
            if let Ok(mr) = new_mem_req(pkt_data, &fmt) {
                let _ = mr.req_id();
                let _ = mr.tag();
                let _ = mr.address();
                let _ = mr.fdwbe();
                let _ = mr.ldwbe();
            }
        }
        TlpType::ConfType0ReadReq
        | TlpType::ConfType0WriteReq
        | TlpType::ConfType1ReadReq
        | TlpType::ConfType1WriteReq => {
            if let Ok(cr) = new_conf_req(pkt_data, &fmt) {
                let _ = cr.req_id();
                let _ = cr.tag();
                let _ = cr.bus_nr();
                let _ = cr.dev_nr();
                let _ = cr.func_nr();
                let _ = cr.ext_reg_nr();
                let _ = cr.reg_nr();
            }
        }
        TlpType::Cpl | TlpType::CplData | TlpType::CplLocked | TlpType::CplDataLocked => {
            if let Ok(cpl) = new_cmpl_req(pkt_data, &fmt) {
                let _ = cpl.cmpl_id();
                let _ = cpl.cmpl_stat();
                let _ = cpl.bcm();
                let _ = cpl.byte_cnt();
                let _ = cpl.req_id();
                let _ = cpl.tag();
                let _ = cpl.laddr();
            }
        }
        TlpType::MsgReq | TlpType::MsgReqData => {
            if let Ok(msg) = new_msg_req(pkt_data, &fmt) {
                let _ = msg.req_id();
                let _ = msg.tag();
                let _ = msg.msg_code();
                let _ = msg.dw3();
                let _ = msg.dw4();
            }
        }
        TlpType::FetchAddAtomicOpReq
        | TlpType::SwapAtomicOpReq
        | TlpType::CompareSwapAtomicOpReq => {
            if let Ok(ar) = new_atomic_req(&pkt) {
                let _ = ar.op();
                let _ = ar.width();
                let _ = ar.req_id();
                let _ = ar.tag();
                let _ = ar.address();
                let _ = ar.operand0();
                let _ = ar.operand1();
                let _ = format!("{:?}", ar);
            }
        }
        _ => {}
    }
});
