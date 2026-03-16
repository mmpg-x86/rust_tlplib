#![no_main]

use libfuzzer_sys::fuzz_target;
use rtlp_lib::*;

// Fuzz the full decode pipeline for both non-flit (PCIe 1–5) and flit (PCIe 6.x).
// Exercises the complete code path a real user would follow:
// parse → identify mode → decode type-specific fields.
fuzz_target!(|data: &[u8]| {
    // ── Non-flit path ──────────────────────────────────────────────────────
    if let Ok(pkt) = TlpPacket::new(data.to_vec(), TlpMode::NonFlit) {
        // Use if-let so that parse errors skip non-flit decode without
        // returning early — execution always reaches the flit path below.
        if let (Ok(tlp_type), Ok(fmt)) = (pkt.tlp_type(), pkt.tlp_format()) {
        // Display and predicate methods must not panic
        let _ = format!("{}", tlp_type);
        let _ = tlp_type.is_non_posted();
        let _ = tlp_type.is_posted();
        let _ = format!("{}", fmt);
        let _ = format!("{:?}", pkt);

        // Decode based on type — mirrors real usage pattern
        match tlp_type {
            TlpType::MemReadReq
            | TlpType::MemReadLockReq
            | TlpType::MemWriteReq
            | TlpType::DeferrableMemWriteReq
            | TlpType::IOReadReq
            | TlpType::IOWriteReq => {
                if let Ok(mr) = new_mem_req(pkt.data(), &fmt) {
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
                // new_conf_req is infallible — always returns Box<dyn ConfigurationRequest>
                let cr = new_conf_req(pkt.data());
                let _ = cr.req_id();
                let _ = cr.tag();
                let _ = cr.bus_nr();
                let _ = cr.dev_nr();
                let _ = cr.func_nr();
                let _ = cr.ext_reg_nr();
                let _ = cr.reg_nr();
            }
            TlpType::Cpl | TlpType::CplData | TlpType::CplLocked | TlpType::CplDataLocked => {
                // new_cmpl_req is infallible — always returns Box<dyn CompletionRequest>
                let cpl = new_cmpl_req(pkt.data());
                let _ = cpl.cmpl_id();
                let _ = cpl.cmpl_stat();
                let _ = cpl.bcm();
                let _ = cpl.byte_cnt();
                let _ = cpl.req_id();
                let _ = cpl.tag();
                let _ = cpl.laddr();
            }
            TlpType::MsgReq | TlpType::MsgReqData => {
                // new_msg_req is infallible — always returns Box<dyn MessageRequest>
                let msg = new_msg_req(pkt.data());
                let _ = msg.req_id();
                let _ = msg.tag();
                let _ = msg.msg_code();
                let _ = msg.dw3();
                let _ = msg.dw4();
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
        } // end if let (Ok(tlp_type), Ok(fmt))
    }

    // ── Flit path (PCIe 6.x) ───────────────────────────────────────────────
    if let Ok(pkt) = TlpPacket::new(data.to_vec(), TlpMode::Flit) {
        // mode() dispatch
        let _ = pkt.mode();

        // flit_type() and Display/Debug must not panic
        if let Some(ft) = pkt.flit_type() {
            let _ = format!("{}", ft);
            let _ = format!("{:?}", ft);
            let _ = ft.base_header_dw();
            let _ = ft.is_read_request();
            let _ = ft.has_data_payload();
        }

        // payload and Debug must not panic
        let _ = pkt.data();
        let _ = format!("{:?}", pkt);

        // FlitDW0 low-level parser must not panic
        if data.len() >= 4 {
            if let Ok(dw0) = FlitDW0::from_dw0(data) {
                let _ = dw0.ohc_count();
                let _ = dw0.total_bytes();
                let _ = dw0.validate_mandatory_ohc();
                // OHC-A word (if present) must not panic
                if dw0.ohc_count() > 0 {
                    let ohc_offset = dw0.tlp_type.base_header_dw() as usize * 4;
                    if data.len() >= ohc_offset + 4 {
                        let _ = FlitOhcA::from_bytes(&data[ohc_offset..]);
                    }
                }
            }
        }
    }
});
