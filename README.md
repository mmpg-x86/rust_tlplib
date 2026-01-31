Rust TLP lib
=============

This crate provide structs and functions to parse PCI TLP packets.


## Example

```rust
use rtlp_lib::TlpPacket;
use rtlp_lib::TlpFmt;
use rtlp_lib::TlpType;
use rtlp_lib::new_msg_req;
use rtlp_lib::new_conf_req;
use rtlp_lib::new_mem_req;
use rtlp_lib::new_cmpl_req;

// Bytes for full TLP Packet
//               <------- DW1 -------->  <------- DW2 -------->  <------- DW3 -------->  <------- DW4 -------->
let bytes = vec![0x00, 0x00, 0x20, 0x01, 0x04, 0x00, 0x00, 0x01, 0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10];
let packet = TlpPacket::new(bytes);

let header = packet.get_header();
// TLP Type tells us what is this packet
let tlp_type = header.get_tlp_type().unwrap();
let tlp_format = packet.get_tlp_format();

// Get requester_id field from this TLP (TLP can be of different types)
match tlp_type {
     TlpType::MemReadReq |
     TlpType::MemReadLockReq |
     TlpType::MemWriteReq |
     TlpType::IOReadReq |
     TlpType::IOWriteReq |
     TlpType::FetchAddAtomicOpReq |
     TlpType::SwapAtomicOpReq |
     TlpType::CompareSwapAtomicOpReq => {
         let requester_id = new_mem_req(packet.get_data(), &tlp_format).req_id();
         println!("Requester ID from Memory/IO TLP: {}", requester_id);
     }
     TlpType::ConfType0ReadReq |
     TlpType::ConfType0WriteReq |
     TlpType::ConfType1ReadReq |
     TlpType::ConfType1WriteReq => {
         let requester_id = new_conf_req(packet.get_data(), &tlp_format).req_id();
         println!("Requester ID from Config TLP: {}", requester_id);
     }
     TlpType::MsgReq |
     TlpType::MsgReqData => {
         let requester_id = new_msg_req(packet.get_data(), &tlp_format).req_id();
         println!("Requester ID from Message TLP: {}", requester_id);
     }
     TlpType::Cpl |
     TlpType::CplData |
     TlpType::CplLocked |
     TlpType::CplDataLocked => {
         let requester_id = new_cmpl_req(packet.get_data(), &tlp_format).req_id();
         println!("Requester ID from Completion TLP: {}", requester_id);
     }
     TlpType::LocalTlpPrefix |
     TlpType::EndToEndTlpPrefix => {
         println!("TLP Prefix Type: {:?} (not yet implemented)", tlp_type);
     }
}
```

## Documentation

The documentation of the released version is available on [doc.rs](https://docs.rs/rtlp-lib).
To generate current documentation please run `cargo doc --open`

## License

Licensed under:

 * The 3-Clause BSD License
