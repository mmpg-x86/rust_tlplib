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
let requester_id = match tlp_type {
     TlpType::MemReadReq |
     TlpType::MemReadLockReq |
     TlpType::MemWriteReq |
     TlpType::IOReadReq |
     TlpType::IOWriteReq |
     TlpType::FetchAddAtomicOpReq |
     TlpType::SwapAtomicOpReq |
     TlpType::CompareSwapAtomicOpReq => new_mem_req(packet.get_data(), &tlp_format).req_id(),
     TlpType::ConfType0ReadReq |
     TlpType::ConfType0WriteReq |
     TlpType::ConfType1ReadReq |
     TlpType::ConfType1WriteReq => new_conf_req(packet.get_data(), &tlp_format).req_id(),
     TlpType::MsgReq |
     TlpType::MsgReqData => new_msg_req(packet.get_data(), &tlp_format).req_id(),
     TlpType::Cpl |
     TlpType::CplData |
     TlpType::CplLocked |
     TlpType::CplDataLocked => new_cmpl_req(packet.get_data(), &tlp_format).req_id(),
     TlpType::LocalTlpPrefix |
     TlpType::EndToEndTlpPrefix => {
         println!("TLP Prefix types not yet supported: {:?}", tlp_type);
         0  // Return default value for unsupported types
     }
};

println!("Requester ID from This TLP Packet: 0x{:04X}", requester_id);
```

## Documentation

The documentation of the released version is available on [doc.rs](https://docs.rs/rtlp-lib).
To generate current documentation please run `cargo doc --open`

## License

Licensed under:

 * The 3-Clause BSD License
