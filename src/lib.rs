use std::convert::TryFrom;
use std::fmt::Display;

#[macro_use]
extern crate bitfield;

/// Errors that can occur when parsing TLP packets
#[derive(Debug, Clone, PartialEq)]
pub enum TlpError {
    /// Invalid format field value
    InvalidFormat,
    /// Invalid type field value
    InvalidType,
    /// Unknown encoding type
    UnknownEncoding,
    /// Unsupported combination of format and type
    UnsupportedCombination,
}

#[repr(u8)]
#[derive(PartialEq, Copy, Clone)]
pub enum TlpFmt {
    NoDataHeader3DW     = 0b000,
    NoDataHeader4DW     = 0b001,
    WithDataHeader3DW   = 0b010,
    WithDataHeader4DW   = 0b011,
    TlpPrefix           = 0b100,
}

impl Display for TlpFmt {
    fn fmt (&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        let name = match &self {
            TlpFmt::NoDataHeader3DW => "3DW no Data Header",
            TlpFmt::NoDataHeader4DW => "4DW no Data Header",
            TlpFmt::WithDataHeader3DW => "3DW with Data Header",
            TlpFmt::WithDataHeader4DW => "4DW with Data Header",
            TlpFmt::TlpPrefix => "Tlp Prefix",
        };
        write!(fmt, "{}", name)
    }
}

impl TryFrom<u32> for TlpFmt {
    type Error = TlpError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == TlpFmt::NoDataHeader3DW as u32 => Ok(TlpFmt::NoDataHeader3DW),
            x if x == TlpFmt::NoDataHeader4DW as u32 => Ok(TlpFmt::NoDataHeader4DW),
            x if x == TlpFmt::WithDataHeader3DW as u32 => Ok(TlpFmt::WithDataHeader3DW),
            x if x == TlpFmt::WithDataHeader4DW as u32 => Ok(TlpFmt::WithDataHeader4DW),
            x if x == TlpFmt::TlpPrefix as u32 => Ok(TlpFmt::TlpPrefix),
            _ => Err(TlpError::InvalidFormat),
        }
    }
}

#[derive(PartialEq)]
pub enum TlpFormatEncodingType {
    MemoryRequest           = 0b00000,
    MemoryLockRequest       = 0b00001,
    IORequest               = 0b00010,
    ConfigType0Request      = 0b00100,
    ConfigType1Request      = 0b00101,
    Completion              = 0b01010,
    CompletionLocked        = 0b01011,
    FetchAtomicOpRequest    = 0b01100,
    UnconSwapAtomicOpRequest= 0b01101,
    CompSwapAtomicOpRequest = 0b01110,
}

impl TryFrom<u32> for TlpFormatEncodingType {
    type Error = TlpError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == TlpFormatEncodingType::MemoryRequest as u32 			=> Ok(TlpFormatEncodingType::MemoryRequest),
            x if x == TlpFormatEncodingType::MemoryLockRequest as u32 		=> Ok(TlpFormatEncodingType::MemoryLockRequest),
            x if x == TlpFormatEncodingType::IORequest as u32 				=> Ok(TlpFormatEncodingType::IORequest),
            x if x == TlpFormatEncodingType::ConfigType0Request as u32 		=> Ok(TlpFormatEncodingType::ConfigType0Request),
            x if x == TlpFormatEncodingType::ConfigType1Request as u32 		=> Ok(TlpFormatEncodingType::ConfigType1Request),
            x if x == TlpFormatEncodingType::Completion as u32 				=> Ok(TlpFormatEncodingType::Completion),
            x if x == TlpFormatEncodingType::CompletionLocked  as u32 		=> Ok(TlpFormatEncodingType::CompletionLocked),
            x if x == TlpFormatEncodingType::FetchAtomicOpRequest as u32 	=> Ok(TlpFormatEncodingType::FetchAtomicOpRequest),
            x if x == TlpFormatEncodingType::UnconSwapAtomicOpRequest as u32 => Ok(TlpFormatEncodingType::UnconSwapAtomicOpRequest),
            x if x == TlpFormatEncodingType::CompSwapAtomicOpRequest as u32 => Ok(TlpFormatEncodingType::CompSwapAtomicOpRequest),
            _ => Err(TlpError::UnknownEncoding),
        }
    }
}

#[derive(PartialEq)]
#[derive(Debug)]
pub enum TlpType {
    MemReadReq,
    MemReadLockReq,
    MemWriteReq,
    IOReadReq,
    IOWriteReq,
    ConfType0ReadReq,
    ConfType0WriteReq,
    ConfType1ReadReq,
    ConfType1WriteReq,
    MsgReq,
    MsgReqData,
    Cpl,
    CplData,
    CplLocked,
    CplDataLocked,
    FetchAddAtomicOpReq,
    SwapAtomicOpReq,
    CompareSwapAtomicOpReq,
    LocalTlpPrefix,
    EndToEndTlpPrefix,
}

impl Display for TlpType {
    fn fmt (&self, fmt: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        let name = match &self {
            TlpType::MemReadReq => "Memory Read Request",
            TlpType::MemReadLockReq => "Locked Memory Read Request",
            TlpType::MemWriteReq => "Memory Write Request",
            TlpType::IOReadReq => "IO Read Request",
            TlpType::IOWriteReq => "IO Write Request",
            TlpType::ConfType0ReadReq => "Type 0 Config Read Request",
            TlpType::ConfType0WriteReq => "Type 0 Config Write Request",
            TlpType::ConfType1ReadReq => "Type 1 Config Read Request",
            TlpType::ConfType1WriteReq => "Type 1 Config Write Request",
            TlpType::MsgReq => "Message Request",
            TlpType::MsgReqData => "Message with Data Request",
            TlpType::Cpl => "Completion",
            TlpType::CplData => "Completion with Data",
            TlpType::CplLocked => "Locked Completion",
            TlpType::CplDataLocked => "Locked Completion with Data",
            TlpType::FetchAddAtomicOpReq => "Fetch Add Atomic Op Request",
            TlpType::SwapAtomicOpReq => "Swap Atomic Op Request",
            TlpType::CompareSwapAtomicOpReq => "Compare Swap Atomic Op Request",
            TlpType::LocalTlpPrefix => "Local Tlp Prefix",
            TlpType::EndToEndTlpPrefix => "End To End Tlp Prefix",
        };
        write!(fmt, "{}", name)
    }
}

bitfield! {
        struct TlpHeader(MSB0 [u8]);
        u32;
        get_format, _: 2, 0;
        get_type,   _: 7, 3;
        get_t9,     _: 8, 8;
        get_tc,     _: 11, 9;
        get_t8,     _: 12, 12;
        get_attr_b2, _: 13, 13;
        get_ln,     _: 14, 14;
        get_th,     _: 15, 15;
        get_td,     _: 16, 16;
        get_ep,     _: 17, 17;
        get_attr,   _: 19, 18;
        get_at,     _: 21, 20;
        get_length, _: 31, 22;
}

impl<T: AsRef<[u8]>> TlpHeader<T> {

    fn get_tlp_type(&self) -> Result<TlpType, TlpError> {
        let tlp_type = self.get_type();
        let tlp_fmt = self.get_format();

        match TlpFormatEncodingType::try_from(tlp_type) {
            Ok(TlpFormatEncodingType::MemoryRequest) => {
                match TlpFmt::try_from(tlp_fmt) {
                    Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::MemReadReq),
                    Ok(TlpFmt::NoDataHeader4DW) => Ok(TlpType::MemReadReq),
                    Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::MemWriteReq),
                    Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::MemWriteReq),
					_ => Err(TlpError::UnsupportedCombination),
                }
            }
            Ok(TlpFormatEncodingType::MemoryLockRequest) => {
                match TlpFmt::try_from(tlp_fmt) {
                    Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::MemReadLockReq),
                    Ok(TlpFmt::NoDataHeader4DW) => Ok(TlpType::MemReadLockReq),
					_ => Err(TlpError::UnsupportedCombination),
                }
            }
			Ok(TlpFormatEncodingType::IORequest) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::IOReadReq),
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::IOWriteReq),
					_ => Err(TlpError::UnsupportedCombination),
				}
			}
			Ok(TlpFormatEncodingType::ConfigType0Request) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::ConfType0ReadReq),
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::ConfType0WriteReq),
					_ => Err(TlpError::UnsupportedCombination),
				}
			}
            Ok(TlpFormatEncodingType::ConfigType1Request) => {
                    match TlpFmt::try_from(tlp_fmt) {
                            Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::ConfType1ReadReq),
                            Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::ConfType1WriteReq),
                            _ => Err(TlpError::UnsupportedCombination),
                    }
            }
			Ok(TlpFormatEncodingType::Completion) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::Cpl),
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::CplData),
					_ => Err(TlpError::UnsupportedCombination),
				}
			}
			Ok(TlpFormatEncodingType::CompletionLocked) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::CplLocked),
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::CplDataLocked),
					_ => Err(TlpError::UnsupportedCombination),
				}
			}
			Ok(TlpFormatEncodingType::FetchAtomicOpRequest) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::FetchAddAtomicOpReq),
					Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::FetchAddAtomicOpReq),
					_ => Err(TlpError::UnsupportedCombination),
				}
			}
			Ok(TlpFormatEncodingType::UnconSwapAtomicOpRequest) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::SwapAtomicOpReq),
					Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::SwapAtomicOpReq),
					_ => Err(TlpError::UnsupportedCombination),
				}
			}
			Ok(TlpFormatEncodingType::CompSwapAtomicOpRequest) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::CompareSwapAtomicOpReq),
					Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::CompareSwapAtomicOpReq),
					_ => Err(TlpError::UnsupportedCombination),
				}
			}
			Err(e) => Err(e)
        }
    }
}

/// Memory Request Trait:
/// Applies to 32 and 64 bits requests as well as legacy IO-Request
/// (Legacy IO Request has the same structure as MemRead3DW)
/// Software using the library may want to use trait instead of bitfield structures
/// Both 3DW (32-bit) and 4DW (64-bit) headers implement this trait
/// 3DW header is also used for all Legacy IO Requests.
pub trait MemRequest {
    fn address(&self) -> u64;
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
    fn ldwbe(&self) -> u8;
    fn fdwbe(&self) -> u8;
}

// Structure for both 3DW Memory Request as well as Legacy IO Request
bitfield! {
    pub struct MemRequest3DW(MSB0 [u8]);
    u32;
    pub get_requester_id,   _: 15, 0;
    pub get_tag,            _: 23, 16;
    pub get_last_dw_be,     _: 27, 24;
    pub get_first_dw_be,    _: 31, 28;
    pub get_address32,      _: 63, 32;
}

bitfield! {
    pub struct MemRequest4DW(MSB0 [u8]);
    u64;
    pub get_requester_id,   _: 15, 0;
    pub get_tag,            _: 23, 16;
    pub get_last_dw_be,     _: 27, 24;
    pub get_first_dw_be,    _: 31, 28;
    pub get_address64,      _: 95, 32;
}

impl <T: AsRef<[u8]>> MemRequest for MemRequest3DW<T> {
    fn address(&self) -> u64 {
        self.get_address32().into()
    }
    fn req_id(&self) -> u16 {
        self.get_requester_id() as u16
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn ldwbe(&self) -> u8 {
        self.get_last_dw_be() as u8
    }
    fn fdwbe(&self) -> u8 {
        self.get_first_dw_be() as u8
    }
}

impl <T: AsRef<[u8]>> MemRequest for MemRequest4DW<T> {
    fn address(&self) -> u64 {
        self.get_address64()
    }
    fn req_id(&self) -> u16 {
        self.get_requester_id() as u16
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn ldwbe(&self) -> u8 {
        self.get_last_dw_be() as u8
    }
    fn fdwbe(&self) -> u8 {
        self.get_first_dw_be() as u8
    }
}

/// Obtain Memory Request trait from bytes in vector as dyn
/// This is preffered way of dealing with TLP headers as exact format (32/64 bits) is not required
///
/// # Examples
///
/// ```
/// use std::convert::TryFrom;
///
/// use rtlp_lib::TlpPacket;
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::MemRequest;
/// use rtlp_lib::new_mem_req;
///
/// let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// let tlp = TlpPacket::new(bytes);
///
/// if let Ok(tlpfmt) = TlpFmt::try_from(tlp.get_tlp_format()) {
///     // MemRequest contain only fields specific to PCI Memory Requests
///     let mem_req: Box<dyn MemRequest> = new_mem_req(tlp.get_data(), &tlpfmt);
///
///     // Address is 64 bits regardles of TLP format
///     //println!("Memory Request Address: {:x}", mem_req.address());
///
///     // Format of TLP (3DW vs 4DW) is stored in the TLP header
///     println!("This TLP size is: {}", tlpfmt);
///     // Type LegacyIO vs MemRead vs MemWrite is stored in first DW of TLP
///     println!("This TLP type is: {}", tlp.get_tlp_type());
/// }
/// ```
pub fn new_mem_req(bytes: Vec<u8>, format: &TlpFmt) -> Box<dyn MemRequest> {
    match format {
        TlpFmt::NoDataHeader3DW => Box::new(MemRequest3DW(bytes)),
        TlpFmt::NoDataHeader4DW => Box::new(MemRequest4DW(bytes)),
        TlpFmt::WithDataHeader3DW => Box::new(MemRequest3DW(bytes)),
        TlpFmt::WithDataHeader4DW => Box::new(MemRequest4DW(bytes)),
        TlpFmt::TlpPrefix => Box::new(MemRequest3DW(bytes)),
    }
}

/// Configuration Request Trait:
/// Configuration Requests Headers are always same size (3DW),
/// this trait is provided to have same API as other headers with variable size
pub trait ConfigurationRequest {
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
    fn bus_nr(&self) -> u8;
    fn dev_nr(&self) -> u8;
    fn func_nr(&self) -> u8;
    fn ext_reg_nr(&self) -> u8;
    fn reg_nr(&self) -> u8;
}

/// Obtain Configuration Request trait from bytes in vector as dyn
///
/// # Examples
///
/// ```
/// use std::convert::TryFrom;
///
/// use rtlp_lib::TlpPacket;
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::ConfigurationRequest;
/// use rtlp_lib::new_conf_req;
///
/// let bytes = vec![0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// let tlp = TlpPacket::new(bytes);
///
/// if let Ok(tlpfmt) = TlpFmt::try_from(tlp.get_tlp_format()) {
///     let config_req: Box<dyn ConfigurationRequest> = new_conf_req(tlp.get_data(), &tlpfmt);
///
///     //println!("Configuration Request Bus: {:x}", config_req.bus_nr());
/// }
/// ```
pub fn new_conf_req(bytes: Vec<u8>, _format: &TlpFmt) -> Box<dyn ConfigurationRequest> {
	Box::new(ConfigRequest(bytes))
}

bitfield! {
    pub struct ConfigRequest(MSB0 [u8]);
    u32;
    pub get_requester_id,   _: 15, 0;
    pub get_tag,            _: 23, 16;
    pub get_last_dw_be,     _: 27, 24;
    pub get_first_dw_be,    _: 31, 28;
    pub get_bus_nr,         _: 39, 32;
    pub get_dev_nr,         _: 44, 40;
    pub get_func_nr,        _: 47, 45;
    pub rsvd,               _: 51, 48;
    pub get_ext_reg_nr,     _: 55, 52;
    pub get_register_nr,    _: 61, 56;
    r,                      _: 63, 62;
}

impl <T: AsRef<[u8]>> ConfigurationRequest for ConfigRequest<T> {
    fn req_id(&self) -> u16 {
        self.get_requester_id() as u16
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn bus_nr(&self) -> u8 {
        self.get_bus_nr() as u8
    }
    fn dev_nr(&self) -> u8 {
        self.get_dev_nr() as u8
    }
    fn func_nr(&self) -> u8 {
        self.get_func_nr() as u8
    }
    fn ext_reg_nr(&self) -> u8 {
        self.get_ext_reg_nr() as u8
    }
    fn reg_nr(&self) -> u8 {
        self.get_register_nr() as u8
    }
}

/// Completion Request Trait
/// Completions are always 3DW (for with data (fmt = b010) and without data (fmt = b000) )
/// This trait is provided to have same API as other headers with variable size
/// To obtain this trait `new_cmpl_req()` function has to be used
/// Trait release user from dealing with bitfield structures.
pub trait CompletionRequest {
    fn cmpl_id(&self) -> u16;
    fn cmpl_stat(&self) -> u8;
    fn bcm(&self) -> u8;
    fn byte_cnt(&self) -> u16;
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
    fn laddr(&self) -> u8;
}

bitfield! {
    pub struct CompletionReqDW23(MSB0 [u8]);
    u16;
    pub get_completer_id,   _: 15, 0;
    pub get_cmpl_stat,      _: 18, 16;
    pub get_bcm,            _: 19, 19;
    pub get_byte_cnt,       _: 31, 20;
    pub get_req_id,         _: 47, 32;
    pub get_tag,            _: 55, 48;
    r,                      _: 57, 56;
    pub get_laddr,          _: 63, 58;
}

impl <T: AsRef<[u8]>> CompletionRequest for CompletionReqDW23<T> {
    fn cmpl_id(&self) -> u16 {
        self.get_completer_id()
    }
    fn cmpl_stat(&self) -> u8 {
        self.get_cmpl_stat() as u8
    }
    fn bcm(&self) -> u8 {
        self.get_bcm() as u8
    }
    fn byte_cnt(&self) -> u16 {
        self.get_byte_cnt()
    }
    fn req_id(&self) -> u16 {
        self.get_req_id()
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn laddr(&self) -> u8 {
        self.get_laddr() as u8
    }
}

/// Obtain Completion Request dyn Trait:
///
/// # Examples
///
/// ```
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::CompletionRequest;
/// use rtlp_lib::new_cmpl_req;
///
/// let bytes = vec![0x20, 0x01, 0xFF, 0xC2, 0x00, 0x00, 0x00, 0x00];
/// // TLP Format usually comes from TlpPacket or Header here we made up one for example
/// let tlpfmt = TlpFmt::WithDataHeader4DW;
///
/// let cmpl_req: Box<dyn CompletionRequest> = new_cmpl_req(bytes, &tlpfmt);
///
/// println!("Requester ID from Completion{}", cmpl_req.req_id());
/// ```
pub fn new_cmpl_req(bytes: Vec<u8>, _format: &TlpFmt) -> Box<dyn CompletionRequest> {
	Box::new(CompletionReqDW23(bytes))
}

/// Message Request trait
/// Provide method to access fields in DW2-4 header is handled by TlpHeader
pub trait MessageRequest {
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
	fn msg_code(&self) -> u8;
	/// DW3-4 vary with Message Code Field
    fn dw3(&self) -> u32;
    fn dw4(&self) -> u32;
}

bitfield! {
    pub struct MessageReqDW24(MSB0 [u8]);
    u16;
    pub get_requester_id,   _: 15, 0;
    pub get_tag,            _: 23, 16;
    pub get_msg_code,       _: 31, 24;
    pub get_dw3,            _: 63, 32;
    pub get_dw4,            _: 96, 64;
}

impl <T: AsRef<[u8]>> MessageRequest for MessageReqDW24<T> {
    fn req_id(&self) -> u16 {
        self.get_requester_id()
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn msg_code(&self) -> u8 {
        self.get_msg_code() as u8
    }
    fn dw3(&self) -> u32 {
        self.get_dw3() as u32
    }
    fn dw4(&self) -> u32 {
        self.get_dw4() as u32
    }
    // TODO: implement routedby method based on type
}

/// Obtain Message Request dyn Trait:
///
/// # Examples
///
/// ```
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::MessageRequest;
/// use rtlp_lib::new_msg_req;
///
/// let bytes = vec![0x20, 0x01, 0xFF, 0xC2, 0x00, 0x00, 0x00, 0x00];
/// let tlpfmt = TlpFmt::NoDataHeader3DW;
///
/// let msg_req: Box<dyn MessageRequest> = new_msg_req(bytes, &tlpfmt);
///
/// println!("Requester ID from Message{}", msg_req.req_id());
/// ```
pub fn new_msg_req(bytes: Vec<u8>, _format: &TlpFmt) -> Box<dyn MessageRequest> {
	Box::new(MessageReqDW24(bytes))
}

/// TLP Packet Header
/// Contains bytes for Packet header and informations about TLP type
pub struct TlpPacketHeader {
    bytes: Vec<u8>,
    header: TlpHeader<Vec<u8>>,
}

impl TlpPacketHeader {
    pub fn new(bytes: Vec<u8>) -> TlpPacketHeader {
        let mut dw0 = vec![0; 4];
        dw0[..4].clone_from_slice(&bytes[0..4]);

        TlpPacketHeader { bytes, header: TlpHeader(dw0) }
    }

    pub fn get_tlp_type(&self) -> Result<TlpType, TlpError> {
        let mut dw0 = vec![0; 4];
        dw0[..4].clone_from_slice(&self.bytes[0..4]);
        let tlp_head = TlpHeader(dw0);

        tlp_head.get_tlp_type()
    }

    pub fn get_format(&self) -> u32 {self.header.get_format()}
    pub fn get_type(&self) -> u32 {self.header.get_type()}
    pub fn get_t9(&self) -> u32 {self.header.get_t9()}
    pub fn get_tc(&self) -> u32 {self.header.get_tc()}
    pub fn get_t8(&self) -> u32 {self.header.get_t8()}
    pub fn get_attr_b2(&self) -> u32 {self.header.get_attr_b2()}
    pub fn get_ln(&self) -> u32 {self.header.get_ln()}
    pub fn get_th(&self) -> u32 {self.header.get_th()}
    pub fn get_td(&self) -> u32 {self.header.get_td()}
    pub fn get_ep(&self) -> u32 {self.header.get_ep()}
    pub fn get_attr(&self) -> u32 {self.header.get_attr()}
    pub fn get_at(&self) -> u32 {self.header.get_at()}
    pub fn get_length(&self) -> u32 {self.header.get_length()}

}

/// TLP Packet structure is high level abstraction for entire TLP packet
/// Contains Header and Data
///
/// # Examples
///
/// ```
/// use rtlp_lib::TlpPacket;
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::TlpType;
/// use rtlp_lib::new_msg_req;
/// use rtlp_lib::new_conf_req;
/// use rtlp_lib::new_mem_req;
/// use rtlp_lib::new_cmpl_req;
///
/// // Bytes for full TLP Packet
/// //               <------- DW1 -------->  <------- DW2 -------->  <------- DW3 -------->  <------- DW4 -------->
/// let bytes = vec![0x00, 0x00, 0x20, 0x01, 0x04, 0x00, 0x00, 0x01, 0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10];
/// let packet = TlpPacket::new(bytes);
///
/// let header = packet.get_header();
/// // TLP Type tells us what is this packet
/// let tlp_type = header.get_tlp_type().unwrap();
/// let tlp_format = packet.get_tlp_format();
/// let requester_id;
/// match (tlp_type) {
///      TlpType::MemReadReq |
///      TlpType::MemReadLockReq |
///      TlpType::MemWriteReq |
///      TlpType::IOReadReq |
///      TlpType::IOWriteReq |
///      TlpType::FetchAddAtomicOpReq |
///      TlpType::SwapAtomicOpReq |
///      TlpType::CompareSwapAtomicOpReq => requester_id = new_mem_req(packet.get_data(), &tlp_format).req_id(),
///      TlpType::ConfType0ReadReq |
///      TlpType::ConfType0WriteReq |
///      TlpType::ConfType1ReadReq |
///      TlpType::ConfType1WriteReq => requester_id = new_conf_req(packet.get_data(), &tlp_format).req_id(),
///      TlpType::MsgReq |
///      TlpType::MsgReqData => requester_id = new_msg_req(packet.get_data(), &tlp_format).req_id(),
///      TlpType::Cpl |
///      TlpType::CplData |
///      TlpType::CplLocked |
///      TlpType::CplDataLocked => requester_id = new_cmpl_req(packet.get_data(), &tlp_format).req_id(),
///      TlpType::LocalTlpPrefix |
///      TlpType::EndToEndTlpPrefix => println!("I need to implement TLP Type: {:?}", tlp_type),
/// }
/// ```
pub struct TlpPacket {
    header: TlpPacketHeader,
    data: Vec<u8>,
}

impl TlpPacket {
    pub fn new(bytes: Vec<u8>) -> TlpPacket {
        let mut ownbytes = bytes.to_vec();
        let mut header = vec![0; 4];
        header.clone_from_slice(&ownbytes[0..4]);
        let data = ownbytes.drain(4..).collect();
        TlpPacket {
            header: TlpPacketHeader::new(header),
            data,
        }
    }

    pub fn get_header(&self) -> &TlpPacketHeader {
        &self.header
    }

    pub fn get_data(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    pub fn get_tlp_type(&self) -> TlpType {
        self.header.get_tlp_type().expect("Cannot Parse TLP!")
    }

    pub fn get_tlp_format(&self) -> TlpFmt {
        let fmt : TlpFmt = TlpFmt::try_from(self.header.get_format()).unwrap();

        fmt
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlp_packet() {
        let d = vec![0x04, 0x00, 0x00, 0x01, 0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10];
        let tlp = TlpPacket::new(d);

        assert_eq!(tlp.get_tlp_type(), TlpType::ConfType0ReadReq);
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
        assert_eq!(mr.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::MemReadReq);
    }

    #[test]
    fn tlp_header_type() {
		// Empty packet is still MemREAD: FMT '000' Type '0 0000' Length 0
        let memread = TlpHeader([0x0, 0x0, 0x0, 0x0]);
        assert_eq!(memread.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::MemReadReq);

		// MemRead32 FMT '000' Type '0 0000'
		let memread32 = TlpHeader([0x00, 0x00, 0x20, 0x01]);
		assert_eq!(memread32.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::MemReadReq);

		// MemWrite32 FMT '010' Type '0 0000'
		let memwrite32 = TlpHeader([0x40, 0x00, 0x00, 0x01]);
		assert_eq!(memwrite32.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::MemWriteReq);

		// CPL without Data: FMT '000' Type '0 1010'
		let cpl_no_data = TlpHeader([0x0a, 0x00, 0x10, 0x00]);
		assert_eq!(cpl_no_data.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::Cpl);

		// CPL with Data: FMT '010' Type '0 1010'
		let cpl_with_data = TlpHeader([0x4a, 0x00, 0x20, 0x40]);
		assert_eq!(cpl_with_data.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::CplData);

		// MemRead 4DW: FMT: '001' Type '0 0000'
		let memread_4dw = TlpHeader([0x20, 0x00, 0x20, 0x40]);
		assert_eq!(memread_4dw.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::MemReadReq);

		// Config Type 0 Read request: FMT: '000' Type '0 0100'
		let conf_t0_read = TlpHeader([0x04, 0x00, 0x00, 0x01]);
		assert_eq!(conf_t0_read.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::ConfType0ReadReq);

		// Config Type 0 Write request: FMT: '010' Type '0 0100'
		let conf_t0_write = TlpHeader([0x44, 0x00, 0x00, 0x01]);
		assert_eq!(conf_t0_write.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::ConfType0WriteReq);

        // Config Type 1 Read request: FMT: '000' Type '0 0101'
        let conf_t1_read = TlpHeader([0x05, 0x88, 0x80, 0x01]);
               assert_eq!(conf_t1_read.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::ConfType1ReadReq);

        // Config Type 1 Read request: FMT: '010' Type '0 0101'
        let conf_t1_write = TlpHeader([0x45, 0x88, 0x80, 0x01]);
               assert_eq!(conf_t1_write.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::ConfType1WriteReq);

        // HeaderLog: 04000001 0000220f 01070000 af36fc70
        // HeaderLog: 60009001 4000000f 00000280 4047605c
        let memwrite64 = TlpHeader([0x60, 0x00, 0x90, 0x01]);
        assert_eq!(memwrite64.get_tlp_type().expect("Cannot Parse TLP!"), TlpType::MemWriteReq);
    }

    #[test]
    fn tlp_header_works_all_zeros() {
        let bits_locations = TlpHeader([0x0, 0x0, 0x0, 0x0]);

        assert_eq!(bits_locations.get_format(), 0);
        assert_eq!(bits_locations.get_type(), 0);
        assert_eq!(bits_locations.get_t9(), 0);
        assert_eq!(bits_locations.get_tc(), 0);
        assert_eq!(bits_locations.get_t8(), 0);
        assert_eq!(bits_locations.get_attr_b2(), 0);
        assert_eq!(bits_locations.get_ln(), 0);
        assert_eq!(bits_locations.get_th(), 0);
        assert_eq!(bits_locations.get_td(), 0);
        assert_eq!(bits_locations.get_ep(), 0);
        assert_eq!(bits_locations.get_attr(), 0);
        assert_eq!(bits_locations.get_at(), 0);
        assert_eq!(bits_locations.get_length(), 0);
    }

    #[test]
    fn tlp_header_works_all_ones() {
        let bits_locations = TlpHeader([0xff, 0xff, 0xff, 0xff]);

        assert_eq!(bits_locations.get_format(), 0x7);
        assert_eq!(bits_locations.get_type(), 0x1f);
        assert_eq!(bits_locations.get_t9(), 0x1);
        assert_eq!(bits_locations.get_tc(), 0x7);
        assert_eq!(bits_locations.get_t8(), 0x1);
        assert_eq!(bits_locations.get_attr_b2(), 0x1);
        assert_eq!(bits_locations.get_ln(), 0x1);
        assert_eq!(bits_locations.get_th(), 0x1);
        assert_eq!(bits_locations.get_td(), 0x1);
        assert_eq!(bits_locations.get_ep(), 0x1);
        assert_eq!(bits_locations.get_attr(), 0x3);
        assert_eq!(bits_locations.get_at(), 0x3);
        assert_eq!(bits_locations.get_length(), 0x3ff);
    }
}
