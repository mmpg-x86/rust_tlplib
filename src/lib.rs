use std::convert::TryFrom;
use std::fmt::Display;

#[macro_use]
extern crate bitfield;

/// Errors that can occur when parsing TLP packets
#[derive(Debug, Clone, PartialEq)]
pub enum TlpError {
    /// Invalid format field value (bits don't match any known format)
    InvalidFormat,
    /// Invalid type field value (bits don't match any known type encoding)
    InvalidType,
    /// Unsupported combination of format and type
    UnsupportedCombination,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Copy, Clone)]
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
            _ => Err(TlpError::InvalidType),
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
					Ok(_) => Err(TlpError::UnsupportedCombination),
					Err(e) => Err(e),
                }
            }
            Ok(TlpFormatEncodingType::MemoryLockRequest) => {
                match TlpFmt::try_from(tlp_fmt) {
                    Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::MemReadLockReq),
                    Ok(TlpFmt::NoDataHeader4DW) => Ok(TlpType::MemReadLockReq),
					Ok(_) => Err(TlpError::UnsupportedCombination),
					Err(e) => Err(e),
                }
            }
			Ok(TlpFormatEncodingType::IORequest) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::IOReadReq),
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::IOWriteReq),
					Ok(_) => Err(TlpError::UnsupportedCombination),
					Err(e) => Err(e),
				}
			}
			Ok(TlpFormatEncodingType::ConfigType0Request) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::ConfType0ReadReq),
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::ConfType0WriteReq),
					Ok(_) => Err(TlpError::UnsupportedCombination),
					Err(e) => Err(e),
				}
			}
            Ok(TlpFormatEncodingType::ConfigType1Request) => {
                    match TlpFmt::try_from(tlp_fmt) {
                            Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::ConfType1ReadReq),
                            Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::ConfType1WriteReq),
                            Ok(_) => Err(TlpError::UnsupportedCombination),
							Err(e) => Err(e),
                    }
            }
			Ok(TlpFormatEncodingType::Completion) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::Cpl),
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::CplData),
					Ok(_) => Err(TlpError::UnsupportedCombination),
					Err(e) => Err(e),
				}
			}
			Ok(TlpFormatEncodingType::CompletionLocked) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::NoDataHeader3DW) => Ok(TlpType::CplLocked),
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::CplDataLocked),
					Ok(_) => Err(TlpError::UnsupportedCombination),
					Err(e) => Err(e),
				}
			}
			Ok(TlpFormatEncodingType::FetchAtomicOpRequest) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::FetchAddAtomicOpReq),
					Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::FetchAddAtomicOpReq),
					Ok(_) => Err(TlpError::UnsupportedCombination),
					Err(e) => Err(e),
				}
			}
			Ok(TlpFormatEncodingType::UnconSwapAtomicOpRequest) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::SwapAtomicOpReq),
					Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::SwapAtomicOpReq),
					Ok(_) => Err(TlpError::UnsupportedCombination),
					Err(e) => Err(e),
				}
			}
			Ok(TlpFormatEncodingType::CompSwapAtomicOpRequest) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::CompareSwapAtomicOpReq),
					Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::CompareSwapAtomicOpReq),
					Ok(_) => Err(TlpError::UnsupportedCombination),
					Err(e) => Err(e),
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
/// if let Ok(tlpfmt) = tlp.get_tlp_format() {
///     // MemRequest contain only fields specific to PCI Memory Requests
///     let mem_req: Box<dyn MemRequest> = new_mem_req(tlp.get_data(), &tlpfmt);
///
///     // Address is 64 bits regardles of TLP format
///     //println!("Memory Request Address: {:x}", mem_req.address());
///
///     // Format of TLP (3DW vs 4DW) is stored in the TLP header
///     println!("This TLP size is: {}", tlpfmt);
///     // Type LegacyIO vs MemRead vs MemWrite is stored in first DW of TLP
///     println!("This TLP type is: {:?}", tlp.get_tlp_type());
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
/// if let Ok(tlpfmt) = tlp.get_tlp_format() {
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
    header: TlpHeader<Vec<u8>>,
}

impl TlpPacketHeader {
    pub fn new(bytes: Vec<u8>) -> TlpPacketHeader {
        let mut dw0 = vec![0; 4];
        dw0[..4].clone_from_slice(&bytes[0..4]);

        TlpPacketHeader { header: TlpHeader(dw0) }
    }

    pub fn get_tlp_type(&self) -> Result<TlpType, TlpError> {
        self.header.get_tlp_type()
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
/// let tlp_format = packet.get_tlp_format().unwrap();
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

    pub fn get_tlp_type(&self) -> Result<TlpType, TlpError> {
        self.header.get_tlp_type()
    }

    pub fn get_tlp_format(&self) -> Result<TlpFmt, TlpError> {
        TlpFmt::try_from(self.header.get_format())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlp_header_type() {
        // Empty packet is still MemREAD: FMT '000' Type '0 0000' Length 0
        let memread = TlpHeader([0x0, 0x0, 0x0, 0x0]);
        assert_eq!(memread.get_tlp_type().unwrap(), TlpType::MemReadReq);

        // MemRead32 FMT '000' Type '0 0000'
        let memread32 = TlpHeader([0x00, 0x00, 0x20, 0x01]);
        assert_eq!(memread32.get_tlp_type().unwrap(), TlpType::MemReadReq);

        // MemWrite32 FMT '010' Type '0 0000'
        let memwrite32 = TlpHeader([0x40, 0x00, 0x00, 0x01]);
        assert_eq!(memwrite32.get_tlp_type().unwrap(), TlpType::MemWriteReq);

        // CPL without Data: FMT '000' Type '0 1010'
        let cpl_no_data = TlpHeader([0x0a, 0x00, 0x10, 0x00]);
        assert_eq!(cpl_no_data.get_tlp_type().unwrap(), TlpType::Cpl);

        // CPL with Data: FMT '010' Type '0 1010'
        let cpl_with_data = TlpHeader([0x4a, 0x00, 0x20, 0x40]);
        assert_eq!(cpl_with_data.get_tlp_type().unwrap(), TlpType::CplData);

        // MemRead 4DW: FMT: '001' Type '0 0000'
        let memread_4dw = TlpHeader([0x20, 0x00, 0x20, 0x40]);
        assert_eq!(memread_4dw.get_tlp_type().unwrap(), TlpType::MemReadReq);

        // Config Type 0 Read request: FMT: '000' Type '0 0100'
        let conf_t0_read = TlpHeader([0x04, 0x00, 0x00, 0x01]);
        assert_eq!(conf_t0_read.get_tlp_type().unwrap(), TlpType::ConfType0ReadReq);

        // Config Type 0 Write request: FMT: '010' Type '0 0100'
        let conf_t0_write = TlpHeader([0x44, 0x00, 0x00, 0x01]);
        assert_eq!(conf_t0_write.get_tlp_type().unwrap(), TlpType::ConfType0WriteReq);

        // Config Type 1 Read request: FMT: '000' Type '0 0101'
        let conf_t1_read = TlpHeader([0x05, 0x88, 0x80, 0x01]);
        assert_eq!(conf_t1_read.get_tlp_type().unwrap(), TlpType::ConfType1ReadReq);

        // Config Type 1 Write request: FMT: '010' Type '0 0101'
        let conf_t1_write = TlpHeader([0x45, 0x88, 0x80, 0x01]);
        assert_eq!(conf_t1_write.get_tlp_type().unwrap(), TlpType::ConfType1WriteReq);

        // HeaderLog: 04000001 0000220f 01070000 af36fc70
        // HeaderLog: 60009001 4000000f 00000280 4047605c
        let memwrite64 = TlpHeader([0x60, 0x00, 0x90, 0x01]);
        assert_eq!(memwrite64.get_tlp_type().unwrap(), TlpType::MemWriteReq);
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

    #[test]
    fn test_invalid_format_error() {
        // Format field with invalid value (e.g., 0b101 = 5)
        let invalid_fmt = TlpHeader([0xa0, 0x00, 0x00, 0x01]); // FMT='101' Type='00000'
        let result = invalid_fmt.get_tlp_type();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TlpError::InvalidFormat);
    }

    #[test]
    fn test_invalid_type_error() {
        // Type field with invalid encoding (e.g., 0b01111 = 15)
        let invalid_type = TlpHeader([0x0f, 0x00, 0x00, 0x01]); // FMT='000' Type='01111'
        let result = invalid_type.get_tlp_type();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TlpError::InvalidType);
    }

    #[test]
    fn test_unsupported_combination_error() {
        // Valid format and type but unsupported combination
        // IO Request with 4DW header (not valid)
        let invalid_combo = TlpHeader([0x22, 0x00, 0x00, 0x01]); // FMT='001' Type='00010' (IO Request 4DW)
        let result = invalid_combo.get_tlp_type();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), TlpError::UnsupportedCombination);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build a DW0-only TlpHeader from a 3-bit fmt and 5-bit type field.
    /// byte0 layout (MSB0): bits[7:5] = fmt, bits[4:0] = type
    fn dw0(fmt: u8, typ: u8) -> TlpHeader<[u8; 4]> {
        TlpHeader([(fmt << 5) | (typ & 0x1f), 0x00, 0x00, 0x00])
    }

    /// Build a full TLP byte vector: DW0 header + arbitrary payload bytes.
    /// DW0 bytes 1-3 are left 0 (length / TC / flags irrelevant for field tests).
    fn mk_tlp(fmt: u8, typ: u8, rest: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + rest.len());
        v.push((fmt << 5) | (typ & 0x1f));
        v.push(0x00); // TC, T9, T8, Attr_b2, LN, TH
        v.push(0x00); // TD, Ep, Attr, AT
        v.push(0x00); // Length
        v.extend_from_slice(rest);
        v
    }

    // ── happy path: every currently-supported (fmt, type) pair ────────────────

    #[test]
    fn header_decode_supported_pairs() {
        const FMT_3DW_NO_DATA:   u8 = 0b000;
        const FMT_4DW_NO_DATA:   u8 = 0b001;
        const FMT_3DW_WITH_DATA: u8 = 0b010;
        const FMT_4DW_WITH_DATA: u8 = 0b011;

        const TY_MEM:        u8 = 0b00000;
        const TY_MEM_LK:     u8 = 0b00001;
        const TY_IO:         u8 = 0b00010;
        const TY_CFG0:       u8 = 0b00100;
        const TY_CFG1:       u8 = 0b00101;
        const TY_CPL:        u8 = 0b01010;
        const TY_CPL_LK:     u8 = 0b01011;
        const TY_ATOM_FETCH: u8 = 0b01100;
        const TY_ATOM_SWAP:  u8 = 0b01101;
        const TY_ATOM_CAS:   u8 = 0b01110;

        // Memory Request: NoData → Read, WithData → Write; both 3DW and 4DW
        assert_eq!(dw0(FMT_3DW_NO_DATA,   TY_MEM).get_tlp_type().unwrap(), TlpType::MemReadReq);
        assert_eq!(dw0(FMT_4DW_NO_DATA,   TY_MEM).get_tlp_type().unwrap(), TlpType::MemReadReq);
        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_MEM).get_tlp_type().unwrap(), TlpType::MemWriteReq);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_MEM).get_tlp_type().unwrap(), TlpType::MemWriteReq);

        // Memory Lock Request: NoData only (3DW and 4DW)
        assert_eq!(dw0(FMT_3DW_NO_DATA, TY_MEM_LK).get_tlp_type().unwrap(), TlpType::MemReadLockReq);
        assert_eq!(dw0(FMT_4DW_NO_DATA, TY_MEM_LK).get_tlp_type().unwrap(), TlpType::MemReadLockReq);

        // IO Request: 3DW only; NoData → Read, WithData → Write
        assert_eq!(dw0(FMT_3DW_NO_DATA,   TY_IO).get_tlp_type().unwrap(), TlpType::IOReadReq);
        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_IO).get_tlp_type().unwrap(), TlpType::IOWriteReq);

        // Config Type 0: 3DW only
        assert_eq!(dw0(FMT_3DW_NO_DATA,   TY_CFG0).get_tlp_type().unwrap(), TlpType::ConfType0ReadReq);
        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_CFG0).get_tlp_type().unwrap(), TlpType::ConfType0WriteReq);

        // Config Type 1: 3DW only
        assert_eq!(dw0(FMT_3DW_NO_DATA,   TY_CFG1).get_tlp_type().unwrap(), TlpType::ConfType1ReadReq);
        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_CFG1).get_tlp_type().unwrap(), TlpType::ConfType1WriteReq);

        // Completion: 3DW only; NoData → Cpl, WithData → CplData
        assert_eq!(dw0(FMT_3DW_NO_DATA,   TY_CPL).get_tlp_type().unwrap(), TlpType::Cpl);
        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_CPL).get_tlp_type().unwrap(), TlpType::CplData);

        // Completion Locked: 3DW only
        assert_eq!(dw0(FMT_3DW_NO_DATA,   TY_CPL_LK).get_tlp_type().unwrap(), TlpType::CplLocked);
        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_CPL_LK).get_tlp_type().unwrap(), TlpType::CplDataLocked);

        // Atomics: WithData only (3DW and 4DW)
        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_ATOM_FETCH).get_tlp_type().unwrap(), TlpType::FetchAddAtomicOpReq);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_ATOM_FETCH).get_tlp_type().unwrap(), TlpType::FetchAddAtomicOpReq);

        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_ATOM_SWAP).get_tlp_type().unwrap(), TlpType::SwapAtomicOpReq);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_ATOM_SWAP).get_tlp_type().unwrap(), TlpType::SwapAtomicOpReq);

        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_ATOM_CAS).get_tlp_type().unwrap(), TlpType::CompareSwapAtomicOpReq);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_ATOM_CAS).get_tlp_type().unwrap(), TlpType::CompareSwapAtomicOpReq);
    }

    // ── negative path: every illegal (fmt, type) pair → UnsupportedCombination ─

    #[test]
    fn header_decode_rejects_unsupported_combinations() {
        const FMT_3DW_NO_DATA:   u8 = 0b000;
        const FMT_4DW_NO_DATA:   u8 = 0b001;
        const FMT_3DW_WITH_DATA: u8 = 0b010;
        const FMT_4DW_WITH_DATA: u8 = 0b011;
        const FMT_PREFIX:        u8 = 0b100;

        const TY_MEM_LK:     u8 = 0b00001;
        const TY_IO:         u8 = 0b00010;
        const TY_CFG0:       u8 = 0b00100;
        const TY_CFG1:       u8 = 0b00101;
        const TY_CPL:        u8 = 0b01010;
        const TY_CPL_LK:     u8 = 0b01011;
        const TY_ATOM_FETCH: u8 = 0b01100;
        const TY_ATOM_SWAP:  u8 = 0b01101;
        const TY_ATOM_CAS:   u8 = 0b01110;

        // IO: 4DW variants are illegal
        assert_eq!(dw0(FMT_4DW_NO_DATA,   TY_IO).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_IO).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);

        // Config: 4DW variants are illegal (configs are always 3DW)
        assert_eq!(dw0(FMT_4DW_NO_DATA,   TY_CFG0).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_CFG0).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_NO_DATA,   TY_CFG1).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_CFG1).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);

        // Completions: 4DW variants are illegal
        assert_eq!(dw0(FMT_4DW_NO_DATA,   TY_CPL).get_tlp_type().unwrap_err(),    TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_CPL).get_tlp_type().unwrap_err(),    TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_NO_DATA,   TY_CPL_LK).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_CPL_LK).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);

        // Atomics: NoData variants are illegal (atomics always carry data)
        assert_eq!(dw0(FMT_3DW_NO_DATA, TY_ATOM_FETCH).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_NO_DATA, TY_ATOM_FETCH).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_3DW_NO_DATA, TY_ATOM_SWAP).get_tlp_type().unwrap_err(),  TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_NO_DATA, TY_ATOM_SWAP).get_tlp_type().unwrap_err(),  TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_3DW_NO_DATA, TY_ATOM_CAS).get_tlp_type().unwrap_err(),   TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_NO_DATA, TY_ATOM_CAS).get_tlp_type().unwrap_err(),   TlpError::UnsupportedCombination);

        // MemReadLock: WithData variants are illegal (lock is a read-only operation)
        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_MEM_LK).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_MEM_LK).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);

        // TlpPrefix fmt (0b100) is a valid format value but illegal for all
        // request/completion type encodings — currently hits UnsupportedCombination
        assert_eq!(dw0(FMT_PREFIX, TY_IO).get_tlp_type().unwrap_err(),   TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_PREFIX, TY_CPL).get_tlp_type().unwrap_err(),  TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_PREFIX, TY_CFG0).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
    }

    // ── atomic tier-A: real bytes through the full packet pipeline ─────────────

    #[test]
    fn atomic_fetchadd_3dw_type_and_fields() {
        const FMT_3DW_WITH_DATA: u8 = 0b010;
        const TY_ATOM_FETCH:     u8 = 0b01100;

        // DW1+DW2 as MemRequest3DW sees them (MSB0):
        //   requester_id [15:0]  = 0x1234
        //   tag          [23:16] = 0x56
        //   last_dw_be   [27:24] = 0x0  (ignored for this test)
        //   first_dw_be  [31:28] = 0x0  (ignored for this test)
        //   address32    [63:32] = 0x89ABCDEF
        let payload = [
            0x12, 0x34, // req_id
            0x56, 0x00, // tag, BE nibbles
            0x89, 0xAB, 0xCD, 0xEF, // address32
        ];

        let pkt = TlpPacket::new(mk_tlp(FMT_3DW_WITH_DATA, TY_ATOM_FETCH, &payload));

        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::FetchAddAtomicOpReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader3DW);

        let fmt = pkt.get_tlp_format().unwrap();
        let mr = new_mem_req(pkt.get_data(), &fmt);
        assert_eq!(mr.req_id(),  0x1234);
        assert_eq!(mr.tag(),     0x56);
        assert_eq!(mr.address(), 0x89AB_CDEF);
    }

    #[test]
    fn atomic_cas_4dw_type_and_fields() {
        const FMT_4DW_WITH_DATA: u8 = 0b011;
        const TY_ATOM_CAS:       u8 = 0b01110;

        // DW1-DW3 as MemRequest4DW sees them (MSB0):
        //   requester_id [15:0]  = 0xBEEF
        //   tag          [23:16] = 0xA5
        //   last/first_dw_be     = 0x00
        //   address64    [95:32] = 0x1122_3344_5566_7788
        let payload = [
            0xBE, 0xEF, // req_id
            0xA5, 0x00, // tag, BE nibbles
            0x11, 0x22, 0x33, 0x44, // address64 high DW
            0x55, 0x66, 0x77, 0x88, // address64 low DW
        ];

        let pkt = TlpPacket::new(mk_tlp(FMT_4DW_WITH_DATA, TY_ATOM_CAS, &payload));

        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::CompareSwapAtomicOpReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader4DW);

        let fmt = pkt.get_tlp_format().unwrap();
        let mr = new_mem_req(pkt.get_data(), &fmt);
        assert_eq!(mr.req_id(),  0xBEEF);
        assert_eq!(mr.tag(),     0xA5);
        assert_eq!(mr.address(), 0x1122_3344_5566_7788);
    }
}

