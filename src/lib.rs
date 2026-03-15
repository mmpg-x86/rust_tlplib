use std::fmt::{self, Display};

use bitfield::bitfield;

/// Selects the framing mode used to interpret the raw byte buffer.
///
/// Non-flit mode covers PCIe 1.0 through 5.0. Flit mode was introduced
/// in PCIe 6.0 and uses fixed 256-byte containers.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TlpMode {
    /// Standard non-flit TLP framing (PCIe 1.0 – 5.0).
    /// Bytes are interpreted directly as a TLP header followed by optional payload.
    NonFlit,

    /// Flit-mode TLP framing (PCIe 6.0+).
    /// Supported by `TlpPacket::new` and `TlpPacket::get_flit_type()`.
    /// `TlpPacketHeader::new` with this mode returns `Err(TlpError::NotImplemented)`.
    Flit,
}

/// Errors that can occur when parsing TLP packets
#[derive(Debug, Clone, PartialEq)]
pub enum TlpError {
    /// Invalid format field value (bits don't match any known format)
    InvalidFormat,
    /// Invalid type field value (bits don't match any known type encoding)
    InvalidType,
    /// Unsupported combination of format and type
    UnsupportedCombination,
    /// Payload/header byte slice is too short to contain the expected fields
    InvalidLength,
    /// Feature exists in the API but is not yet implemented
    NotImplemented,
    /// A TLP type that requires a mandatory OHC word was parsed without it
    /// (e.g. I/O Write missing OHC-A2, Configuration Write missing OHC-A3)
    MissingMandatoryOhc,
}

impl fmt::Display for TlpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlpError::InvalidFormat => write!(f, "invalid TLP format field"),
            TlpError::InvalidType => write!(f, "invalid TLP type field"),
            TlpError::UnsupportedCombination => write!(f, "unsupported format/type combination"),
            TlpError::InvalidLength => write!(f, "byte slice too short for expected TLP fields"),
            TlpError::NotImplemented => write!(f, "feature not yet implemented"),
            TlpError::MissingMandatoryOhc => write!(f, "mandatory OHC word missing for this TLP type"),
        }
    }
}

impl std::error::Error for TlpError {}

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            TlpFmt::NoDataHeader3DW => "3DW no Data Header",
            TlpFmt::NoDataHeader4DW => "4DW no Data Header",
            TlpFmt::WithDataHeader3DW => "3DW with Data Header",
            TlpFmt::WithDataHeader4DW => "4DW with Data Header",
            TlpFmt::TlpPrefix => "Tlp Prefix",
        };
        write!(f, "{name}")
    }
}

impl TryFrom<u32> for TlpFmt {
    type Error = TlpError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            0b000 => Ok(TlpFmt::NoDataHeader3DW),
            0b001 => Ok(TlpFmt::NoDataHeader4DW),
            0b010 => Ok(TlpFmt::WithDataHeader3DW),
            0b011 => Ok(TlpFmt::WithDataHeader4DW),
            0b100 => Ok(TlpFmt::TlpPrefix),
            _     => Err(TlpError::InvalidFormat),
        }
    }
}

/// Atomic operation discriminant
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AtomicOp {
    FetchAdd,
    Swap,
    CompareSwap,
}

/// Operand width — derived from TLP format: 3DW → 32-bit, 4DW → 64-bit
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AtomicWidth {
    W32,
    W64,
}

#[derive(PartialEq)]
pub(crate) enum TlpFormatEncodingType {
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
    DeferrableMemoryWriteRequest = 0b11011,
}

impl TryFrom<u32> for TlpFormatEncodingType {
    type Error = TlpError;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            0b00000 => Ok(TlpFormatEncodingType::MemoryRequest),
            0b00001 => Ok(TlpFormatEncodingType::MemoryLockRequest),
            0b00010 => Ok(TlpFormatEncodingType::IORequest),
            0b00100 => Ok(TlpFormatEncodingType::ConfigType0Request),
            0b00101 => Ok(TlpFormatEncodingType::ConfigType1Request),
            0b01010 => Ok(TlpFormatEncodingType::Completion),
            0b01011 => Ok(TlpFormatEncodingType::CompletionLocked),
            0b01100 => Ok(TlpFormatEncodingType::FetchAtomicOpRequest),
            0b01101 => Ok(TlpFormatEncodingType::UnconSwapAtomicOpRequest),
            0b01110 => Ok(TlpFormatEncodingType::CompSwapAtomicOpRequest),
            0b11011 => Ok(TlpFormatEncodingType::DeferrableMemoryWriteRequest),
            _       => Err(TlpError::InvalidType),
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
    DeferrableMemWriteReq,
    LocalTlpPrefix,
    EndToEndTlpPrefix,
}

impl Display for TlpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
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
            TlpType::DeferrableMemWriteReq => "Deferrable Memory Write Request",
            TlpType::LocalTlpPrefix => "Local Tlp Prefix",
            TlpType::EndToEndTlpPrefix => "End To End Tlp Prefix",
        };
        write!(f, "{name}")
    }
}

impl TlpType {
    /// Returns `true` for non-posted TLP types (requests that expect a Completion).
    pub fn is_non_posted(&self) -> bool {
        matches!(self,
            TlpType::MemReadReq |
            TlpType::MemReadLockReq |
            TlpType::IOReadReq | TlpType::IOWriteReq |
            TlpType::ConfType0ReadReq | TlpType::ConfType0WriteReq |
            TlpType::ConfType1ReadReq | TlpType::ConfType1WriteReq |
            TlpType::FetchAddAtomicOpReq | TlpType::SwapAtomicOpReq | TlpType::CompareSwapAtomicOpReq |
            TlpType::DeferrableMemWriteReq
        )
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
			Ok(TlpFormatEncodingType::DeferrableMemoryWriteRequest) => {
				match TlpFmt::try_from(tlp_fmt) {
					Ok(TlpFmt::WithDataHeader3DW) => Ok(TlpType::DeferrableMemWriteReq),
					Ok(TlpFmt::WithDataHeader4DW) => Ok(TlpType::DeferrableMemWriteReq),
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
/// use rtlp_lib::TlpPacket;
/// use rtlp_lib::TlpFmt;
/// use rtlp_lib::TlpError;
/// use rtlp_lib::TlpMode;
/// use rtlp_lib::MemRequest;
/// use rtlp_lib::new_mem_req;
///
/// fn decode(bytes: Vec<u8>) -> Result<(), TlpError> {
///     let tlp = TlpPacket::new(bytes, TlpMode::NonFlit)?;
///
///     let tlpfmt = tlp.get_tlp_format()?;
///     // MemRequest contains only fields specific to PCI Memory Requests
///     let mem_req: Box<dyn MemRequest> = new_mem_req(tlp.get_data(), &tlpfmt)?;
///
///     // Address is 64 bits regardless of TLP format
///     // println!("Memory Request Address: {:x}", mem_req.address());
///
///     // Format of TLP (3DW vs 4DW) is stored in the TLP header
///     println!("This TLP size is: {}", tlpfmt);
///     // Type LegacyIO vs MemRead vs MemWrite is stored in first DW of TLP
///     println!("This TLP type is: {:?}", tlp.get_tlp_type());
///     Ok(())
/// }
///
///
/// # let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// # decode(bytes).unwrap();
/// ```
pub fn new_mem_req(bytes: Vec<u8>, format: &TlpFmt) -> Result<Box<dyn MemRequest>, TlpError> {
    match format {
        TlpFmt::NoDataHeader3DW => Ok(Box::new(MemRequest3DW(bytes))),
        TlpFmt::NoDataHeader4DW => Ok(Box::new(MemRequest4DW(bytes))),
        TlpFmt::WithDataHeader3DW => Ok(Box::new(MemRequest3DW(bytes))),
        TlpFmt::WithDataHeader4DW => Ok(Box::new(MemRequest4DW(bytes))),
        TlpFmt::TlpPrefix => Err(TlpError::UnsupportedCombination),
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
/// use rtlp_lib::TlpMode;
/// use rtlp_lib::ConfigurationRequest;
/// use rtlp_lib::new_conf_req;
///
/// let bytes = vec![0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
/// let tlp = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
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
    r,                      _: 56, 56;
    pub get_laddr,          _: 63, 57;
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
    u32;
    pub get_requester_id,   _: 15, 0;
    pub get_tag,            _: 23, 16;
    pub get_msg_code,       _: 31, 24;
    pub get_dw3,            _: 63, 32;
    pub get_dw4,            _: 95, 64;
}

impl <T: AsRef<[u8]>> MessageRequest for MessageReqDW24<T> {
    fn req_id(&self) -> u16 {
        self.get_requester_id() as u16
    }
    fn tag(&self) -> u8 {
        self.get_tag() as u8
    }
    fn msg_code(&self) -> u8 {
        self.get_msg_code() as u8
    }
    fn dw3(&self) -> u32 {
        self.get_dw3()
    }
    fn dw4(&self) -> u32 {
        self.get_dw4()
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

/// Atomic Request trait: header fields and operand(s) for atomic op TLPs.
/// Use `new_atomic_req()` to obtain a trait object from raw packet bytes.
pub trait AtomicRequest: std::fmt::Debug {
    fn op(&self) -> AtomicOp;
    fn width(&self) -> AtomicWidth;
    fn req_id(&self) -> u16;
    fn tag(&self) -> u8;
    fn address(&self) -> u64;
    /// Primary operand: addend (FetchAdd), new value (Swap), compare value (CAS)
    fn operand0(&self) -> u64;
    /// Second operand: swap value for CAS; `None` for FetchAdd and Swap
    fn operand1(&self) -> Option<u64>;
}

#[derive(Debug)]
struct AtomicReq {
    op:       AtomicOp,
    width:    AtomicWidth,
    req_id:   u16,
    tag:      u8,
    address:  u64,
    operand0: u64,
    operand1: Option<u64>,
}

impl AtomicRequest for AtomicReq {
    fn op(&self)       -> AtomicOp    { self.op }
    fn width(&self)    -> AtomicWidth { self.width }
    fn req_id(&self)   -> u16         { self.req_id }
    fn tag(&self)      -> u8          { self.tag }
    fn address(&self)  -> u64         { self.address }
    fn operand0(&self) -> u64         { self.operand0 }
    fn operand1(&self) -> Option<u64> { self.operand1 }
}

fn read_operand_be(b: &[u8], off: usize, width: AtomicWidth) -> u64 {
    match width {
        AtomicWidth::W32 => u32::from_be_bytes([b[off], b[off+1], b[off+2], b[off+3]]) as u64,
        AtomicWidth::W64 => u64::from_be_bytes([
            b[off], b[off+1], b[off+2], b[off+3],
            b[off+4], b[off+5], b[off+6], b[off+7],
        ]),
    }
}

/// Parse an atomic TLP request from a `TlpPacket`.
///
/// The TLP type and format are extracted from the packet header.
/// Returns `Err(TlpError::UnsupportedCombination)` if the packet does not
/// encode one of the three atomic op types, and `Err(TlpError::InvalidLength)`
/// if the data payload has the wrong size for the expected header and operands.
///
/// # Examples
///
/// ```
/// use rtlp_lib::{TlpPacket, TlpMode, AtomicRequest, new_atomic_req};
///
/// // FetchAdd 3DW: DW0 byte0 = (fmt=0b010 << 5) | typ=0b01100 = 0x4C
/// let bytes = vec![
///     0x4C, 0x00, 0x00, 0x00, // DW0: WithDataHeader3DW / FetchAdd
///     0xAB, 0xCD, 0x01, 0x00, // DW1: req_id=0xABCD tag=1 BE=0
///     0x00, 0x00, 0x10, 0x00, // DW2: address32=0x0000_1000
///     0x00, 0x00, 0x00, 0x04, // operand: addend=4
/// ];
/// let pkt = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
/// let ar = new_atomic_req(&pkt).unwrap();
/// assert_eq!(ar.req_id(),   0xABCD);
/// assert_eq!(ar.operand0(), 4);
/// assert!(ar.operand1().is_none());
/// ```
pub fn new_atomic_req(pkt: &TlpPacket) -> Result<Box<dyn AtomicRequest>, TlpError> {
    let tlp_type = pkt.get_tlp_type()?;
    let format   = pkt.get_tlp_format()?;
    let bytes    = pkt.get_data();

    let op = match tlp_type {
        TlpType::FetchAddAtomicOpReq    => AtomicOp::FetchAdd,
        TlpType::SwapAtomicOpReq        => AtomicOp::Swap,
        TlpType::CompareSwapAtomicOpReq => AtomicOp::CompareSwap,
        _                               => return Err(TlpError::UnsupportedCombination),
    };
    let (width, hdr_len) = match format {
        TlpFmt::WithDataHeader3DW => (AtomicWidth::W32, 8usize),
        TlpFmt::WithDataHeader4DW => (AtomicWidth::W64, 12usize),
        _                         => return Err(TlpError::UnsupportedCombination),
    };

    let op_size = match width { AtomicWidth::W32 => 4usize, AtomicWidth::W64 => 8usize };
    let num_ops = if matches!(op, AtomicOp::CompareSwap) { 2 } else { 1 };
    let needed  = hdr_len + op_size * num_ops;
    if bytes.len() != needed { return Err(TlpError::InvalidLength); }

    let req_id  = u16::from_be_bytes([bytes[0], bytes[1]]);
    let tag     = bytes[2];
    let address = match width {
        AtomicWidth::W32 => u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64,
        AtomicWidth::W64 => u64::from_be_bytes([
            bytes[4], bytes[5], bytes[6],  bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
        ]),
    };

    let operand0 = read_operand_be(&bytes, hdr_len, width);
    let operand1 = if matches!(op, AtomicOp::CompareSwap) {
        Some(read_operand_be(&bytes, hdr_len + op_size, width))
    } else {
        None
    };

    Ok(Box::new(AtomicReq { op, width, req_id, tag, address, operand0, operand1 }))
}

// ============================================================================
// Flit Mode types (PCIe 6.x)
// ============================================================================

/// TLP type codes used in Flit Mode DW0 byte 0.
///
/// These are **completely different** from the non-flit `TlpType` encoding.
/// In flit mode, `DW0[7:0]` is a flat 8-bit type code rather than the
/// non-flit `Fmt[2:0] | Type[4:0]` split.
///
/// `#[non_exhaustive]` — future type codes will be added without breaking
/// downstream `match` arms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlitTlpType {
    /// NOP — smallest flit object, 1 DW base header, no payload.
    Nop,
    /// 32-bit Memory Read Request (3 DW base header, no payload despite Length field).
    MemRead32,
    /// UIO Memory Read — 64-bit address, 4 DW base header (PCIe 6.1+ UIO).
    UioMemRead,
    /// Message routed to Root Complex, no data.
    MsgToRc,
    /// 32-bit Memory Write Request (3 DW base header + payload).
    MemWrite32,
    /// I/O Write Request — requires mandatory OHC-A2.
    IoWrite,
    /// Type 0 Configuration Write Request — requires mandatory OHC-A3.
    CfgWrite0,
    /// 32-bit FetchAdd AtomicOp Request.
    FetchAdd32,
    /// 32-bit Compare-and-Swap AtomicOp Request (2 DW payload).
    CompareSwap32,
    /// 32-bit Deferrable Memory Write Request.
    DeferrableMemWrite32,
    /// UIO Memory Write — 64-bit address, 4 DW base header (PCIe 6.1+ UIO).
    UioMemWrite,
    /// Message with Data routed to Root Complex.
    MsgDToRc,
    /// Local TLP Prefix token (1 DW base header).
    LocalTlpPrefix,
}

impl FlitTlpType {
    /// Base header size in DW, **not** counting OHC extension words.
    ///
    /// - NOP and LocalTlpPrefix: 1 DW
    /// - UIO types (64-bit address): 4 DW
    /// - All other types: 3 DW
    pub fn base_header_dw(&self) -> u8 {
        match self {
            FlitTlpType::Nop | FlitTlpType::LocalTlpPrefix => 1,
            FlitTlpType::UioMemRead | FlitTlpType::UioMemWrite => 4,
            _ => 3,
        }
    }

    /// Returns `true` for read requests that carry **no payload** even when
    /// the `Length` field is non-zero.
    pub fn is_read_request(&self) -> bool {
        matches!(self, FlitTlpType::MemRead32 | FlitTlpType::UioMemRead)
    }
}

impl TryFrom<u8> for FlitTlpType {
    type Error = TlpError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(FlitTlpType::Nop),
            0x03 => Ok(FlitTlpType::MemRead32),
            0x22 => Ok(FlitTlpType::UioMemRead),
            0x30 => Ok(FlitTlpType::MsgToRc),
            0x40 => Ok(FlitTlpType::MemWrite32),
            0x42 => Ok(FlitTlpType::IoWrite),
            0x44 => Ok(FlitTlpType::CfgWrite0),
            0x4C => Ok(FlitTlpType::FetchAdd32),
            0x4E => Ok(FlitTlpType::CompareSwap32),
            0x5B => Ok(FlitTlpType::DeferrableMemWrite32),
            0x61 => Ok(FlitTlpType::UioMemWrite),
            0x70 => Ok(FlitTlpType::MsgDToRc),
            0x8D => Ok(FlitTlpType::LocalTlpPrefix),
            _    => Err(TlpError::InvalidType),
        }
    }
}

/// Parsed representation of a flit-mode DW0 (first 4 bytes of a flit TLP).
///
/// Flit-mode DW0 layout:
///
/// ```text
/// Byte 0: Type[7:0]            — flat 8-bit type code
/// Byte 1: TC[2:0] | OHC[4:0]  — traffic class + OHC presence bitmap
/// Byte 2: TS[2:0] | Attr[2:0] | Length[9:8]
/// Byte 3: Length[7:0]
/// ```
///
/// Use [`FlitDW0::from_dw0`] to parse from a byte slice.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlitDW0 {
    /// Decoded TLP type.
    pub tlp_type: FlitTlpType,
    /// Traffic Class (bits `[2:0]` of byte 1).
    pub tc: u8,
    /// OHC presence bitmap (bits `[4:0]` of byte 1).
    /// Each set bit indicates one Optional Header Content word appended
    /// after the base header. Use [`FlitDW0::ohc_count`] for the DW count.
    pub ohc: u8,
    /// Transaction Steering (bits `[7:5]` of byte 2).
    pub ts: u8,
    /// Attributes (bits `[4:2]` of byte 2).
    pub attr: u8,
    /// Payload length in DW. A value of `0` encodes 1024 DW.
    pub length: u16,
}

impl FlitDW0 {
    /// Parse the flit-mode DW0 from the first 4 bytes of a byte slice.
    ///
    /// Returns `Err(TlpError::InvalidLength)` if `b.len() < 4`.
    /// Returns `Err(TlpError::InvalidType)` if the type code is unknown.
    pub fn from_dw0(b: &[u8]) -> Result<Self, TlpError> {
        if b.len() < 4 {
            return Err(TlpError::InvalidLength);
        }
        let tlp_type = FlitTlpType::try_from(b[0])?;
        let tc       = (b[1] >> 5) & 0x07;
        let ohc      = b[1] & 0x1F;
        let ts       = (b[2] >> 5) & 0x07;
        let attr     = (b[2] >> 2) & 0x07;
        let length   = (((b[2] & 0x03) as u16) << 8) | (b[3] as u16);
        Ok(FlitDW0 { tlp_type, tc, ohc, ts, attr, length })
    }

    /// Number of OHC extension words present — popcount of [`FlitDW0::ohc`].
    pub fn ohc_count(&self) -> u8 {
        self.ohc.count_ones() as u8
    }

    /// Total TLP size in bytes:
    /// `(base_header_dw + ohc_count) × 4 + payload_bytes`
    ///
    /// Read requests carry **no** payload bytes even when `length > 0`.
    pub fn total_bytes(&self) -> usize {
        let header_bytes = (self.tlp_type.base_header_dw() as usize
            + self.ohc_count() as usize) * 4;
        let payload_bytes = if self.tlp_type.is_read_request() {
            0
        } else {
            self.length as usize * 4
        };
        header_bytes + payload_bytes
    }
}

/// Parsed OHC-A word — the byte layout is shared by OHC-A1, OHC-A2, and OHC-A3.
///
/// OHC-A word byte layout (4 bytes, on-wire order):
///
/// ```text
/// Byte 0: flags[7:4] | PASID[19:16]
/// Byte 1: PASID[15:8]
/// Byte 2: PASID[7:0]
/// Byte 3: ldwbe[7:4] | fdwbe[3:0]
/// ```
///
/// Use [`FlitOhcA::from_bytes`] to parse from a byte slice that starts at the
/// first byte of the OHC-A word (i.e. at offset `base_header_dw * 4` in the TLP).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlitOhcA {
    /// 20-bit PASID value extracted from bytes 0–2.
    pub pasid: u32,
    /// First DW byte enables (bits `[3:0]` of byte 3).
    pub fdwbe: u8,
    /// Last DW byte enables (bits `[7:4]` of byte 3).
    pub ldwbe: u8,
}

impl FlitOhcA {
    /// Parse one OHC-A word from the first 4 bytes of `b`.
    ///
    /// Returns `Err(TlpError::InvalidLength)` if `b.len() < 4`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, TlpError> {
        if b.len() < 4 {
            return Err(TlpError::InvalidLength);
        }
        let pasid = ((b[0] as u32 & 0x0F) << 16)
            | ((b[1] as u32) << 8)
            | (b[2] as u32);
        let fdwbe = b[3] & 0x0F;
        let ldwbe = (b[3] >> 4) & 0x0F;
        Ok(FlitOhcA { pasid, fdwbe, ldwbe })
    }
}

impl FlitDW0 {
    /// Validate mandatory OHC rules for this TLP type.
    ///
    /// Some flit-mode TLP types **require** an OHC word to be present:
    /// - `IoWrite` requires OHC-A2 (bit 0 of the OHC bitmap must be set)
    /// - `CfgWrite0` requires OHC-A3 (bit 0 of the OHC bitmap must be set)
    ///
    /// Returns `Err(TlpError::MissingMandatoryOhc)` if the rule is violated.
    pub fn validate_mandatory_ohc(&self) -> Result<(), TlpError> {
        match self.tlp_type {
            FlitTlpType::IoWrite | FlitTlpType::CfgWrite0 => {
                if self.ohc & 0x01 == 0 {
                    return Err(TlpError::MissingMandatoryOhc);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Iterator over a packed stream of flit-mode TLPs.
///
/// Walks a byte slice containing back-to-back flit TLPs and yields
/// `Ok((offset, FlitTlpType, total_size))` for each one.
///
/// Returns `Some(Err(TlpError::InvalidLength))` if a TLP extends beyond
/// the end of the slice (truncated payload). After the first error,
/// subsequent calls to `next()` return `None`.
///
/// # Examples
///
/// ```
/// use rtlp_lib::{FlitStreamWalker, FlitTlpType};
///
/// let nop = [0x00u8, 0x00, 0x00, 0x00];
/// let (offset, typ, size) = FlitStreamWalker::new(&nop).next().unwrap().unwrap();
/// assert_eq!(offset, 0);
/// assert_eq!(typ, FlitTlpType::Nop);
/// assert_eq!(size, 4);
/// ```
pub struct FlitStreamWalker<'a> {
    data: &'a [u8],
    pos: usize,
    errored: bool,
}

impl<'a> FlitStreamWalker<'a> {
    /// Create a new walker over a packed flit TLP byte stream.
    pub fn new(data: &'a [u8]) -> Self {
        FlitStreamWalker { data, pos: 0, errored: false }
    }
}

impl<'a> Iterator for FlitStreamWalker<'a> {
    type Item = Result<(usize, FlitTlpType, usize), TlpError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.errored || self.pos >= self.data.len() {
            return None;
        }
        let offset = self.pos;
        let dw0 = match FlitDW0::from_dw0(&self.data[self.pos..]) {
            Ok(d)  => d,
            Err(e) => { self.errored = true; return Some(Err(e)); }
        };
        let total = dw0.total_bytes();
        if self.pos + total > self.data.len() {
            self.errored = true;
            return Some(Err(TlpError::InvalidLength));
        }
        self.pos += total;
        Some(Ok((offset, dw0.tlp_type, total)))
    }
}

// ============================================================================
// End of Flit Mode types
// ============================================================================

/// TLP Packet Header
/// Contains bytes for Packet header and informations about TLP type
pub struct TlpPacketHeader {
    header: TlpHeader<Vec<u8>>,
}

impl TlpPacketHeader {
    /// Create a new `TlpPacketHeader` from raw bytes and the specified framing mode.
    ///
    /// Use `TlpMode::NonFlit` for PCIe 1.0–5.0 standard TLP framing.
    /// `TlpMode::Flit` is reserved for future PCIe 6.0 support and currently
    /// returns `Err(TlpError::NotImplemented)`.
    pub fn new(bytes: Vec<u8>, mode: TlpMode) -> Result<TlpPacketHeader, TlpError> {
        match mode {
            TlpMode::NonFlit => Self::new_non_flit(bytes),
            TlpMode::Flit => Err(TlpError::NotImplemented),
        }
    }

    fn new_non_flit(bytes: Vec<u8>) -> Result<TlpPacketHeader, TlpError> {
        if bytes.len() < 4 {
            return Err(TlpError::InvalidLength);
        }
        let mut dw0 = vec![0; 4];
        dw0[..4].clone_from_slice(&bytes[0..4]);

        Ok(TlpPacketHeader { header: TlpHeader(dw0) })
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
/// use rtlp_lib::TlpMode;
/// use rtlp_lib::new_msg_req;
/// use rtlp_lib::new_conf_req;
/// use rtlp_lib::new_mem_req;
/// use rtlp_lib::new_cmpl_req;
///
/// // Bytes for full TLP Packet
/// //               <------- DW1 -------->  <------- DW2 -------->  <------- DW3 -------->  <------- DW4 -------->
/// let bytes = vec![0x00, 0x00, 0x20, 0x01, 0x04, 0x00, 0x00, 0x01, 0x20, 0x01, 0xFF, 0x00, 0xC2, 0x81, 0xFF, 0x10];
/// let packet = TlpPacket::new(bytes, TlpMode::NonFlit).unwrap();
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
///      TlpType::DeferrableMemWriteReq |
///      TlpType::IOReadReq |
///      TlpType::IOWriteReq |
///      TlpType::FetchAddAtomicOpReq |
///      TlpType::SwapAtomicOpReq |
///      TlpType::CompareSwapAtomicOpReq => requester_id = new_mem_req(packet.get_data(), &tlp_format).unwrap().req_id(),
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
    /// Set when the packet was created from `TlpMode::Flit` bytes.
    /// `None` for non-flit packets.
    flit_dw0: Option<FlitDW0>,
    data: Vec<u8>,
}

impl TlpPacket {
    /// Create a new `TlpPacket` from raw bytes and the specified framing mode.
    ///
    /// Use `TlpMode::NonFlit` for standard PCIe 1.0–5.0 TLP framing.
    /// Use `TlpMode::Flit` for PCIe 6.x flit-mode TLP framing.
    pub fn new(bytes: Vec<u8>, mode: TlpMode) -> Result<TlpPacket, TlpError> {
        match mode {
            TlpMode::NonFlit => Self::new_non_flit(bytes),
            TlpMode::Flit    => Self::new_flit(bytes),
        }
    }

    fn new_non_flit(bytes: Vec<u8>) -> Result<TlpPacket, TlpError> {
        if bytes.len() < 4 {
            return Err(TlpError::InvalidLength);
        }
        let mut ownbytes = bytes.to_vec();
        let mut header = vec![0; 4];
        header.clone_from_slice(&ownbytes[0..4]);
        let data = ownbytes.drain(4..).collect();
        Ok(TlpPacket {
            header: TlpPacketHeader::new_non_flit(header)?,
            flit_dw0: None,
            data,
        })
    }

    fn new_flit(bytes: Vec<u8>) -> Result<TlpPacket, TlpError> {
        if bytes.len() < 4 {
            return Err(TlpError::InvalidLength);
        }
        let dw0 = FlitDW0::from_dw0(&bytes)?;
        dw0.validate_mandatory_ohc()?;

        let hdr_bytes = (dw0.tlp_type.base_header_dw() as usize
            + dw0.ohc_count() as usize) * 4;
        if bytes.len() < hdr_bytes {
            return Err(TlpError::InvalidLength);
        }
        let payload = bytes[hdr_bytes..].to_vec();

        // Use a dummy non-flit header; callers should use get_flit_type() for type queries.
        let dummy = TlpPacketHeader::new_non_flit(vec![0u8; 4])?;
        Ok(TlpPacket { header: dummy, flit_dw0: Some(dw0), data: payload })
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

    /// Returns the flit-mode TLP type when the packet was created from
    /// `TlpMode::Flit` bytes, or `None` for non-flit packets.
    pub fn get_flit_type(&self) -> Option<FlitTlpType> {
        self.flit_dw0.map(|d| d.tlp_type)
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

    // ── new_mem_req rejects TlpPrefix ──────────────────────────────────────

    #[test]
    fn mem_req_rejects_tlp_prefix() {
        let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = new_mem_req(bytes, &TlpFmt::TlpPrefix);
        assert!(matches!(result, Err(TlpError::UnsupportedCombination)));
    }
  
    // ── short packet rejection ─────────────────────────────────────────────
  
    #[test]
    fn packet_new_rejects_empty_input() {
        assert!(matches!(TlpPacket::new(vec![], TlpMode::NonFlit), Err(TlpError::InvalidLength)));
    }

    #[test]
    fn packet_new_rejects_3_bytes() {
        assert!(matches!(TlpPacket::new(vec![0x00, 0x00, 0x00], TlpMode::NonFlit), Err(TlpError::InvalidLength)));
    }

    #[test]
    fn packet_new_accepts_4_bytes() {
        // Exactly 4 bytes = header only, no data — should succeed
        assert!(TlpPacket::new(vec![0x00, 0x00, 0x00, 0x00], TlpMode::NonFlit).is_ok());
    }

    #[test]
    fn packet_header_new_rejects_short_input() {
        assert!(matches!(TlpPacketHeader::new(vec![0x00, 0x00], TlpMode::NonFlit), Err(TlpError::InvalidLength)));
    }

    // ── TlpMode: Flit ─────────────────────────────────────────────────────

    #[test]
    fn packet_new_flit_succeeds_for_valid_nop() {
        // NOP flit TLP (type 0x00, 1 DW base header, no payload)
        let bytes = vec![0x00, 0x00, 0x00, 0x00];
        let pkt = TlpPacket::new(bytes, TlpMode::Flit).unwrap();
        assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::Nop));
        assert!(pkt.get_data().is_empty());
    }

    #[test]
    fn packet_new_flit_mrd32_has_no_payload() {
        // MRd32 flit (type 0x03, 3 DW base header, no payload despite Length=1)
        let bytes = vec![0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let pkt = TlpPacket::new(bytes, TlpMode::Flit).unwrap();
        assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::MemRead32));
        assert!(pkt.get_data().is_empty()); // read request, no payload
    }

    #[test]
    fn packet_new_flit_mwr32_has_payload() {
        // MWr32 flit (type 0x40, 3 DW base header + 1 DW payload)
        let bytes = vec![
            0x40, 0x00, 0x00, 0x01, // DW0: MemWrite32, length=1
            0x00, 0x00, 0x00, 0x00, // DW1
            0x00, 0x00, 0x00, 0x00, // DW2
            0xDE, 0xAD, 0xBE, 0xEF, // payload
        ];
        let pkt = TlpPacket::new(bytes, TlpMode::Flit).unwrap();
        assert_eq!(pkt.get_flit_type(), Some(FlitTlpType::MemWrite32));
        assert_eq!(pkt.get_data(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn packet_new_flit_nonflit_returns_none_for_flit_type() {
        // Non-flit packets should return None from get_flit_type()
        let pkt = TlpPacket::new(vec![0x00, 0x00, 0x00, 0x00], TlpMode::NonFlit).unwrap();
        assert_eq!(pkt.get_flit_type(), None);
    }

    #[test]
    fn packet_header_new_flit_returns_not_implemented() {
        // TlpPacketHeader::new() with Flit still returns NotImplemented
        let bytes = vec![0x00, 0x00, 0x00, 0x00];
        assert_eq!(TlpPacketHeader::new(bytes, TlpMode::Flit).err().unwrap(), TlpError::NotImplemented);
    }

    // ── TlpMode: derive traits ─────────────────────────────────────────────

    #[test]
    fn tlp_mode_debug_and_partialeq() {
        assert_eq!(TlpMode::NonFlit, TlpMode::NonFlit);
        assert_ne!(TlpMode::NonFlit, TlpMode::Flit);
        let s = format!("{:?}", TlpMode::NonFlit);
        assert!(s.contains("NonFlit"));
        let s2 = format!("{:?}", TlpMode::Flit);
        assert!(s2.contains("Flit"));
    }

    #[test]
    fn tlp_mode_copy_and_clone() {
        let m = TlpMode::NonFlit;
        let m2 = m; // Copy
        let m3 = m.clone(); // Clone
        assert_eq!(m2, TlpMode::NonFlit);
        assert_eq!(m3, TlpMode::NonFlit);
    }

    // ── TlpError::NotImplemented ──────────────────────────────────────────

    #[test]
    fn not_implemented_error_is_distinct() {
        let e = TlpError::NotImplemented;
        assert_ne!(e, TlpError::InvalidFormat);
        assert_ne!(e, TlpError::InvalidType);
        assert_ne!(e, TlpError::UnsupportedCombination);
        assert_ne!(e, TlpError::InvalidLength);
        assert_eq!(e, TlpError::NotImplemented);
        let s = format!("{:?}", e);
        assert!(s.contains("NotImplemented"));
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
        const TY_DMWR:       u8 = 0b11011;

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

        // DMWr: WithData only (3DW and 4DW)
        assert_eq!(dw0(FMT_3DW_WITH_DATA, TY_DMWR).get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
        assert_eq!(dw0(FMT_4DW_WITH_DATA, TY_DMWR).get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
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
        const TY_DMWR:       u8 = 0b11011;

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

        // DMWr: NoData variants are illegal (DMWr always carries data)
        assert_eq!(dw0(FMT_3DW_NO_DATA, TY_DMWR).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_4DW_NO_DATA, TY_DMWR).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
        assert_eq!(dw0(FMT_PREFIX,      TY_DMWR).get_tlp_type().unwrap_err(), TlpError::UnsupportedCombination);
    }

    // ── DMWr: Deferrable Memory Write header decode ────────────────────────

    #[test]
    fn tlp_header_dmwr32_decode() {
        // Fmt=010 (3DW w/ Data), Type=11011 (DMWr) → byte0 = 0x5B
        let dmwr32 = TlpHeader([0x5B, 0x00, 0x00, 0x00]);
        assert_eq!(dmwr32.get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
    }

    #[test]
    fn tlp_header_dmwr64_decode() {
        // Fmt=011 (4DW w/ Data), Type=11011 (DMWr) → byte0 = 0x7B
        let dmwr64 = TlpHeader([0x7B, 0x00, 0x00, 0x00]);
        assert_eq!(dmwr64.get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
    }

    #[test]
    fn tlp_header_dmwr_rejects_nodata_formats() {
        // Fmt=000, Type=11011 → byte0 = 0x1B
        let dmwr_bad_3dw_nodata = TlpHeader([0x1B, 0x00, 0x00, 0x00]);
        assert_eq!(
            dmwr_bad_3dw_nodata.get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );

        // Fmt=001, Type=11011 → byte0 = 0x3B
        let dmwr_bad_4dw_nodata = TlpHeader([0x3B, 0x00, 0x00, 0x00]);
        assert_eq!(
            dmwr_bad_4dw_nodata.get_tlp_type().unwrap_err(),
            TlpError::UnsupportedCombination
        );
    }

    #[test]
    fn dmwr_full_packet_3dw_fields() {
        // DMWr32 through TlpPacket pipeline with MemRequest3DW fields
        let payload = [
            0xAB, 0xCD, 0x42, 0x0F, // req_id=0xABCD, tag=0x42, BE=0x0F
            0xDE, 0xAD, 0x00, 0x00, // address32=0xDEAD0000
        ];
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b11011, &payload), TlpMode::NonFlit).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader3DW);

        let mr = new_mem_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
        assert_eq!(mr.req_id(), 0xABCD);
        assert_eq!(mr.tag(),    0x42);
        assert_eq!(mr.address(), 0xDEAD_0000);
    }

    #[test]
    fn dmwr_full_packet_4dw_fields() {
        // DMWr64 through TlpPacket pipeline with MemRequest4DW fields
        let payload = [
            0xBE, 0xEF, 0xA5, 0x00, // req_id=0xBEEF, tag=0xA5
            0x11, 0x22, 0x33, 0x44, // address64 hi
            0x55, 0x66, 0x77, 0x88, // address64 lo
        ];
        let pkt = TlpPacket::new(mk_tlp(0b011, 0b11011, &payload), TlpMode::NonFlit).unwrap();
        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::DeferrableMemWriteReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader4DW);

        let mr = new_mem_req(pkt.get_data(), &pkt.get_tlp_format().unwrap()).unwrap();
        assert_eq!(mr.req_id(), 0xBEEF);
        assert_eq!(mr.tag(),    0xA5);
        assert_eq!(mr.address(), 0x1122_3344_5566_7788);
    }

    // ── is_non_posted() semantics ─────────────────────────────────────────────

    #[test]
    fn is_non_posted_returns_true_for_non_posted_types() {
        assert!(TlpType::MemReadReq.is_non_posted());
        assert!(TlpType::MemReadLockReq.is_non_posted());
        assert!(TlpType::IOReadReq.is_non_posted());
        assert!(TlpType::IOWriteReq.is_non_posted());
        assert!(TlpType::ConfType0ReadReq.is_non_posted());
        assert!(TlpType::ConfType0WriteReq.is_non_posted());
        assert!(TlpType::ConfType1ReadReq.is_non_posted());
        assert!(TlpType::ConfType1WriteReq.is_non_posted());
        assert!(TlpType::FetchAddAtomicOpReq.is_non_posted());
        assert!(TlpType::SwapAtomicOpReq.is_non_posted());
        assert!(TlpType::CompareSwapAtomicOpReq.is_non_posted());
        assert!(TlpType::DeferrableMemWriteReq.is_non_posted());
    }

    #[test]
    fn is_non_posted_returns_false_for_posted_types() {
        assert!(!TlpType::MemWriteReq.is_non_posted());
        assert!(!TlpType::MsgReq.is_non_posted());
        assert!(!TlpType::MsgReqData.is_non_posted());
    }

    #[test]
    fn is_non_posted_returns_false_for_completions() {
        // Completions are responses, not requests — is_non_posted() is false
        assert!(!TlpType::Cpl.is_non_posted());
        assert!(!TlpType::CplData.is_non_posted());
        assert!(!TlpType::CplLocked.is_non_posted());
        assert!(!TlpType::CplDataLocked.is_non_posted());
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

        let pkt = TlpPacket::new(mk_tlp(FMT_3DW_WITH_DATA, TY_ATOM_FETCH, &payload), TlpMode::NonFlit).unwrap();

        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::FetchAddAtomicOpReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader3DW);

        let fmt = pkt.get_tlp_format().unwrap();
        let mr = new_mem_req(pkt.get_data(), &fmt).unwrap();
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

        let pkt = TlpPacket::new(mk_tlp(FMT_4DW_WITH_DATA, TY_ATOM_CAS, &payload), TlpMode::NonFlit).unwrap();

        assert_eq!(pkt.get_tlp_type().unwrap(), TlpType::CompareSwapAtomicOpReq);
        assert_eq!(pkt.get_tlp_format().unwrap(), TlpFmt::WithDataHeader4DW);

        let fmt = pkt.get_tlp_format().unwrap();
        let mr = new_mem_req(pkt.get_data(), &fmt).unwrap();
        assert_eq!(mr.req_id(),  0xBEEF);
        assert_eq!(mr.tag(),     0xA5);
        assert_eq!(mr.address(), 0x1122_3344_5566_7788);
    }

    // ── atomic tier-B: operand parsing via new_atomic_req() ───────────────────

    #[test]
    fn fetchadd_3dw_operand() {
        // FetchAdd 3DW (W32): single 32-bit addend after the 8-byte header
        //   DW1: req_id=0xDEAD  tag=0x42  BE=0x00
        //   DW2: address32=0xC001_0004
        //   op0: addend=0x0000_000A
        let payload = [
            0xDE, 0xAD, 0x42, 0x00, // req_id, tag, BE
            0xC0, 0x01, 0x00, 0x04, // address32
            0x00, 0x00, 0x00, 0x0A, // addend (W32)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01100, &payload), TlpMode::NonFlit).unwrap();
        let ar  = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(),       AtomicOp::FetchAdd);
        assert_eq!(ar.width(),    AtomicWidth::W32);
        assert_eq!(ar.req_id(),   0xDEAD);
        assert_eq!(ar.tag(),      0x42);
        assert_eq!(ar.address(),  0xC001_0004);
        assert_eq!(ar.operand0(), 0x0A);
        assert!(ar.operand1().is_none());
    }

    #[test]
    fn fetchadd_4dw_operand() {
        // FetchAdd 4DW (W64): single 64-bit addend after the 12-byte header
        //   DW1: req_id=0x0042  tag=0xBB  BE=0x00
        //   DW2-DW3: address64=0x0000_0001_0000_0000
        //   op0: addend=0xFFFF_FFFF_FFFF_FFFF
        let payload = [
            0x00, 0x42, 0xBB, 0x00, // req_id, tag, BE
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // address64
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // addend (W64)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b011, 0b01100, &payload), TlpMode::NonFlit).unwrap();
        let ar  = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(),       AtomicOp::FetchAdd);
        assert_eq!(ar.width(),    AtomicWidth::W64);
        assert_eq!(ar.req_id(),   0x0042);
        assert_eq!(ar.tag(),      0xBB);
        assert_eq!(ar.address(),  0x0000_0001_0000_0000);
        assert_eq!(ar.operand0(), 0xFFFF_FFFF_FFFF_FFFF);
        assert!(ar.operand1().is_none());
    }

    #[test]
    fn swap_3dw_operand() {
        // Swap 3DW (W32): single 32-bit swap value
        //   DW1: req_id=0x1111  tag=0x05  BE=0x00
        //   DW2: address32=0xF000_0008
        //   op0: new_value=0xABCD_EF01
        let payload = [
            0x11, 0x11, 0x05, 0x00, // req_id, tag, BE
            0xF0, 0x00, 0x00, 0x08, // address32
            0xAB, 0xCD, 0xEF, 0x01, // new_value (W32)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01101, &payload), TlpMode::NonFlit).unwrap();
        let ar  = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(),       AtomicOp::Swap);
        assert_eq!(ar.width(),    AtomicWidth::W32);
        assert_eq!(ar.req_id(),   0x1111);
        assert_eq!(ar.tag(),      0x05);
        assert_eq!(ar.address(),  0xF000_0008);
        assert_eq!(ar.operand0(), 0xABCD_EF01);
        assert!(ar.operand1().is_none());
    }

    #[test]
    fn cas_3dw_two_operands() {
        // CAS 3DW (W32): compare then swap — two 32-bit operands
        //   DW1: req_id=0xABCD  tag=0x07  BE=0x00
        //   DW2: address32=0x0000_4000
        //   op0: compare=0xCAFE_BABE
        //   op1: swap=0xDEAD_BEEF
        let payload = [
            0xAB, 0xCD, 0x07, 0x00, // req_id, tag, BE
            0x00, 0x00, 0x40, 0x00, // address32
            0xCA, 0xFE, 0xBA, 0xBE, // compare (W32)
            0xDE, 0xAD, 0xBE, 0xEF, // swap    (W32)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01110, &payload), TlpMode::NonFlit).unwrap();
        let ar  = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(),       AtomicOp::CompareSwap);
        assert_eq!(ar.width(),    AtomicWidth::W32);
        assert_eq!(ar.req_id(),   0xABCD);
        assert_eq!(ar.tag(),      0x07);
        assert_eq!(ar.address(),  0x0000_4000);
        assert_eq!(ar.operand0(), 0xCAFE_BABE);
        assert_eq!(ar.operand1(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn cas_4dw_two_operands() {
        // CAS 4DW (W64): compare then swap — two 64-bit operands
        //   DW1: req_id=0x1234  tag=0xAA  BE=0x00
        //   DW2-DW3: address64=0xFFFF_FFFF_0000_0000
        //   op0: compare=0x0101_0101_0202_0202
        //   op1: swap=0x0303_0303_0404_0404
        let payload = [
            0x12, 0x34, 0xAA, 0x00, // req_id, tag, BE
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, // address64
            0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, // compare (W64)
            0x03, 0x03, 0x03, 0x03, 0x04, 0x04, 0x04, 0x04, // swap    (W64)
        ];
        let pkt = TlpPacket::new(mk_tlp(0b011, 0b01110, &payload), TlpMode::NonFlit).unwrap();
        let ar  = new_atomic_req(&pkt).unwrap();

        assert_eq!(ar.op(),       AtomicOp::CompareSwap);
        assert_eq!(ar.width(),    AtomicWidth::W64);
        assert_eq!(ar.req_id(),   0x1234);
        assert_eq!(ar.tag(),      0xAA);
        assert_eq!(ar.address(),  0xFFFF_FFFF_0000_0000);
        assert_eq!(ar.operand0(), 0x0101_0101_0202_0202);
        assert_eq!(ar.operand1(), Some(0x0303_0303_0404_0404));
    }

    #[test]
    fn atomic_req_rejects_wrong_tlp_type() {
        // MemRead type is not an atomic — should get UnsupportedCombination
        let pkt = TlpPacket::new(mk_tlp(0b000, 0b00000, &[0u8; 16]), TlpMode::NonFlit).unwrap();
        assert_eq!(new_atomic_req(&pkt).err().unwrap(), TlpError::UnsupportedCombination);
    }

    #[test]
    fn atomic_req_rejects_wrong_format() {
        // FetchAdd type with NoData3DW format is an invalid combo:
        // get_tlp_type() returns UnsupportedCombination, which propagates
        let pkt = TlpPacket::new(mk_tlp(0b000, 0b01100, &[0u8; 16]), TlpMode::NonFlit).unwrap();
        assert_eq!(new_atomic_req(&pkt).err().unwrap(), TlpError::UnsupportedCombination);
    }

    #[test]
    fn atomic_req_rejects_short_payload() {
        // 3 bytes data — FetchAdd 3DW needs exactly 12 (8 hdr + 4 operand)
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01100, &[0u8; 3]), TlpMode::NonFlit).unwrap();
        assert_eq!(new_atomic_req(&pkt).err().unwrap(), TlpError::InvalidLength);

        // 8 bytes data — header OK but operand missing (needs 12)
        let pkt = TlpPacket::new(mk_tlp(0b010, 0b01100, &[0u8; 8]), TlpMode::NonFlit).unwrap();
        assert_eq!(new_atomic_req(&pkt).err().unwrap(), TlpError::InvalidLength);

        // 20 bytes data — CAS 4DW needs exactly 28 (12 hdr + 8 + 8)
        let pkt = TlpPacket::new(mk_tlp(0b011, 0b01110, &[0u8; 20]), TlpMode::NonFlit).unwrap();
        assert_eq!(new_atomic_req(&pkt).err().unwrap(), TlpError::InvalidLength);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn mk_pkt(fmt: u8, typ: u8, data: &[u8]) -> TlpPacket {
        TlpPacket::new(mk_tlp(fmt, typ, data), TlpMode::NonFlit).unwrap()
    }

    // ── atomic tier-B (new API): real binary layout, single-argument call ─────

    #[test]
    fn atomic_fetchadd_3dw_32_parses_operands() {
        // FetchAdd 3DW (W32): 8-byte header + 4-byte addend
        let data = [
            0x01, 0x00, 0x01, 0x00, // req_id=0x0100, tag=0x01, BE=0x00
            0x00, 0x00, 0x10, 0x00, // address32=0x0000_1000
            0x00, 0x00, 0x00, 0x07, // addend=7
        ];
        let pkt = mk_pkt(0b010, 0b01100, &data);
        let a = new_atomic_req(&pkt).unwrap();
        assert_eq!(a.op(),       AtomicOp::FetchAdd);
        assert_eq!(a.width(),    AtomicWidth::W32);
        assert_eq!(a.req_id(),   0x0100);
        assert_eq!(a.tag(),      0x01);
        assert_eq!(a.address(),  0x0000_1000);
        assert_eq!(a.operand0(), 7);
        assert!(a.operand1().is_none());
    }

    #[test]
    fn atomic_swap_4dw_64_parses_operands() {
        // Swap 4DW (W64): 12-byte header + 8-byte new value
        let data = [
            0xBE, 0xEF, 0xA5, 0x00, // req_id=0xBEEF, tag=0xA5, BE=0x00
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // address64=0x0000_0001_0000_0000
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, // new_value
        ];
        let pkt = mk_pkt(0b011, 0b01101, &data);
        let a = new_atomic_req(&pkt).unwrap();
        assert_eq!(a.op(),       AtomicOp::Swap);
        assert_eq!(a.width(),    AtomicWidth::W64);
        assert_eq!(a.req_id(),   0xBEEF);
        assert_eq!(a.tag(),      0xA5);
        assert_eq!(a.address(),  0x0000_0001_0000_0000);
        assert_eq!(a.operand0(), 0xDEAD_BEEF_CAFE_BABE);
        assert!(a.operand1().is_none());
    }

    #[test]
    fn atomic_cas_3dw_32_parses_operands() {
        // CAS 3DW (W32): 8-byte header + 4-byte compare + 4-byte swap
        let data = [
            0xAB, 0xCD, 0x07, 0x00, // req_id=0xABCD, tag=0x07, BE=0x00
            0x00, 0x00, 0x40, 0x00, // address32=0x0000_4000
            0xCA, 0xFE, 0xBA, 0xBE, // compare
            0xDE, 0xAD, 0xBE, 0xEF, // swap
        ];
        let pkt = mk_pkt(0b010, 0b01110, &data);
        let a = new_atomic_req(&pkt).unwrap();
        assert_eq!(a.op(),       AtomicOp::CompareSwap);
        assert_eq!(a.width(),    AtomicWidth::W32);
        assert_eq!(a.req_id(),   0xABCD);
        assert_eq!(a.tag(),      0x07);
        assert_eq!(a.address(),  0x0000_4000);
        assert_eq!(a.operand0(), 0xCAFE_BABE);
        assert_eq!(a.operand1(), Some(0xDEAD_BEEF));
    }

    // ── CompletionReqDW23: Lower Address 7-bit decode ──────────────────────

    #[test]
    fn completion_laddr_full_7_bits() {
        // Lower Address = 0x7F (127) — all 7 bits set
        // DW2 byte 3: R(1 bit)=0, LowerAddr(7 bits)=0x7F → byte = 0x7F
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00, // completer_id, cmpl_stat, bcm, byte_cnt
            0x00, 0x00, 0x00, 0x7F, // req_id, tag, R=0, laddr=0x7F
        ];
        let cmpl = new_cmpl_req(bytes, &TlpFmt::NoDataHeader3DW);
        assert_eq!(cmpl.laddr(), 0x7F);
    }

    #[test]
    fn completion_laddr_bit6_set() {
        // Lower Address = 64 (0x40) — bit 6 is the bit that was previously lost
        // DW2 byte 3: R=0, LowerAddr=0x40 → byte = 0x40
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x40,
        ];
        let cmpl = new_cmpl_req(bytes, &TlpFmt::NoDataHeader3DW);
        assert_eq!(cmpl.laddr(), 0x40);
    }

    #[test]
    fn completion_laddr_with_reserved_bit_set() {
        // R=1, LowerAddr=0x55 (85)
        // DW2 byte 3: 1_1010101 = 0xD5
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xD5,
        ];
        let cmpl = new_cmpl_req(bytes, &TlpFmt::NoDataHeader3DW);
        assert_eq!(cmpl.laddr(), 0x55);
    }

    #[test]
    fn completion_full_fields_with_laddr() {
        // completer_id=0x2001, cmpl_stat=0, bcm=0, byte_cnt=0x0FC,
        // req_id=0x1234, tag=0xAB, R=0, laddr=100 (0x64)
        let bytes = vec![
            0x20, 0x01, 0x00, 0xFC, // completer_id=0x2001, status=0, bcm=0, byte_cnt=0x0FC
            0x12, 0x34, 0xAB, 0x64, // req_id=0x1234, tag=0xAB, R=0, laddr=0x64
        ];
        let cmpl = new_cmpl_req(bytes, &TlpFmt::NoDataHeader3DW);
        assert_eq!(cmpl.cmpl_id(), 0x2001);
        assert_eq!(cmpl.byte_cnt(), 0x0FC);
        assert_eq!(cmpl.req_id(), 0x1234);
        assert_eq!(cmpl.tag(), 0xAB);
        assert_eq!(cmpl.laddr(), 0x64);
    }

    #[test]
    fn atomic_fetchadd_rejects_invalid_operand_length() {
        // FetchAdd 3DW expects exactly 12 bytes (8 hdr + 4 operand).
        // A 14-byte payload (8 hdr + 6-byte "bad" operand) must be rejected.
        let bad = [
            0x01, 0x00, 0x01, 0x00, // req_id, tag, BE
            0x00, 0x00, 0x10, 0x00, // address32
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 6 bytes instead of 4
        ];
        let pkt = mk_pkt(0b010, 0b01100, &bad);
        assert_eq!(new_atomic_req(&pkt).unwrap_err(), TlpError::InvalidLength);
    }

    // ── MessageReqDW24: DW3/DW4 full 32-bit decode ───────────────────────────

    #[test]
    fn message_dw3_preserves_upper_16_bits() {
        // DW3 = 0xDEAD_BEEF — upper 16 bits (0xDEAD) must survive
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00, // req_id, tag, msg_code
            0xDE, 0xAD, 0xBE, 0xEF, // DW3
            0x00, 0x00, 0x00, 0x00, // DW4
        ];
        let msg = new_msg_req(bytes, &TlpFmt::NoDataHeader3DW);
        assert_eq!(msg.dw3(), 0xDEAD_BEEF);
    }

    #[test]
    fn message_dw4_preserves_upper_16_bits() {
        // DW4 = 0xCAFE_BABE — upper 16 bits (0xCAFE) must survive
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00, // req_id, tag, msg_code
            0x00, 0x00, 0x00, 0x00, // DW3
            0xCA, 0xFE, 0xBA, 0xBE, // DW4
        ];
        let msg = new_msg_req(bytes, &TlpFmt::NoDataHeader3DW);
        assert_eq!(msg.dw4(), 0xCAFE_BABE);
    }

    #[test]
    fn message_dw3_dw4_all_bits_set() {
        // Both DW3 and DW4 = 0xFFFF_FFFF
        let bytes = vec![
            0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let msg = new_msg_req(bytes, &TlpFmt::NoDataHeader3DW);
        assert_eq!(msg.dw3(), 0xFFFF_FFFF);
        assert_eq!(msg.dw4(), 0xFFFF_FFFF);
    }

    #[test]
    fn message_request_full_fields() {
        // req_id=0xABCD, tag=0x42, msg_code=0x7F, DW3=0x1234_5678, DW4=0x9ABC_DEF0
        let bytes = vec![
            0xAB, 0xCD, 0x42, 0x7F,
            0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC, 0xDE, 0xF0,
        ];
        let msg = new_msg_req(bytes, &TlpFmt::NoDataHeader3DW);
        assert_eq!(msg.req_id(),   0xABCD);
        assert_eq!(msg.tag(),      0x42);
        assert_eq!(msg.msg_code(), 0x7F);
        assert_eq!(msg.dw3(),      0x1234_5678);
        assert_eq!(msg.dw4(),      0x9ABC_DEF0);
    }
}

