# Test Organization

This document describes the test structure for the rtlp-lib crate.

## Test Files

### 1. Unit Tests (`src/lib.rs`)
**Purpose:** Test internal implementation details not exposed in the public API.

**Location:** `#[cfg(test)] mod tests` inside `src/lib.rs`

**Tests (30 total):**
- `tlp_header_type` - Tests internal `TlpHeader` type detection
- `tlp_header_works_all_zeros` - Tests bitfield parsing with zero values
- `tlp_header_works_all_ones` - Tests bitfield parsing with all bits set
- `test_invalid_format_error` - Tests error handling for invalid format values
- `test_invalid_type_error` - Tests error handling for invalid type encoding
- `test_unsupported_combination_error` - Tests error handling for unsupported format/type combinations
- `header_decode_supported_pairs` - Tests all supported (fmt, type) combinations decode correctly
- `header_decode_rejects_unsupported_combinations` - Tests all illegal (fmt, type) pairs return `UnsupportedCombination`
- `tlp_header_dmwr32_decode` - Tests Deferrable Memory Write 3DW header decoding
- `tlp_header_dmwr64_decode` - Tests Deferrable Memory Write 4DW header decoding
- `tlp_header_dmwr_rejects_nodata_formats` - Tests DMWr rejection of no-data format combinations
- `dmwr_full_packet_3dw_fields` - Tests DMWr32 through full TlpPacket pipeline with field verification
- `dmwr_full_packet_4dw_fields` - Tests DMWr64 through full TlpPacket pipeline with field verification
- `is_non_posted_returns_true_for_non_posted_types` - Tests that read/IO/config/atomic types are non-posted
- `is_non_posted_returns_false_for_posted_types` - Tests that MemWrite and message types are posted
- `is_non_posted_returns_false_for_completions` - Tests that completion types are not non-posted
- `atomic_fetchadd_3dw_type_and_fields` - Tests FetchAdd 3DW type decoding and field parsing
- `atomic_cas_4dw_type_and_fields` - Tests CompareSwap 4DW type decoding and field parsing
- `fetchadd_3dw_operand` - Tests FetchAdd 3DW W32 single-operand parsing
- `fetchadd_4dw_operand` - Tests FetchAdd 4DW W64 single-operand parsing
- `swap_3dw_operand` - Tests Swap 3DW W32 single-operand parsing
- `cas_3dw_two_operands` - Tests CAS 3DW W32 two-operand parsing
- `cas_4dw_two_operands` - Tests CAS 4DW W64 two-operand parsing
- `atomic_req_rejects_wrong_tlp_type` - Tests `new_atomic_req` returns error for non-atomic TLP type
- `atomic_req_rejects_wrong_format` - Tests `new_atomic_req` returns error for invalid format combo
- `atomic_req_rejects_short_payload` - Tests `new_atomic_req` returns `InvalidLength` for short data
- `atomic_fetchadd_3dw_32_parses_operands` - Tests FetchAdd 3DW W32 operand parsing (new API)
- `atomic_swap_4dw_64_parses_operands` - Tests Swap 4DW W64 operand parsing (new API)
- `atomic_cas_3dw_32_parses_operands` - Tests CAS 3DW W32 operand parsing (new API)
- `atomic_fetchadd_rejects_invalid_operand_length` - Tests rejection of operand with invalid byte length

**Why separate:** These tests use `TlpHeader` which is an internal implementation detail, not part of the public API.

### 2. Integration Tests (`tests/tlp_tests.rs`)
**Purpose:** Test the library's functional behavior through its public API.

**Tests (16 total):**
- `test_tlp_packet` - Basic TLP packet parsing
- `test_complreq_trait` - Completion request trait functionality
- `test_configreq_trait` - Configuration request trait functionality
- `is_memreq_tag_works` - Memory request tag extraction (3DW and 4DW)
- `is_memreq_3dw_address_works` - 32-bit address parsing
- `is_memreq_4dw_address_works` - 64-bit address parsing
- `is_tlppacket_creates` - TlpPacketHeader creation
- `test_tlp_packet_invalid_type` - Error propagation through TlpPacket API
- `atomic_fetchadd_3dw_32_parses_operands` - FetchAdd 3DW W32 operand parsing end-to-end
- `atomic_swap_4dw_64_parses_operands` - Swap 4DW W64 operand parsing end-to-end
- `atomic_cas_3dw_32_parses_operands` - CAS 3DW W32 two-operand parsing end-to-end
- `atomic_fetchadd_rejects_invalid_operand_length` - Invalid atomic operand length error propagation
- `dmwr32_decode_via_tlppacket` - DMWr32 decoding and format verification via TlpPacket
- `dmwr64_decode_via_tlppacket` - DMWr64 decoding and format verification via TlpPacket
- `dmwr_rejects_nodata_formats` - DMWr rejects no-data format combinations
- `dmwr_is_non_posted` - DeferrableMemWriteReq is classified as non-posted

**Why separate:** These verify end-to-end functionality that users will rely on.

### 3. API Contract Tests (`tests/api_tests.rs`)
**Purpose:** Ensure the public API remains stable and catch breaking changes.

**Tests (50 total), organized by category:**

#### Error Type Tests (3 tests)
- Verify `TlpError` enum exists and is accessible
- Check `Debug` and `PartialEq` trait implementations
- Ensure all error variants are available

#### TlpFmt Enum Tests (3 tests)
- Verify all format variants exist
- Test `try_from` conversions for valid values
- Test `try_from` returns errors for invalid values

#### TlpType Enum Tests (3 tests)
- Verify all 21 TLP type variants exist (including `LocalTlpPrefix` and `EndToEndTlpPrefix`)
- Check `Debug` and `PartialEq` implementations

#### TlpPacket Tests (9 tests)
- Constructor existence
- `get_tlp_type()` return type and error handling
- `get_tlp_format()` existence
- `get_data()` functionality
- Validation of different packet types
- Error conditions (invalid format, invalid type)

#### TlpPacketHeader Tests (2 tests)
- Constructor existence
- `get_tlp_type()` return type

#### Trait Tests (14 tests)
- `MemRequest` trait methods and return types (3DW and 4DW), struct accessibility
- `ConfigurationRequest` trait methods and return types, struct accessibility
- `CompletionRequest` trait methods and return types, struct accessibility
- `MessageRequest` trait methods and return types, struct accessibility

#### Factory Function Tests (5 tests)
- `new_mem_req()` signature and return type
- `new_conf_req()` signature and return type
- `new_cmpl_req()` signature and return type
- `new_msg_req()` signature and return type
- `new_atomic_req()` signature and return type

#### AtomicOp / AtomicWidth / AtomicRequest Tests (7 tests)
- `AtomicOp` enum variants exist and are public
- `AtomicOp` implements `Debug` and `PartialEq`
- `AtomicWidth` enum variants exist and are public
- `AtomicWidth` implements `Debug` and `PartialEq`
- `new_atomic_req` returns error for non-atomic TLP type
- `new_atomic_req` returns error for no-data format combination
- `new_atomic_req` returns error for short payload

#### API Stability Test (1 test)
- Compilation test ensuring all public types remain available
- Will fail to compile if any public API is removed or renamed

#### Edge Case Tests (3 tests)
- Minimum packet size handling
- Empty data section handling
- Data payload preservation

**Why separate:** These tests serve as a living contract specification. If any test fails, it indicates a breaking API change that will affect users.

### 4. Documentation Tests (6 tests)
**Purpose:** Ensure examples in documentation compile and run correctly.

**Location:** Embedded in doc comments throughout `src/lib.rs`

**Tests:**
- `TlpPacket` usage example
- `new_mem_req` usage example
- `new_conf_req` usage example  
- `new_cmpl_req` usage example
- `new_msg_req` usage example
- `new_atomic_req` usage example

## Test Summary

| Test Type | Location | Count | Purpose |
|-----------|----------|-------|---------|
| Unit Tests | `src/lib.rs` | 30 | Internal implementation |
| Integration Tests | `tests/tlp_tests.rs` | 16 | Functional behavior |
| API Contract Tests | `tests/api_tests.rs` | 50 | API stability |
| Doc Tests | `src/lib.rs` | 6 | Documentation examples |
| **Total** | | **102** | |

## Running Tests

```bash
# Run all tests
cargo test

# Run specific test file
cargo test --test api_tests
cargo test --test tlp_tests

# Run unit tests only
cargo test --lib

# Run doc tests only
cargo test --doc

# Run with output
cargo test -- --nocapture
```

## Benefits of This Structure

1. **Breaking Change Detection:** API tests will fail if the public interface changes
2. **Clear Separation:** Unit tests focus on internals, integration tests on behavior
3. **Documentation:** Tests serve as usage examples for the API
4. **Confidence:** Comprehensive coverage means safe refactoring
5. **Gen6 Preparation:** Clean structure ready for adding Gen6-specific tests

## Future Work

When adding Gen6 packet parsing support:
- Add Gen6-specific tests to `tests/tlp_tests.rs`
- Add Gen6 API contracts to `tests/api_tests.rs`
- Update this document with new test counts
