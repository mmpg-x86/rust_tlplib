# Test Organization

This document describes the test structure for the rtlp-lib crate.

## Test Files

### 1. Unit Tests (`src/lib.rs`)
**Purpose:** Test internal implementation details not exposed in the public API.

**Location:** `#[cfg(test)] mod tests` inside `src/lib.rs`

**Tests (6 total):**
- `tlp_header_type` - Tests internal `TlpHeader` type detection
- `tlp_header_works_all_zeros` - Tests bitfield parsing with zero values
- `tlp_header_works_all_ones` - Tests bitfield parsing with all bits set
- `test_invalid_format_error` - Tests error handling for invalid format values
- `test_invalid_type_error` - Tests error handling for invalid type encoding
- `test_unsupported_combination_error` - Tests error handling for unsupported format/type combinations

**Why separate:** These tests use `TlpHeader` which is an internal implementation detail, not part of the public API.

### 2. Integration Tests (`tests/tlp_tests.rs`)
**Purpose:** Test the library's functional behavior through its public API.

**Tests (8 total):**
- `test_tlp_packet` - Basic TLP packet parsing
- `test_complreq_trait` - Completion request trait functionality
- `test_configreq_trait` - Configuration request trait functionality
- `is_memreq_tag_works` - Memory request tag extraction (3DW and 4DW)
- `is_memreq_3dw_address_works` - 32-bit address parsing
- `is_memreq_4dw_address_works` - 64-bit address parsing
- `is_tlppacket_creates` - TlpPacketHeader creation
- `test_tlp_packet_invalid_type` - Error propagation through TlpPacket API

**Why separate:** These verify end-to-end functionality that users will rely on.

### 3. API Contract Tests (`tests/api_tests.rs`)
**Purpose:** Ensure the public API remains stable and catch breaking changes.

**Tests (42 total), organized by category:**

#### Error Type Tests (3 tests)
- Verify `TlpError` enum exists and is accessible
- Check `Debug` and `PartialEq` trait implementations
- Ensure all error variants are available

#### TlpFmt Enum Tests (3 tests)
- Verify all format variants exist
- Test `try_from` conversions for valid values
- Test `try_from` returns errors for invalid values

#### TlpType Enum Tests (3 tests)
- Verify all 20 TLP type variants exist
- Check `Debug` and `PartialEq` implementations

#### TlpPacket Tests (10 tests)
- Constructor existence
- `get_tlp_type()` return type and error handling
- `get_tlp_format()` existence
- `get_data()` functionality
- Validation of different packet types
- Error conditions (invalid format, invalid type)

#### TlpPacketHeader Tests (2 tests)
- Constructor existence
- `get_tlp_type()` return type

#### Trait Tests (12 tests)
- `MemRequest` trait methods and return types (3DW and 4DW)
- `ConfigurationRequest` trait methods and return types
- `CompletionRequest` trait methods and return types
- `MessageRequest` trait methods and return types
- Struct accessibility tests

#### Factory Function Tests (4 tests)
- `new_mem_req()` signature and return type
- `new_conf_req()` signature and return type
- `new_cmpl_req()` signature and return type
- `new_msg_req()` signature and return type

#### API Stability Test (1 test)
- Compilation test ensuring all public types remain available
- Will fail to compile if any public API is removed or renamed

#### Edge Case Tests (3 tests)
- Minimum packet size handling
- Empty data section handling
- Data payload preservation

**Why separate:** These tests serve as a living contract specification. If any test fails, it indicates a breaking API change that will affect users.

### 4. Documentation Tests (5 tests)
**Purpose:** Ensure examples in documentation compile and run correctly.

**Location:** Embedded in doc comments throughout `src/lib.rs`

**Tests:**
- `TlpPacket` usage example
- `new_mem_req` usage example
- `new_conf_req` usage example  
- `new_cmpl_req` usage example
- `new_msg_req` usage example

## Test Summary

| Test Type | Location | Count | Purpose |
|-----------|----------|-------|---------|
| Unit Tests | `src/lib.rs` | 6 | Internal implementation |
| Integration Tests | `tests/tlp_tests.rs` | 8 | Functional behavior |
| API Contract Tests | `tests/api_tests.rs` | 42 | API stability |
| Doc Tests | `src/lib.rs` | 5 | Documentation examples |
| **Total** | | **61** | |

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
