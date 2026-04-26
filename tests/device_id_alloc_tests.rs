use std::alloc::{GlobalAlloc, Layout, System};
use std::fmt::{self, Write};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use rtlp_lib::DeviceID;

struct CountingAlloc;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

#[derive(Default)]
struct FixedBdfBuf {
    bytes: [u8; 7],
    len: usize,
}

impl FixedBdfBuf {
    fn clear(&mut self) {
        self.len = 0;
    }
}

impl Write for FixedBdfBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        if end > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[test]
fn device_id_display_hot_loop_does_not_allocate() {
    let id = DeviceID::from_parts(0xC2, 0x1F, 0x07).unwrap();
    let mut out = FixedBdfBuf::default();

    write!(&mut out, "{id}").unwrap();
    assert_eq!(&out.bytes[..out.len], b"C2:1F.7");

    ALLOCS.store(0, Ordering::Relaxed);
    for _ in 0..1_000_000 {
        out.clear();
        write!(&mut out, "{}", black_box(id)).unwrap();
        black_box(out.len);
    }

    assert_eq!(ALLOCS.load(Ordering::Relaxed), 0);
}
