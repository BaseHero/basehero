//! Test-only thread-local allocation accounting. No production dependency.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
pub struct Counting;
thread_local! {
    pub static BYTES: Cell<Option<usize>> = const { Cell::new(None) };
    /// While set: (live bytes since it was set, their peak). Frees of older
    /// memory lower live below zero; the peak is the most this thread held
    /// above where it started.
    pub static PEAK: Cell<Option<(isize, isize)>> = const { Cell::new(None) };
}
fn live(change: isize) {
    PEAK.with(|n| {
        if let Some((live, peak)) = n.get() {
            let live = live + change;
            n.set(Some((live, peak.max(live))));
        }
    });
}
// SAFETY: every allocation operation forwards its original pointer/layout to
// System; accounting uses only a non-allocating thread-local Cell. This crate is
// a dev-dependency, so the production crate keeps forbid(unsafe_code).
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        BYTES.with(|n| {
            if let Some(v) = n.get() {
                n.set(Some(v + layout.size()));
            }
        });
        live(layout.size() as isize);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        live(-(layout.size() as isize));
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        BYTES.with(|n| {
            if let Some(v) = n.get() {
                n.set(Some(v + size));
            }
        });
        live(size as isize - layout.size() as isize);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
