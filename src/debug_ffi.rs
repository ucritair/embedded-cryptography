// --- debug puts() interface to the C pico-sdk ---

unsafe extern "C" {
    fn puts(s: *const u8) -> i32;
}       
        
pub fn dbg_puts(s: &str) {
    let c_string = cstr_core::CString::new(s).unwrap();
    unsafe {
        puts(c_string.as_ptr());
    }
}

