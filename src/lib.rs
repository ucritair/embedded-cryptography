#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc;
//use cortex_m_rt::entry;
use embedded_alloc::LlffHeap as Heap;

// griffon
// adding a GPIO so we can show error state from the rust code (LED)
use rp235x_hal as _;

use embedded_hal::digital::{OutputPin};
use rp235x_hal::{
    self as hal, gpio::Pins, Sio,
};


pub mod aes_ctr;
pub mod tfhe;

#[cfg(any(feature = "std", feature = "alloc"))]
pub mod zkp;

pub mod poly;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;


fn gpio_init()
{
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let sio = Sio::new(pac.SIO);
    let pins = rp235x_hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    // Set a pin to drive output
    let mut output_pin = pins.gpio23.into_push_pull_output();

    output_pin.set_high().unwrap();
}



// Minimal panic handler for no_std when building as a static library for FFI.
// The test configuration links std, so this is disabled under tests.
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    // set board LED to indicate we entered the rust panic_handler
    gpio_init();
    loop {}
}

// Provide a no-op personality function to satisfy linkers when building staticlib
// with panic=abort on some Apple targets.
#[cfg(not(feature = "std"))]
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

// Provide a minimal global allocator so `alloc` types (Vec, Box, etc.) work in no_std.
// This is intentionally simple and can be replaced by integrators if needed.
//
// griffon: use embedded-alloc here instead of dlmalloc
#[cfg(all(not(feature = "std"), feature = "alloc"))]
#[global_allocator]
static ALLOC: Heap = Heap::empty();


#[unsafe(no_mangle)]
pub extern "C" fn rust_heap_used() -> u32 {
    return ALLOC.used() as u32;
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_heap_free() -> u32 {
    return ALLOC.free() as u32;
}

// griffon
// -- FIXME: reduce the heap size, it currently overlaps the stack at top of memory!!!
// -- FIXME: change this to allow the C side to set the heap base address and size !!!
//
// PSRAM_BASE_ADDRESS   0x11000000
// PSRAM_SIZE_BYTES (8 * 1024 * 1024) = 8388608
#[unsafe(no_mangle)]
pub extern "C" fn rust_heap_init(
    heap_start_addr: usize,
    heap_size: usize,
    ) {
    //gpio_init();
    unsafe {
        ALLOC.init(heap_start_addr, heap_size);
    }


    let mut testvec: Vec<u8> = alloc::vec![];
    testvec.push(0x42);
    testvec.push(0x00);
    testvec.push(0x11);
    testvec.push(0x22);
    testvec.push(0x33);
    testvec.push(0x44);
    testvec.push(0x55);
    testvec.push(0x66);
    testvec.push(0x77);
    testvec.push(0x88);
    testvec.push(0x99);
    testvec.push(0xAA);
    testvec.push(0xBB);
    testvec.push(0xCC);
    testvec.push(0xDD);
    testvec.push(0xEE);
    testvec.push(0xFF);

    // do not optimize
    core::hint::black_box(&mut testvec);

    assert_eq!(testvec.len(), 17);

    //assert_eq!(testvec.as_slice(), &[1, 2, 3, 4]);
    assert_eq!(testvec, [0x42, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
}

//#[global_allocator]
//static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;
