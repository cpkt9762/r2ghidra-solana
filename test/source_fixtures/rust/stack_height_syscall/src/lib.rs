use solana_program::{log::sol_log, program::set_return_data};

#[no_mangle]
pub extern "C" fn entrypoint(input: *const u8) -> u64 {
    let stack_height = unsafe { core::ptr::read_unaligned(input.add(16) as *const u64) };
    sol_log("this is rust test");
    set_return_data(&stack_height.to_le_bytes());
    stack_height
}
