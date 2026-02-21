use solana_program::{
    log::{sol_log, sol_log_64, sol_log_compute_units},
    program::set_return_data,
    pubkey::Pubkey,
    syscalls::sol_log_pubkey,
};

#[no_mangle]
pub extern "C" fn entrypoint(_input: *const u8) -> u64 {
    sol_log("Hello from native runner!");
    sol_log_64(1, 2, 3, 4, 5);
    sol_log_compute_units();

    let program_id = Pubkey::new_from_array([0u8; 32]);
    let seed = b"hello";

    let (pda_found, bump) = Pubkey::find_program_address(&[seed], &program_id);

    let pda_created = Pubkey::create_program_address(&[seed, &[bump]], &program_id)
        .expect("Failed to create program address");

    if pda_found != pda_created {
        sol_log("ERROR: PDA mismatch!");
        return 1;
    }

    unsafe { sol_log_pubkey(pda_found.as_ref().as_ptr()) };
    set_return_data(&pda_found.to_bytes()[..8]);

    0
}
