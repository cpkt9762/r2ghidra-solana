.globl entrypoint
.extern sol_log_
.extern sol_set_return_data 
entrypoint:
    ldxdw r6, [r1+16]
    add64 r1, 24
    mov64 r2, 16
    call sol_log_
    stxdw [r10-8], r6
    mov64 r1, r10
    sub64 r1, 8
    mov64 r2, 8
    call sol_set_return_data
    mov64 r0, r6
    exit
