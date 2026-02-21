.globl entrypoint
entrypoint:
    add64 r10, -64
    ldxdw r6, [r1+16]
    add64 r1, 24
    mov64 r2, 16
    syscall 544561597
    stxdw [r10+56], r6
    mov64 r1, r10
    add64 r1, 56
    mov64 r2, 8
    syscall 2720453611
    mov64 r0, r6
    add64 r10, 64
    return
