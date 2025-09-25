from pwn import *

r = remote("challenge.secso.cc", 7002)

payload = b"36313634366436393665"

r.recvuntil(b"Password")
r.sendline(b"2")
r.sendline(b"admin")
r.sendline(payload)
r.interactive()