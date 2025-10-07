from pwn import *

nc = "nc numbers.p2.securinets.tn 7011"
r = remote("numbers.p2.securinets.tn", 7011)

r.recvlines(2)
for i in range(1, 111):
    print(i)
    if i % 10 == 9:
        continue
    r.recvuntil(b":")
    r.sendline(str(i).encode())
    r.recvuntil(b":")
    r.sendline((str(i) + "9").encode())

r.interactive()