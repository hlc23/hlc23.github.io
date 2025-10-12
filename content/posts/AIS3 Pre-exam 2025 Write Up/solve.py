from math import isqrt
from hashlib import sha512
from mt19937predictor import MT19937Predictor

enum_urandom = [bytes([i]) for i in range(256)] # 256 possible values
sha512_hashes = [sha512(v).digest() for v in enum_urandom]

with open('output.txt', 'r') as f:
    lines = f.readlines()

predictor = MT19937Predictor()

for i in range(80):
    for e, h in enumerate(sha512_hashes):
        hash_byte = int.from_bytes(h)
        xor_value = int(lines[i].strip(), 16) ^ hash_byte
        
        root = isqrt(xor_value)
        if root * root == xor_value:
            predictor.setrandbits(root, 256)
            print(f"Recovered state for line {i}: {e:02x} (xor value: {xor_value:02x})")
            break


flag = int(lines[80].strip(), 16)
flag = flag ^ (predictor.getrandbits(256)**2)

byte_length = (flag.bit_length() + 7) // 8
bytes_result = flag.to_bytes(byte_length, 'big')
print(f"Recovered flag: {bytes_result}")