import string
import random
from pwn import *

def guess_mapping(mapping):
    shift_table = [-1, 1]
    r = random.randint(0, 1)
    shift = shift_table[r]
    new_mapping = {}
    for c, v in mapping.items():
        v = ord(v) + shift_table[shift]
        if v < ord('a'):
            v += 26
        elif v > ord('z'):
            v -= 26
        new_mapping[c] = chr(v)
    return new_mapping

def encode(s, mapping):
    return "".join(mapping[c] if c in mapping else c for c in s)

def find_input_for_output(target_output, mapping):
    reverse_mapping = {v: k for k, v in mapping.items()}
    return "".join(reverse_mapping[c] if c in reverse_mapping else c for c in target_output)

r = remote("misc-b6c94dd8.p1.securinets.tn", 7000)
# get initial mapping
r.recvline()
def find_mapping():
    r.sendline(b"abcdefghijklmnopqrstuvwxyz")
    r.recvline() # echo
    res = r.recvline().strip().decode() # mapping
    mapping = {k: v for k, v in zip(string.ascii_lowercase, res)}
    return mapping

flag = ""

_0 = "[[]]<[]"
_1 = "([[]]>[])"
_2 = f"{_1}+{_1}"
_3 = f"{_2}+{_1}"
_4 = f"{_1}<<{_1}<<{_1}"
_5 = f"({_4})+{_1}"
_6 = f"({_4})+{_2}"
_7 = f"({_4})+{_3}"
_8 = f"{_4}<<{_1}"
_9 = f"({_8})+{_1}"
_10 = f"({_8})+{_2}"
_11 = f"({_8})+{_3}"
_12 = f"({_8})+({_4})"
_13 = f"({_8})+{_5}"
_14 = f"({_8})+{_6}"
_15 = f"({_8})+{_7}"
_16 = f"{_8}<<{_1}"
_17 = f"({_16})+{_1}"
_18 = f"({_16})+{_2}"
_19 = f"({_16})+{_3}"
_20 = f"({_16})+({_4})"
_21 = f"({_16})+{_5}"
_22 = f"({_16})+{_6}"
_23 = f"({_16})+{_7}"
_24 = f"({_16})+({_8})"
_25 = f"{_24}+{_1}"
_26 = f"{_24}+{_2}"
_27 = f"{_24}+{_3}"
_28 = f"{_24}+({_4})"
_29 = f"{_24}+{_5}"
_30 = f"{_24}+{_6}"
_31 = f"{_24}+{_7}"
_32 = f"{_16}<<{_1}"

num_exprs = [_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16,
             _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29]

base = "flag["
end = "]"
gen_inp = [f"{base}{expr}{end}" for expr in num_exprs]
mapping = find_mapping()
start = 0
l = len(gen_inp)
# l = 20
try:
    end_at = 0
    for i in range(start, l+1):
        end_at = i
        inp = gen_inp[i]
        print(f"[log]: trying to get flag[{i}]")

    # while True:
    #     inp = input().strip()
        gm = guess_mapping(mapping)
        payload = find_input_for_output(inp, gm) # the encode(payload, gm) should be inp if guess is correct
        r.sendline(payload.encode())
        r.recvline() # echo
        res = r.recvline().strip().decode()
        while True:
            if "150" in res:
                raise ValueError("Input exceeds 150 characters")
            if len(res) == 1:
                # print(res, end="")
                flag += res
                break
            if "sryy" in res:
                print("[log]: failed to get the flag.")
                mapping = find_mapping()
                break
            if encode(payload, gm) == res:
                print("[log]: encoded correctly!")
                break
            else:
                # guess failed, auto resend to try again
                gm = guess_mapping(mapping)
                payload = find_input_for_output(inp, gm)
                r.sendline(payload.encode())
                r.recvline() # echo
                res = r.recvline().strip().decode()
except Exception as e:
    print(f"[log]: {e}")
print(f"[log]: stop at {end_at}, flag is {flag}")