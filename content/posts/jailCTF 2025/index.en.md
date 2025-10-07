---
title: "JailCTF 2025"
date: 2025-10-05T21:54:07+08:00
draft: false # Set 'false' to publish
tableOfContents: false # Enable/disable Table of Contents
description: ''
categories:
  - CTF
tags:
  - Write Up
---

## pyjail
### blindness

source code:
```python
import sys
inp = input('blindness > ')
sys.stdout.close()
flag = open('flag.txt').read()
eval(inp, {'__builtins__': {}, 'flag': flag})
print('bye bye')
```

Simply put, there is no direct echo and no built-in jail.
The flag can be accessed directly, but without stdout, it cannot be printed out.
You can trigger an Exception to make the flag appear in stderr.

payload:
```python
().__getattribute__(flag)
```

Flag: `jail{stderr_leak_5fd787f079eb69e}`

--- 

# END

Huh? You ask why there’s only one challenge I solved?  
Go check out [Securinets-CTF-2025](../securinets-ctf-2025/) instead.