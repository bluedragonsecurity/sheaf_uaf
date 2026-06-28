#!/usr/bin/env python3
# dragon_sheafwatch.py - SheafJack pcs->main inspector (KASLR-aware)

import gdb
import re
import time

OFF_SHEAF_SIZE    = 0x18
OFF_SHEAF_OBJECTS = 0x20

KASLR_SLIDE = 0
_last_snap = {}

def u64(addr):
    return int(gdb.parse_and_eval(f"*(unsigned long *)0x{addr:x}")) & ((1<<64)-1)

def u32(addr):
    return int(gdb.parse_and_eval(f"*(unsigned int *)0x{addr:x}")) & 0xffffffff

def sym(name):
    s = int(gdb.parse_and_eval(f"(unsigned long)&{name}"))
    return (s + KASLR_SLIDE) & ((1<<64)-1)

def detect_kaslr_via_lstar():
    global KASLR_SLIDE
    try:
        out = gdb.execute("monitor info registers", to_string=True)
    except gdb.error as e:
        print(f"[!] monitor info registers failed: {e}")
        return False
    m = re.search(r"LSTAR\s*=\s*([0-9a-fA-F]+)", out)
    if not m:
        print("[!] LSTAR not found in monitor output.")
        return False
    lstar = int(m.group(1), 16)
    try:
        sym_entry = int(gdb.parse_and_eval("(unsigned long)&entry_SYSCALL_64"))
    except gdb.error:
        print("[!] symbol entry_SYSCALL_64 missing in vmlinux.")
        return False
    KASLR_SLIDE = (lstar - sym_entry) & ((1<<64)-1)
    print(f"[dragon] LSTAR             = 0x{lstar:x}")
    print(f"[dragon] &entry_SYSCALL_64 = 0x{sym_entry:x}")
    print(f"[dragon] KASLR slide       = 0x{KASLR_SLIDE:x}")
    return True

class KaslrAuto(gdb.Command):
    """kaslr - auto-detect KASLR slide via MSR_LSTAR"""
    def __init__(self): super().__init__("kaslr", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        detect_kaslr_via_lstar()

class KaslrFromText(gdb.Command):
    """kaslr_text <runtime_text_hex> - set slide from runtime _text address"""
    def __init__(self): super().__init__("kaslr_text", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        global KASLR_SLIDE
        a = arg.split()
        if len(a) != 1:
            print(self.__doc__); return
        runtime_text  = int(a[0], 16)
        linktime_text = int(gdb.parse_and_eval("(unsigned long)&_text"))
        KASLR_SLIDE = (runtime_text - linktime_text) & ((1<<64)-1)
        print(f"[dragon] _text link-time = 0x{linktime_text:x}")
        print(f"[dragon] _text runtime   = 0x{runtime_text:x}")
        print(f"[dragon] KASLR slide     = 0x{KASLR_SLIDE:x}")

class KaslrSet(gdb.Command):
    """kaslr_set <slide_hex> - set slide manually"""
    def __init__(self): super().__init__("kaslr_set", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        global KASLR_SLIDE
        a = arg.split()
        if len(a) != 1:
            print(self.__doc__); return
        KASLR_SLIDE = int(a[0], 16)
        print(f"[dragon] KASLR slide     = 0x{KASLR_SLIDE:x}")

KaslrAuto()
KaslrFromText()
KaslrSet()

def find_cache(name):
    if KASLR_SLIDE == 0:
        print("[!] KASLR_SLIDE=0. Run 'kaslr_text <hex>' or 'kaslr' first.")
        return None
    head_addr = sym("slab_caches")
    kc_t = gdb.lookup_type("struct kmem_cache")
    off_list = int(gdb.parse_and_eval("(unsigned long)&((struct kmem_cache *)0)->list"))
    try:
        nxt = u64(head_addr)
    except gdb.MemoryError:
        print(f"[!] Cannot read slab_caches @ 0x{head_addr:x}. Bad slide?")
        return None
    walked = 0
    while nxt != head_addr and walked < 4096:
        cache_addr = nxt - off_list
        cache = gdb.Value(cache_addr).cast(kc_t.pointer())
        try:
            cname = cache['name'].string()
        except (gdb.MemoryError, gdb.error):
            cname = ""
        if cname == name:
            return cache
        try:
            nxt = u64(nxt)
        except gdb.MemoryError:
            print(f"[!] List corruption / bad slide @ 0x{nxt:x}")
            return None
        walked += 1
    return None

def get_pcs_main(cache, cpu):
    cpu_sheaves_ptr = int(cache['cpu_sheaves'])
    pcpu_arr  = sym("__per_cpu_offset")
    pcpu_off  = u64(pcpu_arr + cpu*8)
    pcs_addr  = (cpu_sheaves_ptr + pcpu_off) & ((1<<64)-1)
    try:
        pcs_t = gdb.lookup_type("struct slub_percpu_sheaves")
        pcs   = gdb.Value(pcs_addr).cast(pcs_t.pointer())
        main  = int(pcs['main'])
    except gdb.error:
        main = u64(pcs_addr + 0x08)
    return pcs_addr, main

def dump_sheaf(sheaf_addr):
    if sheaf_addr == 0:
        return None, []
    size = u32(sheaf_addr + OFF_SHEAF_SIZE)
    if size > 64:
        print(f"[!] suspicious size={size}, refusing to dump")
        return size, []
    objs = []
    base = sheaf_addr + OFF_SHEAF_OBJECTS
    for i in range(size):
        try:
            objs.append(u64(base + i*8))
        except gdb.MemoryError:
            objs.append(0xDEADBEEFDEADBEEF)
    return size, objs

def peek_obj(addr, nqw=2):
    out = []
    for i in range(nqw):
        try:
            out.append(f"{u64(addr+i*8):016x}")
        except gdb.MemoryError:
            out.append("xxxxxxxxxxxxxxxx")
    return " ".join(out)

def snapshot(cache_name, cpu, verbose=True):
    cache = find_cache(cache_name)
    if cache is None:
        print(f"[!] cache '{cache_name}' not found in slab_caches")
        return None
    cache_addr = int(cache)
    obj_size   = int(cache['object_size'])
    real_size  = int(cache['size'])
    sheaf_cap  = int(cache['sheaf_capacity'])
    pcs_addr, main = get_pcs_main(cache, cpu)
    size, objs = dump_sheaf(main)

    if verbose:
        print(f"\n[dragon] cache={cache_name} @ 0x{cache_addr:x}")
        print(f"         object_size={obj_size}  size={real_size}  sheaf_capacity={sheaf_cap}")
        print(f"         cpu={cpu}  pcs @ 0x{pcs_addr:x}  main @ 0x{main:x}")
        if main == 0:
            print("         pcs->main = NULL")
        else:
            print(f"         main->size = {size}   (LIFO top = objects[{(size-1) if size else 0}])")
            print(f"         +---- pcs->main->objects[] ----")
            for i, o in enumerate(objs):
                tag  = " <-- TOP (next alloc)" if i == size-1 else ""
                head = peek_obj(o, 2) if o else "(null)"
                print(f"         | [{i:02d}] 0x{o:016x}  | {head}{tag}")
            print(f"         +------------------------------")
    return objs

class SheafWatch(gdb.Command):
    """sheafwatch <cache_name> [cpu] [iters] [interval_sec]"""
    def __init__(self): super().__init__("sheafwatch", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        if KASLR_SLIDE == 0:
            print("[!] Set slide first: 'kaslr_text <hex>' or 'kaslr'.")
            return
        a = arg.split()
        if len(a) < 1:
            print(self.__doc__); return
        cache_name = a[0]
        cpu        = int(a[1])   if len(a) > 1 else 0
        iters      = int(a[2])   if len(a) > 2 else 1
        interval   = float(a[3]) if len(a) > 3 else 0.5
        for k in range(iters):
            if k > 0:
                gdb.execute("continue &", to_string=True)
                time.sleep(interval)
                gdb.execute("interrupt", to_string=True)
                time.sleep(0.05)
            print(f"\n========== iter {k+1}/{iters} ==========")
            objs = snapshot(cache_name, cpu, verbose=True)
            _last_snap[(cache_name, cpu)] = objs or []

class SheafDiff(gdb.Command):
    """sheafdiff <cache_name> [cpu]"""
    def __init__(self): super().__init__("sheafdiff", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        if KASLR_SLIDE == 0:
            print("[!] Set slide first: 'kaslr_text <hex>' or 'kaslr'.")
            return
        a = arg.split()
        if len(a) < 1:
            print(self.__doc__); return
        cache_name = a[0]
        cpu = int(a[1]) if len(a) > 1 else 0
        prev = set(_last_snap.get((cache_name, cpu), []))
        cur_list = snapshot(cache_name, cpu, verbose=True) or []
        cur = set(cur_list)
        added   = cur - prev
        removed = prev - cur
        print(f"\n[diff] +{len(added)} freed-into-sheaf   -{len(removed)} popped/flushed")
        for o in sorted(added):
            print(f"   + 0x{o:016x}")
        for o in sorted(removed):
            print(f"   - 0x{o:016x}")
        _last_snap[(cache_name, cpu)] = cur_list

SheafWatch()
SheafDiff()
class SheafList(gdb.Command):
    """sheaflist [filter_substring] - list all caches with object_size and sheaf_capacity"""
    def __init__(self): super().__init__("sheaflist", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        if KASLR_SLIDE == 0:
            print("[!] Set slide first: 'kaslr_text <hex>' or 'kaslr'.")
            return
        a = arg.split()
        flt = a[0] if a else ""
        head_addr = sym("slab_caches")
        kc_t = gdb.lookup_type("struct kmem_cache")
        off_list = int(gdb.parse_and_eval("(unsigned long)&((struct kmem_cache *)0)->list"))
        try:
            nxt = u64(head_addr)
        except gdb.MemoryError:
            print(f"[!] Cannot read slab_caches @ 0x{head_addr:x}")
            return
        print(f"{'NAME':<40} {'obj_sz':>7} {'size':>7} {'cap':>4}")
        print("-" * 62)
        count = 0; matched = 0
        while nxt != head_addr and count < 4096:
            cache_addr = nxt - off_list
            cache = gdb.Value(cache_addr).cast(kc_t.pointer())
            try:
                cname = cache['name'].string()
                osz   = int(cache['object_size'])
                sz    = int(cache['size'])
                cap   = int(cache['sheaf_capacity'])
            except (gdb.MemoryError, gdb.error):
                cname, osz, sz, cap = "?", 0, 0, 0
            if not flt or flt in cname:
                print(f"{cname:<40} {osz:>7} {sz:>7} {cap:>4}")
                matched += 1
            try:
                nxt = u64(nxt)
            except gdb.MemoryError:
                print(f"[!] List corruption @ 0x{nxt:x}")
                return
            count += 1
        print("-" * 62)
        print(f"[dragon] {count} caches walked, {matched} matched filter '{flt}'")

SheafList()
print("[dragon] loaded. commands: kaslr, kaslr_text, kaslr_set, sheaflist, sheafwatch, sheafdiff")
