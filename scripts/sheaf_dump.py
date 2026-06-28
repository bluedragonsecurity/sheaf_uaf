#!/usr/bin/env drgn
# Usage: sudo drgn sheaf_dump.py [cache_name] [delay_sec] [bytes_per_obj]
# Default: kmalloc-256, 1.0s, 32 bytes per object preview

import sys
import time
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.slab import find_slab_cache

CACHE  = sys.argv[1] if len(sys.argv) > 1 else "kmalloc-256"
DELAY  = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
NBYTES = int(sys.argv[3]) if len(sys.argv) > 3 else 32

def dump_sheaf(cpu, label, sheaf):
    if not sheaf:
        print(f"  CPU{cpu} {label:5s} : NULL")
        return
    addr = sheaf.value_()
    size = int(sheaf.size)
    cap  = int(sheaf.cache.sheaf_capacity) if sheaf.cache else 0
    print(f"  CPU{cpu} {label:5s} @ 0x{addr:x}  size={size}/{cap}")
    for i in range(size):
        try:
            slot = int(sheaf.objects[i])
        except Exception as e:
            print(f"   [{i:2d}] <objects[i] err: {e}>")
            continue
        if slot == 0:
            print(f"   [{i:2d}] NULL")
            continue
        try:
            data = prog.read(slot, NBYTES)
            hexs = " ".join(f"{b:02x}" for b in data)
            print(f"   [{i:2d}] 0x{slot:016x}: {hexs}")
        except Exception:
            print(f"   [{i:2d}] 0x{slot:016x}: <unreadable>")

def main():
    s = find_slab_cache(prog, CACHE)
    if not s:
        sys.exit(f"cache {CACHE!r} not found")
    if not s.cpu_sheaves:
        sys.exit(f"cache {CACHE!r}: cpu_sheaves is NULL (sheaf_capacity=0, e.g. SLAB_TYPESAFE_BY_RCU)")
    pcs = s.cpu_sheaves
    obj_size = int(s.size)
    it = 0
    while True:
        print(f"\nt={time.time():.6f}  iter={it}  cache={CACHE}  obj_size={obj_size}")
        for cpu in for_each_online_cpu(prog):
            cs = per_cpu_ptr(pcs, cpu)
            dump_sheaf(cpu, "main",  cs.main)
            dump_sheaf(cpu, "spare", cs.spare)
            dump_sheaf(cpu, "rcuf",  cs.rcu_free)
        it += 1
        sys.stdout.flush()
        time.sleep(DELAY)

try:
    main()
except KeyboardInterrupt:
    pass
