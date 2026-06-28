#!/usr/bin/env drgn
from drgn.helpers.linux import for_each_slab_cache
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.cpumask import for_each_online_cpu

interesting = ['vm_area_struct', 'maple_node', 'filp']

for cache in for_each_slab_cache(prog):
    name = cache.name.string_().decode()
    if name not in interesting:
        continue
    cap = int(cache.sheaf_capacity)
    print(f'\n=== {name} (sheaf_capacity={cap}) ===')

    # Per-CPU sheaves
    for cpu in for_each_online_cpu(prog):
        pcs = per_cpu_ptr(cache.cpu_sheaves, cpu)
        main = pcs.main
        spare = pcs.spare
        rcu_free = pcs.rcu_free
        print(f'  cpu{int(cpu)}:')
        if main:
            print(f' main  @ {hex(main.value_())}  size={int(main.size)}/{cap}')
        if spare:
            print(f' spare @ {hex(spare.value_())}  size={int(spare.size)}/{cap}')
        if rcu_free:
            print(f' rcu_free @ {hex(rcu_free.value_())}  size={int(rcu_free.size)}/{cap}')

    # Barn (NUMA-shared)
    for nid in range(int(prog['nr_node_ids'])):
        n = cache.node[nid]
        if not n.barn:
            continue
        barn = n.barn
        full = int(barn.nr_full)
        empty = int(barn.nr_empty)
        print(f'  node[{nid}].barn @ {hex(barn.value_())} full={full}/10  empty={empty}/10')
