#!/usr/bin/env python3
import io, sys
p = 'drivers/gpu/arm/bifrost-r14p0-00cet0/mali_kbase_mmu.c'
s = io.open(p, encoding='utf-8').read()
old1 = "((1 << pool.order) - 1))"
new1 = "((1 << pool->order) - 1))"
old2 = ">> pool.order;"
new2 = ">> pool->order;"
if new1 in s and new2 in s and old1 not in s and old2 not in s:
    print('[skip] already fixed')
    sys.exit(0)
if old1 not in s:
    raise SystemExit('anchor1 not found')
if old2 not in s:
    raise SystemExit('anchor2 not found')
s = s.replace(old1, new1, 1)
s = s.replace(old2, new2, 1)
io.open(p, 'w', encoding='utf-8').write(s)
print('[ok] pool.order -> pool->order')