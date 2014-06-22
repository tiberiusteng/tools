#!/usr/bin/env python2
# ported from http://cuddletech.com/arc_summary.html

import pprint
import re

## spl slab usage

spl_size  = 0
spl_alloc = 0

for l in open('/proc/spl/kmem/slab', 'rb').readlines()[2:]:
  f = re.split(r'\s+', l)
  spl_size += int(f[2])
  spl_alloc += int(f[3])

## arc

a = {i[0]: long(i[2]) for i in [line.strip().split() for line in open('/proc/spl/kstat/zfs/arcstats', 'rb').read().strip().split('\n')[2:]]}

arc_size = a['size']
mru_size = a['p']
target_size = a['c']
arc_min_size = a['c_min']
arc_max_size = a['c_max']

print 'ARC Size:'
print '    Current Size:            {0:9,.0f} MB (arcsize)'.format(arc_size / 1024.0 / 1024.0)
print '    Target Size (Adaptive):  {0:9,.0f} MB (c)'.format(target_size / 1024.0 / 1024.0)
print '    Min Size (Hard Limit):   {0:9,.0f} MB (zfs_arc_min)'.format(arc_min_size / 1024.0 / 1024.0)
print '    Max Size (Hard Limit):   {0:9,.0f} MB (zfs_arc_max)'.format(arc_max_size / 1024.0 / 1024.0)
print
print 'SPL Memory Usage:'
print '    SPL slab allocated:      {0:9,.0f} MB'.format(spl_size / 1024.0 / 1024.0)
print '    SPL slab used:           {0:9,.0f} MB'.format(spl_alloc / 1024.0 / 1024.0)
print

mfu_size = arc_size - mru_size
mru_perc = 100*(mru_size / float(target_size))
mfu_perc = 100*(mfu_size / float(target_size))

print 'ARC Size Breakdown:'
print '    Most Recently Used Cache Size:    {0:2.0f} %  {1:9,.0f} MB (p)'.format(mru_perc, mru_size / 1024.0 / 1024.0)
print '    Most Frequently Used Cache Size:  {0:2.0f} %  {1:9,.0f} MB (c-p)'.format(mfu_perc, mfu_size / 1024.0 / 1024.0)
print

arc_hits   = a['hits']
arc_misses = a['misses']
arc_accesses_total = arc_hits + arc_misses

arc_hit_perc  = 100*(arc_hits   / float(arc_accesses_total))
arc_miss_perc = 100*(arc_misses / float(arc_accesses_total))

mfu_hits = a['mfu_hits']
mru_hits = a['mru_hits']
mfu_ghost_hits = a['mfu_ghost_hits']
mru_ghost_hits = a['mru_ghost_hits']
anon_hits = arc_hits - (mfu_hits + mru_hits + mfu_ghost_hits + mru_ghost_hits)

real_hits = mfu_hits + mru_hits
real_hits_perc = 100*(real_hits / float(arc_accesses_total))

anon_hits_perc = 100*(anon_hits / float(arc_hits))
mfu_hits_perc  = 100*(mfu_hits  / float(arc_hits))
mru_hits_perc  = 100*(mru_hits  / float(arc_hits))
mfu_ghost_hits_perc = 100*(mfu_ghost_hits / float(arc_hits))
mru_ghost_hits_perc = 100*(mru_ghost_hits / float(arc_hits))

demand_data_hits = a['demand_data_hits']
demand_metadata_hits = a['demand_metadata_hits']
prefetch_data_hits = a['prefetch_data_hits']
prefetch_metadata_hits = a['prefetch_metadata_hits']

demand_data_hits_perc = 100*(demand_data_hits / float(arc_hits))
demand_metadata_hits_perc = 100*(demand_metadata_hits / float(arc_hits))
prefetch_data_hits_perc = 100*(prefetch_data_hits / float(arc_hits))
prefetch_metadata_hits_perc = 100*(prefetch_metadata_hits / float(arc_hits))

demand_data_misses = a['demand_data_misses']
demand_metadata_misses = a['demand_metadata_misses']
prefetch_data_misses = a['prefetch_data_misses']
prefetch_metadata_misses = a['prefetch_metadata_misses']

demand_data_misses_perc = 100*(demand_data_misses / float(arc_misses))
demand_metadata_misses_perc = 100*(demand_metadata_misses / float(arc_misses))
prefetch_data_misses_perc = 100*(prefetch_data_misses / float(arc_misses))
prefetch_metadata_misses_perc = 100*(prefetch_metadata_misses / float(arc_misses))

prefetch_data_total = prefetch_data_hits + prefetch_data_misses

prefetch_data_perc = 0
if prefetch_data_total > 0:
    prefetch_data_perc = 100*(prefetch_data_hits / float(prefetch_data_total))

demand_data_total = demand_data_hits + demand_data_misses
demand_data_perc = 100*(demand_data_hits / float(demand_data_total))

print 'ARC Efficency:'
print '    Cache Access Total:                  {0:14,d}'.format(arc_accesses_total)
print '    Cache Hit Ratio:               {0:2.0f} %  {1:14,d}  [Defined State for Buffer]'.format(arc_hit_perc, arc_hits)
print '    Cache Miss Ratio:              {0:2.0f} %  {1:14,d}  [Undefined State for Buffer]'.format(arc_miss_perc, arc_misses)
print '    REAL Hit Ratio:                {0:2.0f} %  {1:14,d}  [MRU/MFU Hits Only]'.format(real_hits_perc, real_hits)
print
print '    Data Demand Efficiency:        {0:2.0f} %'.format(demand_data_perc)
if prefetch_data_total == 0:
    print '    Data Prefetch Efficiency:      DISABLED (zfs_prefetch_disable)'
else:
    print '    Data Prefetch Efficiency:      {0:2.0f} %'.format(prefetch_data_perc)
print

print '    CACHE HITS BY CACHE LIST:'
if anon_hits < 1:
    print '      Anon:                           -- % Counter Rolled.'
else:
    print '      Anon:                        {0:2.0f} %  {1:14,d}              [New Customer, First Cache Hit]'.format(anon_hits_perc, anon_hits)
print '      Most Recently Used:          {0:2.0f} %  {1:14,d} (mru)        [Return Customer]'.format(mru_hits_perc, mru_hits)
print '      Most Frequently Used:        {0:2.0f} %  {1:14,d} (mfu)        [Frequent Customer]'.format(mfu_hits_perc, mfu_hits)
print '      Most Recently Used Ghost:    {0:2.0f} %  {1:14,d} (mru_ghost)  [Return Customer Evicted, Now Back]'.format(mru_ghost_hits_perc, mru_ghost_hits)
print '      Most Frequently Used Ghost:  {0:2.0f} %  {1:14,d} (mfu_ghost)  [Frequent Customer Evicted, Now Back]'.format(mfu_ghost_hits_perc, mfu_ghost_hits)
print

print '    CACHE HITS BY DATA TYPE:'
print '      Demand Data:                 {0:2.0f} %  {1:14,d}'.format(demand_data_hits_perc, demand_data_hits)
print '      Prefetch Data:               {0:2.0f} %  {1:14,d}'.format(prefetch_data_hits_perc, prefetch_data_hits)
print '      Demand Metadata              {0:2.0f} %  {1:14,d}'.format(demand_metadata_hits_perc, demand_metadata_hits)
print '      Prefetch Metadata:           {0:2.0f} %  {1:14,d}'.format(prefetch_metadata_hits_perc, prefetch_metadata_hits)
print

print '    CACHE MISSES BY DATA TYPE:'
print '      Demand Data:                 {0:2.0f} %  {1:14,d}'.format(demand_data_misses_perc, demand_data_misses)
print '      Prefetch Data:               {0:2.0f} %  {1:14,d}'.format(prefetch_data_misses_perc, prefetch_data_misses)
print '      Demand Metadata              {0:2.0f} %  {1:14,d}'.format(demand_metadata_misses_perc, demand_metadata_misses)
print '      Prefetch Metadata:           {0:2.0f} %  {1:14,d}'.format(prefetch_metadata_misses_perc, prefetch_metadata_misses)
print

# vim:et
