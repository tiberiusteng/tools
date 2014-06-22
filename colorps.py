#!/usr/bin/env python
# coding: utf8

from __future__ import print_function

import re
import subprocess
import sys

class Xterm256color:
  def __getattr__(self, attr):
    if not attr[1:]:
      return '\033[m'
    return '\033[38;5;%sm' % attr[1:]

def terminal_size():
  import fcntl, termios, struct
  try:
    h, w, hp, wp = struct.unpack('HHHH',
      fcntl.ioctl(0, termios.TIOCGWINSZ,
      struct.pack('HHHH', 0, 0, 0, 0)))
  except:
    return 0, 0
  return w, h

def chunks(l, n):
  if n == 0:
    yield l
  else:
    for i in range(0, len(l), n):
      yield l[i:i+n]

def mem_color(v):
  global f
  if len(v) < 4: return v
  return '{x.c32}{0}{x.c}{1}'.format(v[:-3], v[-3:], **f)

def cmd_color(v):
  global f
  
  if v[0] == '[' and v[-1] == ']':
    s = [v]
  else:
    s = re.split(r'(\s+)', v)
      
  r = []
  r.append('{x.c172}{0}{x.c}'.format(s[0], **f))
  for a in s[1:]:
    #if a[0] == '-':
    if 0:
      r.append('{x.c170}{0}{x.c}'.format(a, **f))
    else:
      r.append(a)
  return ''.join(r)

term_width, term_height = terminal_size()

# formatter argument
f = {'x': Xterm256color()}

os = subprocess.Popen(['uname'], stdout=subprocess.PIPE).stdout.read().decode('utf8').strip()

if os == 'FreeBSD':
  fields = 'pid,nlwp,tt,stat,time,pcpu,pri,ni,vsz,rss,wchan,args'
else:
  fields = 'pid,nlwp,tt,stat,time,pcpu,pri,ni,vsz,rss,wchan:25,args'

out_lines = subprocess.Popen(
  ['ps', '-axwwo', fields],
  stdout=subprocess.PIPE).stdout.read().decode('utf8').split('\n')

# calculate field width
field_name = re.split(r'\s+', out_lines[0].strip())
field_count = len(field_name)
field_max_width = [0] * field_count
field_is_num = [True] * field_count

for n, line in enumerate(out_lines):
  fields = re.split(r'\s+', line.strip(), field_count - 1)
  
  for i, v in enumerate(fields):
    field_max_width[i] = max(field_max_width[i], len(v))
    if n and not re.match(r'^[-\d:.]*$', v):
      field_is_num[i] = False
    
# print it out
for ln, line in enumerate(out_lines):
  fields = re.split(r'\s+', line.strip(), field_count - 1)
  fields_print = []

  for i, v in enumerate(fields):

    if i == field_count - 1:
      #prefix_width = sum(field_max_width[:-1]) + field_count - 1
      #remain_width = (term_width - prefix_width) if term_width else 0
      #if len(v) >= remain_width:
      #    v = ('\n' + ' ' * prefix_width).join(chunks(v, remain_width))
      if ln: v = cmd_color(v)
      fields_print.append(v)
      break 
    
    fs = '%%%s%ds' % ('' if field_is_num[i] else '-', field_max_width[i])
    v = fs % v

    if field_name[i] in ['VSZ', 'RSS']:
      v = mem_color(v)

    fields_print.append(v)
  
  print(' '.join(fields_print).encode('utf8'))
  
# vim: ts=2 sts=2 sw=2 et
