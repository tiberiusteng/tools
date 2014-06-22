#!/usr/bin/env python
# coding: utf8

import os, pprint, sys, time, re

sys.path.append('/net/srv/ftp/gb/tib/scripts')
import DNS

hexentity = re.compile(r'\\x([0-9a-f-A-F]{2})')
urlhexentity = re.compile(r'%([0-9a-fA-F]{2})')

def decode_bytes(s):
    return hexentity.sub(lambda x: chr(int(eval('0x%s' % x.group(1)))),
        urlhexentity.sub(lambda x: chr(int(eval('0x%s' % x.group(1)))), s))

class CassandraSystemLogSyntax:
    def __init__(self):
        self.pat = re.compile(
            r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(?P<milli>\d{3}) ' \
            r'(?P<prio>[a-zA-Z ]{5}) ' \
            r'(?P<thread>\[[^]]+\]) ' \
            r'(?P<file>[^:]+):(?P<line>\d+) (?P<msg>.+)$')

        self.filename_pat = re.compile(r'(/srv/cassandra/[a-zA-Z0-9_./-]+)')
        self.number_pat = re.compile(r'(?<=[\s=/(\[])([0-9.,%]+)(?=[\s=/)\]])')

        self.x = Xterm256color()

    def __call__(self, line):
        line = line.rstrip()
        m = self.pat.match(line)
        if not m: return line
        gd = m.groupdict()
        x = gd['x'] = self.x

        gd['msg'] = self.filename_pat.sub(r'{x.c80}\1{x.c}'.format(**gd), gd['msg'])
        gd['msg'] = self.number_pat.sub(r'{x.c184}\1{x.c}'.format(**gd), gd['msg'])

        line = '{x.c27}{ts}{x.c},{x.c25}{milli} {x.c40}{prio} {x.c208}{thread} {x.c178}{file}{x.c}:{x.c172}{line}{x.c} {msg}'.format(**gd)

        return line

class AccessLogSyntax:
    def __init__(self):
        self.pat = re.compile(
            r'^(?P<server>\w+: )?(?P<host>.*?) (?P<ident>.*?)( (?P<user>.*?))? (?P<ts>\[.*?\]) ' \
            r'(?P<req>\".*?\") (?P<status>.*?) (?P<size>.*?) ' \
            r'(?P<referer>\".*?\") (?P<ua>\".*?\")( (?P<dur>\d+))?$')
        
        self.pat_time = re.compile(':(\d{2}):(\d{2}):(\d{2}) ')

        self.x = Xterm256color()

    def __call__(self, line):
        m = self.pat.match(line.strip())
        if not m: return line

        gd = m.groupdict()

        tm = self.pat_time.search(gd['ts']).groups()
        gd['ts'] = '[%s:%s:%s]' % (tm[0], tm[1], tm[2])

        gd['reflen'] = len(gd['referer'])
        gd['ualen'] = len(gd['ua'])
        if not gd['server']: gd['server'] = ''

        try:
            gd['size'] = int(gd['size'])
        except:
            gd['size'] = 0

        if gd['dur']:
            gd['dur'] = '%6.3f' % (float(gd['dur']) / 1000000.0)
        else:
            gd['dur'] = '-'

        x = gd['x'] = self.x

        gd['req'] = decode_bytes(gd['req'])

        line = '{server}{host:15s} {ts} {status:3s} {size:6d} r:{reflen:3d} u:{ualen:3d} {dur} {req}'.format(**gd)

        if ' /forum' in gd['req'] and gd['size'] > 50000:
            line = x.c6 + line + x.c
        elif gd['size'] > 50000:
            line = x.c202 + line + x.c

        return line

class ErrorLogSyntax:
    def __init__(self):
        self.pat = re.compile(
            r'''
            ((?P<server>\w+):\ )?
            \[(?P<wd>\w+)\ (?P<month>\w+)\ (?P<date>\d+)\ (?P<time>[^ ]+)\ (?P<year>\d+)\]\ 
            \[(?P<level>\w+)\]\ 
            \[client\ (?P<client>.+)\]\ 
            (?P<msg>.+?)
            (,\ referer:\ (?P<referer>.+))?$
            ''', re.X)

        self.php_error_pat = re.compile(
            r'''
            ((?P<server>\w+):\ )?
            (?P<month>\w+)\ +(?P<date>\d+)\ (?P<time>[^ ]+)\ ([\w-]+)\ ([^ ]+)\ 
            (?P<msg>.+?)$
            ''', re.X)

        self.file_not_exist_pat = re.compile(
            r'(File does not exist:) '
            r'(.+)')

        self.php_err_pat = re.compile(
            r'((mod_fcgid: stderr:( PHP)?)|(FastCGI: server "/usr/local/sbin/php-fpm" stderr:( PHP)?( message:)?( PHP)?)|PHP) '
            r'(?P<msg>.+)')

        self.php_func_link_pat = re.compile(
            r' \[<a href=\'(.+)\'>(.+)</a>\]')

        self.php_first_line_pat = re.compile(
            r'(?P<level>.+?):  ((?P<func>.+?): )?(?P<desc>.+?)((, called)? in (?P<file>[^ ]+?)( on line |:)(?P<line>\d+))?( and defined in ([^ ]+?) on line (\d+))?$')

        self.php_stack_item = [
            re.compile(r'(?P<lv>\s*\d+\. )(?P<func>.+?) (?P<file>.+?):(?P<line>\d+)'),
            re.compile(r'(?P<lv>#\d+ )(?P<file>.+?)\((?P<line>\d+)\): (?P<func>.+)'),
            re.compile(r'(?P<lv>  )(?P<func>thrown in) (?P<file>.+?) on line (?P<line>\d+)'),
        ]

        self.x = Xterm256color()


        self.last_ip = ''
        self.last_time = ''
        self.last_referer = ''
        self.last_server = ''
        self.in_php_error = 0

        self.dns_format = '{0:26s} ↓{x.c208}{client:15s} {x.c178}{1}{x.c}\n'

    def __call__(self, line):
        for pat in (self.pat, self.php_error_pat):
            m = pat.match(line)
            if m: break

        if not m: return line

        gd = m.groupdict()
        gd['x'] = self.x

        # reverse lookup client
        if gd.get('client') == self.last_ip:
            gd['client'] = gd['client-dn'] = ''
        else:
            self.last_ip = gd.get('client')
            try:
                gd['client-dn'] = self.dns_format.format('', DNS.revlookup(gd['client']), **gd)
            except DNS.DNSError, e:
                gd['client-dn'] = self.dns_format.format('', '(%s)' % str(e), **gd)
            except:
                #gd['client'] = ''
                gd['client-dn'] = self.dns_format.format('', '-', **gd)

        # File does not exist 加色, 解檔名
        n = self.file_not_exist_pat.match(gd['msg'])
        if n:
            ng = list(n.groups())
            ng[1] = decode_bytes(ng[1])
            if ('robots.txt' in ng[1]) or ('favicon.ico' in ng[1]):
                return None
            gd['msg'] = '{x.c40}{0} {x.c}{1}'.format(*ng, **gd)

        # referer
        if gd.get('referer') != self.last_referer:
            self.last_referer = gd.get('referer')

            if not gd.get('referer'): gd['referer'] = '<none>'

            gd['referer'] = decode_bytes(gd['referer'])
            gd['referer'] = '{0:26s} ↓{x.c241}{referer}{x.c}\n'.format('', **gd)
        else:
            gd['referer'] = ''

        # PHP Error
        n = self.php_err_pat.match(gd['msg'])
        if n:
            ng = n.groupdict()
            gd['msg'] = ng['msg']
            gd['msg'] = self.php_func_link_pat.sub('', gd['msg'])

            # first line
            n = self.php_first_line_pat.match(gd['msg'])
            if n:
                ng = n.groupdict()
                if ng['func']:
                    ng['func'] = '{x.c184}{0}{x.c}: '.format(ng['func'], **gd)
                else:
                    ng['func'] = ''
                ng['x'] = self.x

                gd['msg'] = (
                    '{x.c203}{level}{x.c}:  '
                    '{func}{x.c183}{desc}{x.c}\n                 in {x.c80}{file}{x.c}:{x.c172}{line}{x.c}').format(**ng)
                    #'{x.c80}{file}{x.c}:{x.c172}{line}{x.c}').format(**ng)
            
            # stack trace
            for s in self.php_stack_item:
                n = s.match(gd['msg'])
                if n:
                    ng = n.groupdict()
                    ng['x'] = self.x

                    gd['msg'] = '{lv}{x.c184}{func} {x.c80}{file}{x.c}:{x.c172}{line}{x.c}'.format(**ng)

        # time
        if gd['time'] == self.last_time:
            gd['time'] = ''
        else:
            self.last_time = gd['time']

        if gd['server'] == self.last_server:
            gd['server'] = ''
        else:
            self.last_server = gd['server']

        # position help
        #                           0          5                14                 20
        #                                                     {x.c124}{level:5s}
        return '{client-dn}{referer}{server:5s} {x.c75}{time:8s} {x.c}{msg}'.format(**gd)

class Xterm256color:
    def __getattr__(self, attr):
        if not attr[1:]:
            return '\033[m'
        return '\033[38;5;%sm' % attr[1:]

if __name__ == '__main__':
    #f = file(sys.argv[1], 'r')
    #f.seek(0, os.SEEK_END)

    syntax = None

    #if (('_gamebase.log' in sys.argv[1]) or 
    #    ('_wahaha.log' in sys.argv[1]) or
    #    ('_www.log' in sys.argv[1])):
    # access log
    if len(sys.argv) > 1:
        if sys.argv[1] == 'access':
            syntax = AccessLogSyntax()
        elif sys.argv[1] == 'cassandra-system':
            syntax = CassandraSystemLogSyntax()
        elif sys.argv[1] == 'error':
            syntax = ErrorLogSyntax()
    else:
        syntax = ErrorLogSyntax()

    if not syntax:
        print "Syntax not supported! Check source!"
        sys.exit(-1)

    try:
        while 1:
            #where = f.tell()
            line = sys.stdin.readline()
            #if not line:
            #    time.sleep(0.2)
            #    f.seek(where)
            #else:
            #    # highlight the line!
            c = syntax(line)
            if c: print c

    except KeyboardInterrupt:
        pass

# vim: ts=4 sts=4 sw=4 et
