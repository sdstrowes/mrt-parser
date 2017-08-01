# mrt-parser

I just needed a quick and dirty MRT parser.

This tool ignores most fields from MRT BGP dumps taken from
[routeviews.org](http://routeviews.org/). It spits out a prefix in the first
column, then any AS sequences (paths) or sets in subsequent columns. One
sequence and/or set per line.

By dropping a lot of inspection, this tool can run fairly quickly ([ripe ncc's
bgpdump](https://bitbucket.org/ripencc/bgpdump/wiki/Home) does a lot more
string formatting for output):

```
sds@stkilda:~/proj/mrt-parser$ time zcat bview.20170801.0800.gz > /dev/null

real	0m3.288s
user	0m3.252s
sys	0m0.020s


sds@stkilda:~/proj/mrt-parser$ time ./mrt  -f bview.20170801.0800.gz > /dev/null

real	0m23.587s
user	0m23.313s
sys	0m0.120s

sds@stkilda:~/proj/mrt-parser$ time ~/ext/bgpdump/bgpdump -m bview.20170801.0800.gz > /dev/null 2>&1

real	1m40.063s
user	1m30.846s
sys	0m8.477s
```
