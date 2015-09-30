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
sds@stkilda:~/proj/mrt-parser$ time ./mrt -f rib.20150929.0000.v4 > /dev/null

real    0m16.768s
user    0m16.325s
sys     0m0.436s
sds@stkilda:~/proj/mrt-parser$ time ~/ext/bgpdump/bgpdump -M rib.20150929.0000.v4 > /dev/null 2>&1 

real    1m51.894s
user    1m30.514s
sys     0m21.269s
```
