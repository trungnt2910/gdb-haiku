#source: start.s
#readelf: -d -W
#ld: -shared -z now
#target: *-*-linux* *-*-gnu*

#...
 0x[0-9a-f]+ +\(FLAGS\) +BIND_NOW
#pass
