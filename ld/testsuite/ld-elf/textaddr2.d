#source: maxpage1.s
#ld: -shared -Ttext-segment 0x7000000 -z max-page-size=0x200000
#readelf: -l --wide
#target: *-*-linux-gnu *-*-gnu*

#...
  LOAD +0x0+ 0x0*7000000 0x0*7000000 0x0*[0-9a-f]+ 0x0*[0-9a-f]+ R[ W]E 0x200000
#pass
