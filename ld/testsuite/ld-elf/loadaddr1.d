#source: loadaddr.s
#ld: -T loadaddr1.t -z max-page-size=0x200000
#readelf: -l --wide
#target: *-*-linux*

#...
  LOAD +0x000000 0xf*80000000 0xf*80000000 0x100050 0x100050 RWE 0x200000
  LOAD +0x200000 0xf*ff600000 0xf*80101000 0x0*10 0x0*10 R E 0x200000
  LOAD +0x302000 0xf*80102000 0xf*80102000 0x0*10 0x0*10 RW  0x200000
#pass
