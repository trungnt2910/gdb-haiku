#name: MIPS rel32 o32
#source: rel32.s
#as: -KPIC -EB -32
#readelf: -x 6 -r
#ld: -shared -melf32btsmip

Relocation section '.rel.dyn' at offset 0x2d8 contains 2 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
00000000  00000000 R_MIPS_NONE      
00000300  00000003 R_MIPS_REL32     

Hex dump of section '.text':
  0x000002f0 00000000 00000000 00000000 00000000 ................
  0x00000300 00000300 00000000 00000000 00000000 ................
  0x00000310 00000000 00000000 00000000 00000000 ................
