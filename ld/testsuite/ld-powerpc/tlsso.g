#source: tls.s
#as: -a64
#ld: -shared
#objdump: -sj.got
#target: powerpc64*-*-*

.*

Contents of section \.got:
 10788 (00000000|88870100) (00018788|00000000) 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
