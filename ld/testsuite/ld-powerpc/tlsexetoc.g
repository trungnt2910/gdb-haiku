#source: tlstoc.s
#as: -a64
#ld: tmpdir/libtlslib.so
#objdump: -sj.got
#target: powerpc64*-*-*

.*

Contents of section \.got:
.* (00000000|c0850110) (100185c0|00000000) 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
.* 00000000 00000000 (00000000|01000000) (00000001|00000000)  .*
.* 00000000 00000000 (00000000|01000000) (00000001|00000000)  .*
.* 00000000 00000000 (ffffffff|5080ffff) (ffff8050|ffffffff)  .*
.* 00000000 00000000                    .*
