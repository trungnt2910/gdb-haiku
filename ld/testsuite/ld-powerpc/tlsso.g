#source: tls.s
#as: -a64
#ld: -shared -melf64ppc
#objdump: -sj.got
#target: powerpc64*-*-*

.*: +file format elf64-powerpc

Contents of section \.got:
.* 00000000 000187b8 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
.* 00000000 00000000 00000000 00000000  .*
