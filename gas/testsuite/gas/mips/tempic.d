#objdump: -rst -mmips:4000
#name: MIPS empic
#as: -membedded-pic -mips3
#source: empic.s

# Check GNU-specific embedded relocs, for ELF.

.*: +file format elf.*mips.*

SYMBOL TABLE:
0+0000000 l    d  \.text	0+0000000 
0+0000000 l    d  \.data	0+0000000 
0+0000000 l    d  \.bss	0+0000000 
0+0000004 l       \.text	0+0000000 l2
0+0000100 l       \.foo	0+0000000 l1
0+0000034 l       \.text	0+0000000 l3
0+0000098 l       \.text	0+0000000 l5
0+0000000 l    d  \.foo	0+0000000 
0+0000004 l       \.foo	0+0000000 l4
0+0000000 l    d  \.reginfo	0+0000000 
0+0000000 l    d  \.(mdebug|pdr)	0+0000000 
0+0000000         \*UND\*	0+0000000 g1
0+0000000         \*UND\*	0+0000000 g2


RELOCATION RECORDS FOR \[\.text\]:
OFFSET [ ]+ TYPE              VALUE 
0+0000004 R_MIPS_GNU_REL16_S2  g1
0+000000c R_MIPS_GNU_REL16_S2  g2
0+0000014 R_MIPS_GNU_REL16_S2  g2
0+000001c R_MIPS_GNU_REL16_S2  \.foo
0+0000024 R_MIPS_GNU_REL16_S2  \.text
0+000002c R_MIPS_GNU_REL16_S2  \.foo
0+0000034 R_MIPS_GNU_REL16_S2  \.text
0+000003c R_MIPS_GNU_REL_HI16  g1
0+0000040 R_MIPS_GNU_REL_LO16  g1
0+0000044 R_MIPS_GNU_REL_HI16  \.foo
0+0000048 R_MIPS_GNU_REL_LO16  \.foo
0+0000050 R_MIPS_32         g1
0+0000054 R_MIPS_32         \.foo
0+0000058 R_MIPS_32         \.text
0+000005c R_MIPS_PC32       g1
0+0000060 R_MIPS_PC32       \.foo
0+0000068 R_MIPS_64         g1
0+0000070 R_MIPS_64         \.foo
0+0000078 R_MIPS_64         \.text
0+0000080 R_MIPS_PC64       g1
0+0000088 R_MIPS_PC64       \.foo
0+0000098 R_MIPS_GNU_REL16_S2  \.text
0+000009c R_MIPS_GNU_REL16_S2  \.text
0+00000a0 R_MIPS_GNU_REL_HI16  \.text
0+00000a4 R_MIPS_GNU_REL_LO16  \.text
0+00000a8 R_MIPS_GNU_REL_HI16  \.text
0+00000ac R_MIPS_GNU_REL_LO16  \.text
0+00000b0 R_MIPS_32         \.text
0+00000b8 R_MIPS_64         \.text
0+00000cc R_MIPS_GNU_REL16_S2  \.text
0+00000d0 R_MIPS_GNU_REL16_S2  \.text
0+00000dc R_MIPS_32         \.text
0+00000e8 R_MIPS_64         \.text


RELOCATION RECORDS FOR \[\.foo\]:
OFFSET [ ]+ TYPE              VALUE 
0+0000004 R_MIPS_GNU_REL_HI16  g1
0+0000008 R_MIPS_GNU_REL_LO16  g1
0+000000c R_MIPS_GNU_REL_HI16  \.foo
0+0000010 R_MIPS_GNU_REL_LO16  \.foo
0+0000014 R_MIPS_GNU_REL_HI16  \.text
0+0000018 R_MIPS_GNU_REL_LO16  \.text
0+000001c R_MIPS_GNU_REL_HI16  g1
0+0000020 R_MIPS_GNU_REL_LO16  g1
0+0000024 R_MIPS_GNU_REL_HI16  g1
0+0000028 R_MIPS_GNU_REL_LO16  g1
0+000002c R_MIPS_GNU_REL_HI16  \.foo
0+0000030 R_MIPS_GNU_REL_LO16  \.foo
0+0000034 R_MIPS_GNU_REL_HI16  \.text
0+0000038 R_MIPS_GNU_REL_LO16  \.text
0+000003c R_MIPS_32         g1
0+0000040 R_MIPS_32         \.foo
0+0000044 R_MIPS_32         \.text
0+0000048 R_MIPS_PC32       g1
0+0000050 R_MIPS_PC32       \.text
0+0000058 R_MIPS_64         g1
0+0000060 R_MIPS_64         \.foo
0+0000068 R_MIPS_64         \.text
0+0000070 R_MIPS_PC64       g1
0+0000080 R_MIPS_PC64       \.text
0+0000088 R_MIPS_GNU_REL_HI16  g1
0+000008c R_MIPS_GNU_REL_LO16  g1
0+0000090 R_MIPS_GNU_REL_HI16  \.foo
0+0000094 R_MIPS_GNU_REL_LO16  \.foo
0+0000098 R_MIPS_GNU_REL_HI16  \.text
0+000009c R_MIPS_GNU_REL_LO16  \.text
0+00000a0 R_MIPS_GNU_REL_HI16  g1
0+00000a4 R_MIPS_GNU_REL_LO16  g1
0+00000a8 R_MIPS_GNU_REL_HI16  \.foo
0+00000ac R_MIPS_GNU_REL_LO16  \.foo
0+00000b0 R_MIPS_GNU_REL_HI16  \.text
0+00000b4 R_MIPS_GNU_REL_LO16  \.text
0+00000b8 R_MIPS_32         g1
0+00000bc R_MIPS_32         \.foo
0+00000c0 R_MIPS_32         \.text
0+00000c4 R_MIPS_PC32       g1
0+00000cc R_MIPS_PC32       \.text
0+00000d0 R_MIPS_64         g1
0+00000d8 R_MIPS_64         \.foo
0+00000e0 R_MIPS_64         \.text
0+00000e8 R_MIPS_PC64       g1
0+00000f8 R_MIPS_PC64       \.text

Contents of section \.text:
 0000 00000000 0411ffff 00000000 1000ffff  .*
 0010 00000000 1000ffff 00000000 0411003f  .*
 0020 00000000 04110000 00000000 10000041  .*
 0030 00000000 10000000 00000000 3c030000  .*
 0040 [26]463000c 3c030000 [26]4630114 2403ffd0  .*
 0050 00000000 00000100 00000004 00000028  .*
 0060 0000012c ffffffd0 00000000 00000000  .*
 0070 00000000 00000100 00000000 00000004  .*
 0080 00000000 0000004c 00000000 00000154  .*
 0090 ffffffff ffffffd0 10000032 10000033  .*
 00a0 3c030000 [26]46300d8 3c030000 [26]46300e8  .*
 00b0 000000cc 00000034 00000000 000000cc  .*
 00c0 00000000 00000034 00000000 10000032  .*
 00d0 10000033 24030034 2403003c 000000cc  .*
 00e0 00000034 00000000 00000000 000000cc  .*
 00f0 00000000 00000034 00000000 00000000  .*
Contents of section \.data:
Contents of section \.reginfo:
 0000 80000008 00000000 00000000 00000000  .*
 0010 00000000 00000000                    .*
Contents of section \.(mdebug|pdr):
#...
Contents of section \.foo:
 0000 00000000 3c030000 [26]4630004 3c030000  .*
 0010 [26]463010c 3c030000 [26]4630018 3c030000  .*
 0020 [26]463001c 3c030000 [26]4630024 3c030000  .*
 0030 [26]463012c 3c030000 [26]4630038 00000000  .*
 0040 00000100 00000004 00000044 000000fc  .*
 0050 00000050 00000000 00000000 00000000  .*
 0060 00000000 00000100 00000000 00000004  .*
 0070 00000000 0000006c 00000000 000000fc  .*
 0080 00000000 00000080 3c030000 [26]463008c  .*
 0090 3c030000 [26]4630194 3c030000 [26]46300a0  .*
 00a0 3c030000 [26]46300a4 3c030000 [26]46301ac  .*
 00b0 3c030000 [26]46300b8 00000004 00000104  .*
 00c0 00000008 000000c4 00000100 000000d0  .*
 00d0 00000000 00000004 00000000 00000104  .*
 00e0 00000000 00000008 00000000 000000e8  .*
 00f0 00000000 00000100 00000000 000000fc  .*
 0100 00000000 00000000 00000000 00000000  .*

