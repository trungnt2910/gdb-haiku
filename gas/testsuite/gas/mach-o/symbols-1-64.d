#as: -L
#objdump: -t
#target: x86_64-*-darwin* powerpc64-*-darwin*
#source: symbols-base-64.s
.*: +file format mach-o.*
#...
SYMBOL TABLE:
0000000000000000 l( )+0e SECT( )+01 0000 \[.text\] Lzt0
0000000000000002 l( )+0e SECT( )+01 0000 \[.text\] Lmt0
0000000000000004 l( )+0e SECT( )+01 0000 \[.text\] Lat0
0000000000000024 l( )+0e SECT( )+02 0000 \[.data\] Lzd0
0000000000000026 l( )+0e SECT( )+02 0000 \[.data\] Lmd0
0000000000000029 l( )+0e SECT( )+02 0000 \[.data\] Lad0
000000000000009c l( )+0e SECT( )+03 0000 \[.bss\] zlcomm0
00000000000000a2 l( )+0e SECT( )+03 0000 \[.bss\] mlcomm0
00000000000000a8 l( )+0e SECT( )+03 0000 \[.bss\] alcomm0
0000000000000060 l( )+0e SECT( )+04 0000 \[__HERE.__there\] Lzs0
0000000000000062 l( )+0e SECT( )+04 0000 \[__HERE.__there\] Lms0
0000000000000064 l( )+0e SECT( )+04 0000 \[__HERE.__there\] Las0
000000000000001e l( )+0e SECT( )+01 0000 \[.text\] Lzt1
0000000000000021 l( )+0e SECT( )+01 0000 \[.text\] Lmt1
0000000000000023 l( )+0e SECT( )+01 0000 \[.text\] Lat1
0000000000000042 l( )+0e SECT( )+02 0000 \[.data\] Lzd1
0000000000000044 l( )+0e SECT( )+02 0000 \[.data\] Lmd1
0000000000000047 l( )+0e SECT( )+02 0000 \[.data\] Lad1
00000000000000ae l( )+0e SECT( )+03 0000 \[.bss\] zlcomm1
00000000000000b4 l( )+0e SECT( )+03 0000 \[.bss\] mlcomm1
00000000000000ba l( )+0e SECT( )+03 0000 \[.bss\] alcomm1
0000000000000086 l( )+0e SECT( )+04 0000 \[__HERE.__there\] Lzs1
0000000000000092 l( )+0e SECT( )+04 0000 \[__HERE.__there\] Lms1
0000000000000093 l( )+0e SECT( )+04 0000 \[__HERE.__there\] Las1
0000000000000028 g( )+0f SECT( )+02 0000 \[.data\] adg0
0000000000000046 g( )+0f SECT( )+02 0000 \[.data\] adg1
0000000000000065 g( )+0f SECT( )+04 0000 \[__HERE.__there\] asg0
0000000000000091 g( )+0f SECT( )+04 0000 \[__HERE.__there\] asg1
0000000000000005 g( )+0f SECT( )+01 0000 \[.text\] atg0
0000000000000022 g( )+0f SECT( )+01 0000 \[.text\] atg1
0000000000000027 g( )+0f SECT( )+02 0000 \[.data\] mdg0
0000000000000045 g( )+0f SECT( )+02 0000 \[.data\] mdg1
0000000000000063 g( )+0f SECT( )+04 0000 \[__HERE.__there\] msg0
0000000000000090 g( )+0f SECT( )+04 0000 \[__HERE.__there\] msg1
0000000000000003 g( )+0f SECT( )+01 0000 \[.text\] mtg0
0000000000000020 g( )+0f SECT( )+01 0000 \[.text\] mtg1
0000000000000025 g( )+0f SECT( )+02 0000 \[.data\] zdg0
0000000000000043 g( )+0f SECT( )+02 0000 \[.data\] zdg1
0000000000000061 g( )+0f SECT( )+04 0000 \[__HERE.__there\] zsg0
0000000000000087 g( )+0f SECT( )+04 0000 \[__HERE.__there\] zsg1
0000000000000001 g( )+0f SECT( )+01 0000 \[.text\] ztg0
000000000000001f g( )+0f SECT( )+01 0000 \[.text\] ztg1
0000000000000000 g( )+01 UND( )+00 0000 _aud0
0000000000000000 g( )+01 UND( )+00 0000 _aud1
0000000000000000 g( )+01 UND( )+00 0000 _aus0
0000000000000000 g( )+01 UND( )+00 0000 _aus1
0000000000000000 g( )+01 UND( )+00 0000 _aut0
0000000000000000 g( )+01 UND( )+00 0000 _mud0
0000000000000000 g( )+01 UND( )+00 0000 _mud1
0000000000000000 g( )+01 UND( )+00 0000 _mus0
0000000000000000 g( )+01 UND( )+00 0000 _mus1
0000000000000000 g( )+01 UND( )+00 0000 _mut0
0000000000000000 g( )+01 UND( )+00 0000 _zud0
0000000000000000 g( )+01 UND( )+00 0000 _zud1
0000000000000000 g( )+01 UND( )+00 0000 _zus0
0000000000000000 g( )+01 UND( )+00 0000 _zus1
0000000000000000 g( )+01 UND( )+00 0000 _zut0
000000000000000a( )+01 COM( )+00 0300 acommon0
000000000000000a( )+01 COM( )+00 0300 acommon1
000000000000000a( )+01 COM( )+00 0300 mcommon0
000000000000000a( )+01 COM( )+00 0300 mcommon1
000000000000000a( )+01 COM( )+00 0300 zcommon0
000000000000000a( )+01 COM( )+00 0300 zcommon1
