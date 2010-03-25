#objdump: -dr --prefix-addresses --show-raw-insn
#name: C674x instructions generating relocations
#as: -march=c674x -mlittle-endian

.*: *file format elf32-tic6x-le


Disassembly of section \.text:
0+00 <[^>]*> 1280003c[ \t]+addab \.D1X b14,0,a5
[ \t]*0: R_C6000_SBR_U15_B[ \t]+ext1
0+04 <[^>]*> 138000be[ \t]+addab \.D2 b15,0,b7
[ \t]*4: R_C6000_SBR_U15_B[ \t]+ext2\+0x7
0+08 <[^>]*> 1a00003c[ \t]+addab \.D1X b14,0,a20
[ \t]*8: R_C6000_SBR_U15_B[ \t]+a1
0+0c <[^>]*> 1f00003e[ \t]+addab \.D2 b14,0,b30
[ \t]*c: R_C6000_SBR_U15_B[ \t]+b1
0+10 <[^>]*> 1780043c[ \t]+addab \.D1X b14,4,a15
0+14 <[^>]*> 1800043e[ \t]+addab \.D2 b14,4,b16
0+18 <[^>]*> 1280005c[ \t]+addah \.D1X b14,0,a5
[ \t]*18: R_C6000_SBR_U15_H[ \t]+ext1
0+1c <[^>]*> 138000de[ \t]+addah \.D2 b15,0,b7
[ \t]*1c: R_C6000_SBR_U15_H[ \t]+ext2\+0x6
0+20 <[^>]*> 1a00005c[ \t]+addah \.D1X b14,0,a20
[ \t]*20: R_C6000_SBR_U15_H[ \t]+a1
0+24 <[^>]*> 1f00005e[ \t]+addah \.D2 b14,0,b30
[ \t]*24: R_C6000_SBR_U15_H[ \t]+b1
0+28 <[^>]*> 1780045c[ \t]+addah \.D1X b14,4,a15
0+2c <[^>]*> 1800045e[ \t]+addah \.D2 b14,4,b16
0+30 <[^>]*> 1280007c[ \t]+addaw \.D1X b14,0,a5
[ \t]*30: R_C6000_SBR_U15_W[ \t]+ext1
0+34 <[^>]*> 138000fe[ \t]+addaw \.D2 b15,0,b7
[ \t]*34: R_C6000_SBR_U15_W[ \t]+ext2\+0x8
0+38 <[^>]*> 1a00007c[ \t]+addaw \.D1X b14,0,a20
[ \t]*38: R_C6000_SBR_U15_W[ \t]+a1
0+3c <[^>]*> 1f00007e[ \t]+addaw \.D2 b14,0,b30
[ \t]*3c: R_C6000_SBR_U15_W[ \t]+b1
0+40 <[^>]*> 1780047c[ \t]+addaw \.D1X b14,4,a15
0+44 <[^>]*> 1800047e[ \t]+addaw \.D2 b14,4,b16
0+48 <[^>]*> 1280007c[ \t]+addaw \.D1X b14,0,a5
[ \t]*48: R_C6000_DSBT_INDEX[ \t]+__c6xabi_DSBT_BASE
0+4c <[^>]*> 138000fe[ \t]+addaw \.D2 b15,0,b7
[ \t]*4c: R_C6000_SBR_GOT_U15_W[ \t]+ext2\+0x8
0+50 <[^>]*> 00800050[ \t]+addk \.S1 0,a1
[ \t]*50: R_C6000_ABS_S16[ \t]+ext1\+0x3
0+54 <[^>]*> 01800052[ \t]+addk \.S2 0,b3
[ \t]*54: R_C6000_SBR_S16[ \t]+ext2\+0x5
0+58 <[^>]*> 02000250[ \t]+addk \.S1 4,a4
0+5c <[^>]*> 02fffe52[ \t]+addk \.S2 -4,b5
0+60 <[^>]*> 00800028[ \t]+mvk \.S1 0,a1
[ \t]*60: R_C6000_ABS_S16[ \t]+ext1\+0x3
0+64 <[^>]*> 0180002a[ \t]+mvk \.S2 0,b3
[ \t]*64: R_C6000_SBR_S16[ \t]+ext2\+0x5
0+68 <[^>]*> 02000228[ \t]+mvk \.S1 4,a4
0+6c <[^>]*> 02fffe2a[ \t]+mvk \.S2 -4,b5
0+70 <[^>]*> 00800068[ \t]+mvkh \.S1 0,a1
[ \t]*70: R_C6000_ABS_H16[ \t]+ext3\+0x1
0+74 <[^>]*> 0100006a[ \t]+mvkh \.S2 0,b2
[ \t]*74: R_C6000_SBR_GOT_H16_W[ \t]+ext2\+0x2
0+78 <[^>]*> 01800068[ \t]+mvkh \.S1 0,a3
[ \t]*78: R_C6000_SBR_H16_B[ \t]+ext1\+0x3
0+7c <[^>]*> 0200006a[ \t]+mvkh \.S2 0,b4
[ \t]*7c: R_C6000_SBR_H16_H[ \t]+ext3\+0x4
0+80 <[^>]*> 02800068[ \t]+mvkh \.S1 0,a5
[ \t]*80: R_C6000_SBR_H16_W[ \t]+ext2\+0x5
0+84 <[^>]*> 0300016a[ \t]+mvkh \.S2 131072,b6
0+88 <[^>]*> 00800068[ \t]+mvkh \.S1 0,a1
[ \t]*88: R_C6000_ABS_L16[ \t]+ext3\+0x1
0+8c <[^>]*> 0100006a[ \t]+mvkh \.S2 0,b2
[ \t]*8c: R_C6000_SBR_GOT_L16_W[ \t]+ext2\+0x2
0+90 <[^>]*> 01800068[ \t]+mvkh \.S1 0,a3
[ \t]*90: R_C6000_SBR_L16_B[ \t]+ext1\+0x3
0+94 <[^>]*> 0200006a[ \t]+mvkh \.S2 0,b4
[ \t]*94: R_C6000_SBR_L16_H[ \t]+ext3\+0x4
0+98 <[^>]*> 02800068[ \t]+mvkh \.S1 0,a5
[ \t]*98: R_C6000_SBR_L16_W[ \t]+ext2\+0x5
0+9c <[^>]*> 030000ea[ \t]+mvkh \.S2 65536,b6
0+a0 <[^>]*> 00800028[ \t]+mvk \.S1 0,a1
[ \t]*a0: R_C6000_ABS_L16[ \t]+ext3\+0x1
0+a4 <[^>]*> 0100002a[ \t]+mvk \.S2 0,b2
[ \t]*a4: R_C6000_SBR_GOT_L16_W[ \t]+ext2\+0x2
0+a8 <[^>]*> 01800028[ \t]+mvk \.S1 0,a3
[ \t]*a8: R_C6000_SBR_L16_B[ \t]+ext1\+0x3
0+ac <[^>]*> 0200002a[ \t]+mvk \.S2 0,b4
[ \t]*ac: R_C6000_SBR_L16_H[ \t]+ext3\+0x4
0+b0 <[^>]*> 02800028[ \t]+mvk \.S1 0,a5
[ \t]*b0: R_C6000_SBR_L16_W[ \t]+ext2\+0x5
0+b4 <[^>]*> 030000aa[ \t]+mvk \.S2 1,b6
0+b8 <[^>]*> 0080002e[ \t]+ldb \.D2T2 \*\+b14\(0\),b1
[ \t]*b8: R_C6000_SBR_U15_B[ \t]+ext1
0+bc <[^>]*> 008000ac[ \t]+ldb \.D2T1 \*\+b15\(0\),a1
[ \t]*bc: R_C6000_SBR_U15_B[ \t]+ext2\+0x7
0+c0 <[^>]*> 008000ae[ \t]+ldb \.D2T2 \*\+b15\(0\),b1
[ \t]*c0: R_C6000_SBR_U15_B[ \t]+b1
0+c4 <[^>]*> 0080002c[ \t]+ldb \.D2T1 \*\+b14\(0\),a1
[ \t]*c4: R_C6000_SBR_U15_B[ \t]+a1
0+c8 <[^>]*> 00b882a6[ \t]+ldb \.D2T2 \*\+b14\(4\),b1
0+cc <[^>]*> 0080042c[ \t]+ldb \.D2T1 \*\+b14\(4\),a1
0+d0 <[^>]*> 0080001e[ \t]+ldbu \.D2T2 \*\+b14\(0\),b1
[ \t]*d0: R_C6000_SBR_U15_B[ \t]+ext1
0+d4 <[^>]*> 0080009c[ \t]+ldbu \.D2T1 \*\+b15\(0\),a1
[ \t]*d4: R_C6000_SBR_U15_B[ \t]+ext2\+0x7
0+d8 <[^>]*> 0080009e[ \t]+ldbu \.D2T2 \*\+b15\(0\),b1
[ \t]*d8: R_C6000_SBR_U15_B[ \t]+b1
0+dc <[^>]*> 0080001c[ \t]+ldbu \.D2T1 \*\+b14\(0\),a1
[ \t]*dc: R_C6000_SBR_U15_B[ \t]+a1
0+e0 <[^>]*> 00b88296[ \t]+ldbu \.D2T2 \*\+b14\(4\),b1
0+e4 <[^>]*> 0080041c[ \t]+ldbu \.D2T1 \*\+b14\(4\),a1
0+e8 <[^>]*> 0080004e[ \t]+ldh \.D2T2 \*\+b14\(0\),b1
[ \t]*e8: R_C6000_SBR_U15_H[ \t]+ext1
0+ec <[^>]*> 008000cc[ \t]+ldh \.D2T1 \*\+b15\(0\),a1
[ \t]*ec: R_C6000_SBR_U15_H[ \t]+ext2\+0x6
0+f0 <[^>]*> 008000ce[ \t]+ldh \.D2T2 \*\+b15\(0\),b1
[ \t]*f0: R_C6000_SBR_U15_H[ \t]+b1
0+f4 <[^>]*> 0080004c[ \t]+ldh \.D2T1 \*\+b14\(0\),a1
[ \t]*f4: R_C6000_SBR_U15_H[ \t]+a1
0+f8 <[^>]*> 00b842c6[ \t]+ldh \.D2T2 \*\+b14\(4\),b1
0+fc <[^>]*> 0080024c[ \t]+ldh \.D2T1 \*\+b14\(4\),a1
0+100 <[^>]*> 0080000e[ \t]+ldhu \.D2T2 \*\+b14\(0\),b1
[ \t]*100: R_C6000_SBR_U15_H[ \t]+ext1
0+104 <[^>]*> 0080008c[ \t]+ldhu \.D2T1 \*\+b15\(0\),a1
[ \t]*104: R_C6000_SBR_U15_H[ \t]+ext2\+0x6
0+108 <[^>]*> 0080008e[ \t]+ldhu \.D2T2 \*\+b15\(0\),b1
[ \t]*108: R_C6000_SBR_U15_H[ \t]+b1
0+10c <[^>]*> 0080000c[ \t]+ldhu \.D2T1 \*\+b14\(0\),a1
[ \t]*10c: R_C6000_SBR_U15_H[ \t]+a1
0+110 <[^>]*> 00b84286[ \t]+ldhu \.D2T2 \*\+b14\(4\),b1
0+114 <[^>]*> 0080020c[ \t]+ldhu \.D2T1 \*\+b14\(4\),a1
0+118 <[^>]*> 0080006e[ \t]+ldw \.D2T2 \*\+b14\(0\),b1
[ \t]*118: R_C6000_SBR_U15_W[ \t]+ext1
0+11c <[^>]*> 008000ec[ \t]+ldw \.D2T1 \*\+b15\(0\),a1
[ \t]*11c: R_C6000_SBR_U15_W[ \t]+ext2\+0x4
0+120 <[^>]*> 008000ee[ \t]+ldw \.D2T2 \*\+b15\(0\),b1
[ \t]*120: R_C6000_SBR_U15_W[ \t]+b1
0+124 <[^>]*> 0080006c[ \t]+ldw \.D2T1 \*\+b14\(0\),a1
[ \t]*124: R_C6000_SBR_U15_W[ \t]+a1
0+128 <[^>]*> 00b822e6[ \t]+ldw \.D2T2 \*\+b14\(4\),b1
0+12c <[^>]*> 0080016c[ \t]+ldw \.D2T1 \*\+b14\(4\),a1
0+130 <[^>]*> 0080006e[ \t]+ldw \.D2T2 \*\+b14\(0\),b1
[ \t]*130: R_C6000_DSBT_INDEX[ \t]+__c6xabi_DSBT_BASE
0+134 <[^>]*> 0080006c[ \t]+ldw \.D2T1 \*\+b14\(0\),a1
[ \t]*134: R_C6000_SBR_GOT_U15_W[ \t]+ext2\+0x4
0+138 <[^>]*> 0080003e[ \t]+stb \.D2T2 b1,\*\+b14\(0\)
[ \t]*138: R_C6000_SBR_U15_B[ \t]+ext1
0+13c <[^>]*> 008000bc[ \t]+stb \.D2T1 a1,\*\+b15\(0\)
[ \t]*13c: R_C6000_SBR_U15_B[ \t]+ext2\+0x7
0+140 <[^>]*> 008000be[ \t]+stb \.D2T2 b1,\*\+b15\(0\)
[ \t]*140: R_C6000_SBR_U15_B[ \t]+b1
0+144 <[^>]*> 0080003c[ \t]+stb \.D2T1 a1,\*\+b14\(0\)
[ \t]*144: R_C6000_SBR_U15_B[ \t]+a1
0+148 <[^>]*> 00b882b6[ \t]+stb \.D2T2 b1,\*\+b14\(4\)
0+14c <[^>]*> 0080043c[ \t]+stb \.D2T1 a1,\*\+b14\(4\)
0+150 <[^>]*> 0080005e[ \t]+sth \.D2T2 b1,\*\+b14\(0\)
[ \t]*150: R_C6000_SBR_U15_H[ \t]+ext1
0+154 <[^>]*> 008000dc[ \t]+sth \.D2T1 a1,\*\+b15\(0\)
[ \t]*154: R_C6000_SBR_U15_H[ \t]+ext2\+0x6
0+158 <[^>]*> 008000de[ \t]+sth \.D2T2 b1,\*\+b15\(0\)
[ \t]*158: R_C6000_SBR_U15_H[ \t]+b1
0+15c <[^>]*> 0080005c[ \t]+sth \.D2T1 a1,\*\+b14\(0\)
[ \t]*15c: R_C6000_SBR_U15_H[ \t]+a1
0+160 <[^>]*> 00b842d6[ \t]+sth \.D2T2 b1,\*\+b14\(4\)
0+164 <[^>]*> 0080025c[ \t]+sth \.D2T1 a1,\*\+b14\(4\)
0+168 <[^>]*> 0080007e[ \t]+stw \.D2T2 b1,\*\+b14\(0\)
[ \t]*168: R_C6000_SBR_U15_W[ \t]+ext1
0+16c <[^>]*> 008000fc[ \t]+stw \.D2T1 a1,\*\+b15\(0\)
[ \t]*16c: R_C6000_SBR_U15_W[ \t]+ext2\+0x4
0+170 <[^>]*> 008000fe[ \t]+stw \.D2T2 b1,\*\+b15\(0\)
[ \t]*170: R_C6000_SBR_U15_W[ \t]+b1
0+174 <[^>]*> 0080007c[ \t]+stw \.D2T1 a1,\*\+b14\(0\)
[ \t]*174: R_C6000_SBR_U15_W[ \t]+a1
0+178 <[^>]*> 00b822f6[ \t]+stw \.D2T2 b1,\*\+b14\(4\)
0+17c <[^>]*> 0080017c[ \t]+stw \.D2T1 a1,\*\+b14\(4\)
0+180 <[^>]*> 0080007e[ \t]+stw \.D2T2 b1,\*\+b14\(0\)
[ \t]*180: R_C6000_DSBT_INDEX[ \t]+__c6xabi_DSBT_BASE
0+184 <[^>]*> 0080007c[ \t]+stw \.D2T1 a1,\*\+b14\(0\)
[ \t]*184: R_C6000_SBR_GOT_U15_W[ \t]+ext2\+0x4
[ \t]*\.\.\.
