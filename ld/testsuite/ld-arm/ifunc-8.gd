
.*

Contents of section \.data:
#------------------------------------------------------------------------------
#------ 00010000: foo
#------ 00010004: contains aaf1 [R_ARM_IRELATIVE]
#------ 00010008: contains PC-relative offset of aaf1's .iplt entry
#------ 0001000c: contains atf1 [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 10000 44332211 00a00000 bc90ffff 04a00000  .*
#------------------------------------------------------------------------------
#------ 00010010: contains PC-relative offset of atf1's .iplt entry
#------ 00010014: contains abf1 [R_ARM_IRELATIVE]
#------ 00010018: contains PC-relative offset of abf1's .iplt entry
#------ 0001001c: contains taf1 [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 10010 c490ffff 08a00000 cc90ffff 0da00000  .*
#------------------------------------------------------------------------------
#------ 00010020: contains PC-relative offset of taf1's .iplt entry
#------ 00010024: contains ttf1 [R_ARM_IRELATIVE]
#------ 00010028: contains PC-relative offset of ttf1's .iplt entry
#------ 0001002c: contains tbf1 [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 10020 d090ffff 0fa00000 d890ffff 11a00000  .*
#------------------------------------------------------------------------------
#------ 00010030: contains PC-relative offset of tbf1's .iplt entry
#------ 00010034: aaf2 [R_ARM_ABS32]
#------ 00010038: aaf2 [R_ARM_REL32]
#------ 0001003c: atf2 [R_ARM_ABS32]
#------------------------------------------------------------------------------
 10030 e090ffff 00000000 00000000 00000000  .*
#------------------------------------------------------------------------------
#------ 00010040: atf2 [R_ARM_REL32]
#------ 00010044: abf2 [R_ARM_ABS32]
#------ 00010048: abf2 [R_ARM_REL32]
#------ 0001004c: taf2 [R_ARM_ABS32]
#------------------------------------------------------------------------------
 10040 00000000 00000000 00000000 00000000  .*
#------------------------------------------------------------------------------
#------ 00010050: taf2 [R_ARM_REL32]
#------ 00010054: ttf2 [R_ARM_ABS32]
#------ 00010058: ttf2 [R_ARM_REL32]
#------ 0001005c: tbf2 [R_ARM_ABS32]
#------------------------------------------------------------------------------
 10050 00000000 00000000 00000000 00000000  .*
#------------------------------------------------------------------------------
#------ 00010060: tbf2 [R_ARM_REL32]
#------ 00010064: contains aaf3 [R_ARM_IRELATIVE]
#------ 00010068: contains PC-relative offset of aaf3's .iplt entry
#------ 0001006c: contains atf3 [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 10060 00000000 14a00000 0091ffff 18a00000  .*
#------------------------------------------------------------------------------
#------ 00010070: contains PC-relative offset of atf3's .iplt entry
#------ 00010074: contains abf3 [R_ARM_IRELATIVE]
#------ 00010078: contains PC-relative offset of abf3's .iplt entry
#------ 0001007c: contains taf3 [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 10070 b090ffff 1ca00000 b890ffff 21a00000  .*
#------------------------------------------------------------------------------
#------ 00010080: contains PC-relative offset of taf3's .iplt entry
#------ 00010084: contains ttf3 [R_ARM_IRELATIVE]
#------ 00010088: contains PC-relative offset of ttf3's .iplt entry
#------ 0001008c: contains tbf3 [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 10080 dc90ffff 23a00000 b890ffff 25a00000  .*
#------------------------------------------------------------------------------
#------ 00010090: contains PC-relative offset of tbf3's .iplt entry
#------ 00010094: aaf4 [R_ARM_ABS32]
#------ 00010098: aaf4 [R_ARM_REL32]
#------ 0001009c: atf4 [R_ARM_ABS32]
#------------------------------------------------------------------------------
 10090 c090ffff 00000000 00000000 00000000  .*
#------------------------------------------------------------------------------
#------ 000100a0: atf4 [R_ARM_REL32]
#------ 000100a4: abf4 [R_ARM_ABS32]
#------ 000100a8: abf4 [R_ARM_REL32]
#------ 000100ac: taf4 [R_ARM_ABS32]
#------------------------------------------------------------------------------
 100a0 00000000 00000000 00000000 00000000  .*
#------------------------------------------------------------------------------
#------ 000100b0: taf4 [R_ARM_REL32]
#------ 000100b4: ttf4 [R_ARM_ABS32]
#------ 000100b8: ttf4 [R_ARM_REL32]
#------ 000100bc: tbf4 [R_ARM_ABS32]
#------------------------------------------------------------------------------
 100b0 00000000 00000000 00000000 00000000  .*
#------------------------------------------------------------------------------
#------ 000100c0: tbf4 [R_ARM_REL32]
#------------------------------------------------------------------------------
 100c0 00000000                             .*
Contents of section \.got:
#------------------------------------------------------------------------------
#------ 00011000: .got.plt
#------ 00011004: reserved .got.plt entry
#------ 00011008: reserved .got.plt entry
#------ 0001100c: atf2's .got.plt entry [R_ARM_JUMP_SLOT]
#------------------------------------------------------------------------------
 11000 00200100 00000000 00000000 00900000  .*
#------------------------------------------------------------------------------
#------ 00011010: aaf4's .got.plt entry [R_ARM_JUMP_SLOT]
#------ 00011014: ttf2's .got.plt entry [R_ARM_JUMP_SLOT]
#------ 00011018: tbf2's .got.plt entry [R_ARM_JUMP_SLOT]
#------ 0001101c: taf2's .got.plt entry [R_ARM_JUMP_SLOT]
#------------------------------------------------------------------------------
 11010 00900000 00900000 00900000 00900000  .*
#------------------------------------------------------------------------------
#------ 00011020: aaf2's .got.plt entry [R_ARM_JUMP_SLOT]
#------ 00011024: abf4's .got.plt entry [R_ARM_JUMP_SLOT]
#------ 00011028: tbf4's .got.plt entry [R_ARM_JUMP_SLOT]
#------ 0001102c: ttf4's .got.plt entry [R_ARM_JUMP_SLOT]
#------------------------------------------------------------------------------
 11020 00900000 00900000 00900000 00900000  .*
#------------------------------------------------------------------------------
#------ 00011030: atf4's .got.plt entry [R_ARM_JUMP_SLOT]
#------ 00011034: taf4's .got.plt entry [R_ARM_JUMP_SLOT]
#------ 00011038: abf2's .got.plt entry [R_ARM_JUMP_SLOT]
#------ 0001103c: aaf1's .igot.plt entry [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 11030 00900000 00900000 00900000 00a00000  .*
#------------------------------------------------------------------------------
#------ 00011040: atf1's .igot.plt entry [R_ARM_IRELATIVE]
#------ 00011044: abf1's .igot.plt entry [R_ARM_IRELATIVE]
#------ 00011048: taf1's .igot.plt entry [R_ARM_IRELATIVE]
#------ 0001104c: ttf1's .igot.plt entry [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 11040 04a00000 08a00000 0da00000 0fa00000  .*
#------------------------------------------------------------------------------
#------ 00011050: tbf1's .igot.plt entry [R_ARM_IRELATIVE]
#------ 00011054: atf3's .igot.plt entry [R_ARM_IRELATIVE]
#------ 00011058: abf3's .igot.plt entry [R_ARM_IRELATIVE]
#------ 0001105c: ttf3's .igot.plt entry [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 11050 11a00000 18a00000 1ca00000 23a00000  .*
#------------------------------------------------------------------------------
#------ 00011060: tbf3's .igot.plt entry [R_ARM_IRELATIVE]
#------ 00011064: taf3's .igot.plt entry [R_ARM_IRELATIVE]
#------ 00011068: aaf3's .igot.plt entry [R_ARM_IRELATIVE]
#------ 0001106c: .got entry for foo [R_ARM_RELATIVE]
#------------------------------------------------------------------------------
 11060 25a00000 21a00000 14a00000 00000100  .*
#------------------------------------------------------------------------------
#------ 00011070: .got entry for foo [R_ARM_RELATIVE]
#------ 00011074: .got entry for atf2 [R_ARM_GLOB_DAT]
#------ 00011078: .got entry for aaf4 [R_ARM_GLOB_DAT]
#------ 0001107c: .got entry for ttf2 [R_ARM_GLOB_DAT]
#------------------------------------------------------------------------------
 11070 00000100 00000000 00000000 00000000  .*
#------------------------------------------------------------------------------
#------ 00011080: .got entry for tbf2 [R_ARM_GLOB_DAT]
#------ 00011084: .got entry for taf2 [R_ARM_GLOB_DAT]
#------ 00011088: .got entry for aaf2 [R_ARM_GLOB_DAT]
#------ 0001108c: .got entry for abf4 [R_ARM_GLOB_DAT]
#------------------------------------------------------------------------------
 11080 00000000 00000000 00000000 00000000  .*
#------------------------------------------------------------------------------
#------ 00011090: .got entry for tbf4 [R_ARM_GLOB_DAT]
#------ 00011094: .got entry for ttf4 [R_ARM_GLOB_DAT]
#------ 00011098: .got entry for atf4 [R_ARM_GLOB_DAT]
#------ 0001109c: .got entry for taf4 [R_ARM_GLOB_DAT]
#------------------------------------------------------------------------------
 11090 00000000 00000000 00000000 00000000  .*
#------------------------------------------------------------------------------
#------ 000110a0: .got entry for abf2 [R_ARM_GLOB_DAT]
#------------------------------------------------------------------------------
 110a0 00000000                             .*
