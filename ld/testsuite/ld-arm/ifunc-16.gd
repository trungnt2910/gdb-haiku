
.*

Contents of section \.data:
#------------------------------------------------------------------------------
#------ 00010000: foo
#------------------------------------------------------------------------------
 10000 44332211 00800000 30800000           .*
Contents of section \.got:
#------------------------------------------------------------------------------
#------ 00011000: .got.plt
#------ 00011004: reserved .got.plt entry
#------ 00011008: reserved .got.plt entry
#------ 0001100c: f1's .igot.plt entry [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 11000 00200100 00000000 00000000 00a00000  .*
#------------------------------------------------------------------------------
#------ 00011010: f1t's .igot.plt entry [R_ARM_IRELATIVE]
#------ 00011014: f2t's .igot.plt pointer to 0xa00f [R_ARM_IRELATIVE]
#------ 00011018: f3's .igot.plt pointer to 0xa008 [R_ARM_IRELATIVE]
#------ 0001101c: f2's .igot.plt pointer to 0xa004 [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 11010 0da00000 0fa00000 08a00000 04a00000  .*
#------------------------------------------------------------------------------
#------ 00011020: f3t's .igot.plt pointer to 0xa011 [R_ARM_IRELATIVE]
#------------------------------------------------------------------------------
 11020 11a00000                             .*
