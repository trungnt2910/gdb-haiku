/* Configuration for the Xtensa architecture for GDB, the GNU debugger.

   Copyright (C) 2003, 2005, 2006, 2007 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#include "xtensa-config.h"
#include "defs.h"
#include "gdbarch.h"
#include "xtensa-tdep.h"
#include "gdbtypes.h"

/* Check version of configuration file.  */
#define XTENSA_CONFIG_VERSION 0x60
#if XTENSA_TDEP_VERSION != XTENSA_CONFIG_VERSION
#warning "xtensa-config.c version mismatch!"
#endif


/* Return the byte order from the configuration.
   We need this function, because the byte order is needed even
   before the target structure (tdep) has been set up.  */

int
xtensa_config_byte_order (void)
{
  return XCHAL_HAVE_BE ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
}


/* This routine returns the predefined architecture-dependent
   parameter structure (tdep) and register map.  */

struct gdbarch_tdep xtensa_tdep;

struct gdbarch_tdep *
xtensa_config_tdep (struct gdbarch_info *info)
{
  return &xtensa_tdep;
}


/* Masked registers.  */
xtensa_reg_mask_t xtensa_submask0[] = { { 96, 0, 4 } };
const xtensa_mask_t xtensa_mask0 = { 1, xtensa_submask0 };
xtensa_reg_mask_t xtensa_submask1[] = { { 96, 5, 1 } };
const xtensa_mask_t xtensa_mask1 = { 1, xtensa_submask1 };
xtensa_reg_mask_t xtensa_submask2[] = { { 96, 18, 1 } };
const xtensa_mask_t xtensa_mask2 = { 1, xtensa_submask2 };
xtensa_reg_mask_t xtensa_submask3[] = { { 96, 6, 2 } };
const xtensa_mask_t xtensa_mask3 = { 1, xtensa_submask3 };
xtensa_reg_mask_t xtensa_submask4[] = { { 96, 4, 1 } };
const xtensa_mask_t xtensa_mask4 = { 1, xtensa_submask4 };
xtensa_reg_mask_t xtensa_submask5[] = { { 96, 16, 2 } };
const xtensa_mask_t xtensa_mask5 = { 1, xtensa_submask5 };
xtensa_reg_mask_t xtensa_submask6[] = { { 96, 8, 4 } };
const xtensa_mask_t xtensa_mask6 = { 1, xtensa_submask6 };
xtensa_reg_mask_t xtensa_submask7[] = { { 95, 12, 20 } };
const xtensa_mask_t xtensa_mask7 = { 1, xtensa_submask7 };
xtensa_reg_mask_t xtensa_submask8[] = { { 95, 0, 1 } };
const xtensa_mask_t xtensa_mask8 = { 1, xtensa_submask8 };
xtensa_reg_mask_t xtensa_submask9[] = { { 108, 8, 4 } };
const xtensa_mask_t xtensa_mask9 = { 1, xtensa_submask9 };
xtensa_reg_mask_t xtensa_submask10[] = { { 109, 24, 8 } };
const xtensa_mask_t xtensa_mask10 = { 1, xtensa_submask10 };
xtensa_reg_mask_t xtensa_submask11[] = { { 109, 16, 8 } };
const xtensa_mask_t xtensa_mask11 = { 1, xtensa_submask11 };
xtensa_reg_mask_t xtensa_submask12[] = { { 109, 8, 8 } };
const xtensa_mask_t xtensa_mask12 = { 1, xtensa_submask12 };
xtensa_reg_mask_t xtensa_submask13[] = { { 110, 16, 2 } };
const xtensa_mask_t xtensa_mask13 = { 1, xtensa_submask13 };
xtensa_reg_mask_t xtensa_submask14[] = { { 111, 16, 2 } };
const xtensa_mask_t xtensa_mask14 = { 1, xtensa_submask14 };
xtensa_reg_mask_t xtensa_submask15[] = { { 67, 22, 10 } };
const xtensa_mask_t xtensa_mask15 = { 1, xtensa_submask15 };


/* Register map.  */
xtensa_register_t rmap[] = 
{
  { /* 0000 */ "ar0", 0, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000100, 0x0006, 0, 
    0, 0 },
  { /* 0001 */ "ar1", 4, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000101, 0x0006, 0, 
    0, 0 },
  { /* 0002 */ "ar2", 8, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000102, 0x0006, 0, 
    0, 0 },
  { /* 0003 */ "ar3", 12, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000103, 0x0006, 0, 
    0, 0 },
  { /* 0004 */ "ar4", 16, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000104, 0x0006, 0, 
    0, 0 },
  { /* 0005 */ "ar5", 20, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000105, 0x0006, 0, 
    0, 0 },
  { /* 0006 */ "ar6", 24, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000106, 0x0006, 0, 
    0, 0 },
  { /* 0007 */ "ar7", 28, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000107, 0x0006, 0, 
    0, 0 },
  { /* 0008 */ "ar8", 32, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000108, 0x0006, 0, 
    0, 0 },
  { /* 0009 */ "ar9", 36, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000109, 0x0006, 0, 
    0, 0 },
  { /* 0010 */ "ar10", 40, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000010a, 0x0006, 0, 
    0, 0 },
  { /* 0011 */ "ar11", 44, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000010b, 0x0006, 0, 
    0, 0 },
  { /* 0012 */ "ar12", 48, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000010c, 0x0006, 0, 
    0, 0 },
  { /* 0013 */ "ar13", 52, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000010d, 0x0006, 0, 
    0, 0 },
  { /* 0014 */ "ar14", 56, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000010e, 0x0006, 0, 
    0, 0 },
  { /* 0015 */ "ar15", 60, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000010f, 0x0006, 0, 
    0, 0 },
  { /* 0016 */ "ar16", 64, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000110, 0x0006, 0, 
    0, 0 },
  { /* 0017 */ "ar17", 68, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000111, 0x0006, 0, 
    0, 0 },
  { /* 0018 */ "ar18", 72, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000112, 0x0006, 0, 
    0, 0 },
  { /* 0019 */ "ar19", 76, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000113, 0x0006, 0, 
    0, 0 },
  { /* 0020 */ "ar20", 80, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000114, 0x0006, 0, 
    0, 0 },
  { /* 0021 */ "ar21", 84, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000115, 0x0006, 0, 
    0, 0 },
  { /* 0022 */ "ar22", 88, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000116, 0x0006, 0, 
    0, 0 },
  { /* 0023 */ "ar23", 92, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000117, 0x0006, 0, 
    0, 0 },
  { /* 0024 */ "ar24", 96, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000118, 0x0006, 0, 
    0, 0 },
  { /* 0025 */ "ar25", 100, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000119, 0x0006, 0, 
    0, 0 },
  { /* 0026 */ "ar26", 104, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000011a, 0x0006, 0, 
    0, 0 },
  { /* 0027 */ "ar27", 108, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000011b, 0x0006, 0, 
    0, 0 },
  { /* 0028 */ "ar28", 112, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000011c, 0x0006, 0, 
    0, 0 },
  { /* 0029 */ "ar29", 116, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000011d, 0x0006, 0, 
    0, 0 },
  { /* 0030 */ "ar30", 120, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000011e, 0x0006, 0, 
    0, 0 },
  { /* 0031 */ "ar31", 124, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000011f, 0x0006, 0, 
    0, 0 },
  { /* 0032 */ "ar32", 128, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000120, 0x0006, 0, 
    0, 0 },
  { /* 0033 */ "ar33", 132, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000121, 0x0006, 0, 
    0, 0 },
  { /* 0034 */ "ar34", 136, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000122, 0x0006, 0, 
    0, 0 },
  { /* 0035 */ "ar35", 140, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000123, 0x0006, 0, 
    0, 0 },
  { /* 0036 */ "ar36", 144, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000124, 0x0006, 0, 
    0, 0 },
  { /* 0037 */ "ar37", 148, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000125, 0x0006, 0, 
    0, 0 },
  { /* 0038 */ "ar38", 152, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000126, 0x0006, 0, 
    0, 0 },
  { /* 0039 */ "ar39", 156, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000127, 0x0006, 0, 
    0, 0 },
  { /* 0040 */ "ar40", 160, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000128, 0x0006, 0, 
    0, 0 },
  { /* 0041 */ "ar41", 164, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000129, 0x0006, 0, 
    0, 0 },
  { /* 0042 */ "ar42", 168, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000012a, 0x0006, 0, 
    0, 0 },
  { /* 0043 */ "ar43", 172, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000012b, 0x0006, 0, 
    0, 0 },
  { /* 0044 */ "ar44", 176, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000012c, 0x0006, 0, 
    0, 0 },
  { /* 0045 */ "ar45", 180, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000012d, 0x0006, 0, 
    0, 0 },
  { /* 0046 */ "ar46", 184, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000012e, 0x0006, 0, 
    0, 0 },
  { /* 0047 */ "ar47", 188, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000012f, 0x0006, 0, 
    0, 0 },
  { /* 0048 */ "ar48", 192, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000130, 0x0006, 0, 
    0, 0 },
  { /* 0049 */ "ar49", 196, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000131, 0x0006, 0, 
    0, 0 },
  { /* 0050 */ "ar50", 200, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000132, 0x0006, 0, 
    0, 0 },
  { /* 0051 */ "ar51", 204, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000133, 0x0006, 0, 
    0, 0 },
  { /* 0052 */ "ar52", 208, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000134, 0x0006, 0, 
    0, 0 },
  { /* 0053 */ "ar53", 212, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000135, 0x0006, 0, 
    0, 0 },
  { /* 0054 */ "ar54", 216, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000136, 0x0006, 0, 
    0, 0 },
  { /* 0055 */ "ar55", 220, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000137, 0x0006, 0, 
    0, 0 },
  { /* 0056 */ "ar56", 224, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000138, 0x0006, 0, 
    0, 0 },
  { /* 0057 */ "ar57", 228, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x00000139, 0x0006, 0, 
    0, 0 },
  { /* 0058 */ "ar58", 232, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000013a, 0x0006, 0, 
    0, 0 },
  { /* 0059 */ "ar59", 236, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000013b, 0x0006, 0, 
    0, 0 },
  { /* 0060 */ "ar60", 240, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000013c, 0x0006, 0, 
    0, 0 },
  { /* 0061 */ "ar61", 244, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000013d, 0x0006, 0, 
    0, 0 },
  { /* 0062 */ "ar62", 248, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000013e, 0x0006, 0, 
    0, 0 },
  { /* 0063 */ "ar63", 252, xtRegisterTypeArRegfile, 0x2, 0, 
    32, 4, 4, 0x0000013f, 0x0006, 0, 
    0, 0 },
  { /* 0064 */ "lbeg", 256, xtRegisterTypeSpecialReg, 0x1100, 0, 
    32, 4, 4, 0x00000200, 0x0006, 0, 
    0, 0 },
  { /* 0065 */ "lend", 260, xtRegisterTypeSpecialReg, 0x1100, 0, 
    32, 4, 4, 0x00000201, 0x0006, 0, 
    0, 0 },
  { /* 0066 */ "lcount", 264, xtRegisterTypeSpecialReg, 0x1100, 0, 
    32, 4, 4, 0x00000202, 0x0006, 0, 
    0, 0 },
  { /* 0067 */ "ptevaddr", 268, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x00000253, 0x0007, 0, 
    0, 0 },
  { /* 0068 */ "ddr", 272, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x00000268, 0x0007, 0, 
    0, 0 },
  { /* 0069 */ "interrupt", 276, xtRegisterTypeSpecialReg, 0x1000, 0, 
    17, 4, 4, 0x000002e2, 0x000b, 0, 
    0, 0 },
  { /* 0070 */ "intset", 280, xtRegisterTypeSpecialReg, 0x1000, 0, 
    17, 4, 4, 0x000002e2, 0x000d, 0, 
    0, 0 },
  { /* 0071 */ "intclear", 284, xtRegisterTypeSpecialReg, 0x1000, 0, 
    17, 4, 4, 0x000002e3, 0x000d, 0, 
    0, 0 },
  { /* 0072 */ "ccount", 288, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002ea, 0x000f, 0, 
    0, 0 },
  { /* 0073 */ "prid", 292, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002eb, 0x0003, 0, 
    0, 0 },
  { /* 0074 */ "icount", 296, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002ec, 0x000f, 0, 
    0, 0 },
  { /* 0075 */ "ccompare0", 300, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002f0, 0x000f, 0, 
    0, 0 },
  { /* 0076 */ "ccompare1", 304, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002f1, 0x000f, 0, 
    0, 0 },
  { /* 0077 */ "ccompare2", 308, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002f2, 0x000f, 0, 
    0, 0 },
  { /* 0078 */ "epc1", 312, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002b1, 0x0007, 0, 
    0, 0 },
  { /* 0079 */ "epc2", 316, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002b2, 0x0007, 0, 
    0, 0 },
  { /* 0080 */ "epc3", 320, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002b3, 0x0007, 0, 
    0, 0 },
  { /* 0081 */ "epc4", 324, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002b4, 0x0007, 0, 
    0, 0 },
  { /* 0082 */ "excsave1", 328, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002d1, 0x0007, 0, 
    0, 0 },
  { /* 0083 */ "excsave2", 332, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002d2, 0x0007, 0, 
    0, 0 },
  { /* 0084 */ "excsave3", 336, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002d3, 0x0007, 0, 
    0, 0 },
  { /* 0085 */ "excsave4", 340, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002d4, 0x0007, 0, 
    0, 0 },
  { /* 0086 */ "eps2", 344, xtRegisterTypeSpecialReg, 0x1000, 0, 
    19, 4, 4, 0x000002c2, 0x0007, 0, 
    0, 0 },
  { /* 0087 */ "eps3", 348, xtRegisterTypeSpecialReg, 0x1000, 0, 
    19, 4, 4, 0x000002c3, 0x0007, 0, 
    0, 0 },
  { /* 0088 */ "eps4", 352, xtRegisterTypeSpecialReg, 0x1000, 0, 
    19, 4, 4, 0x000002c4, 0x0007, 0, 
    0, 0 },
  { /* 0089 */ "exccause", 356, xtRegisterTypeSpecialReg, 0x1000, 0, 
    6, 4, 4, 0x000002e8, 0x0007, 0, 
    0, 0 },
  { /* 0090 */ "depc", 360, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002c0, 0x0007, 0, 
    0, 0 },
  { /* 0091 */ "excvaddr", 364, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002ee, 0x0007, 0, 
    0, 0 },
  { /* 0092 */ "windowbase", 368, xtRegisterTypeSpecialReg, 0x1002, 0, 
    4, 4, 4, 0x00000248, 0x0007, 0, 
    0, 0 },
  { /* 0093 */ "windowstart", 372, xtRegisterTypeSpecialReg, 0x1002, 0, 
    16, 4, 4, 0x00000249, 0x0007, 0, 
    0, 0 },
  { /* 0094 */ "sar", 376, xtRegisterTypeSpecialReg, 0x1100, 0, 
    6, 4, 4, 0x00000203, 0x0006, 0, 
    0, 0 },
  { /* 0095 */ "litbase", 380, xtRegisterTypeSpecialReg, 0x1100, 0, 
    32, 4, 4, 0x00000205, 0x0006, 0, 
    0, 0 },
  { /* 0096 */ "ps", 384, xtRegisterTypeSpecialReg, 0x1100, 0, 
    19, 4, 4, 0x000002e6, 0x0007, 0, 
    0, 0 },
  { /* 0097 */ "misc0", 388, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002f4, 0x0007, 0, 
    0, 0 },
  { /* 0098 */ "misc1", 392, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002f5, 0x0007, 0, 
    0, 0 },
  { /* 0099 */ "intenable", 396, xtRegisterTypeSpecialReg, 0x1000, 0, 
    17, 4, 4, 0x000002e4, 0x0007, 0, 
    0, 0 },
  { /* 0100 */ "dbreaka0", 400, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x00000290, 0x0007, 0, 
    0, 0 },
  { /* 0101 */ "dbreakc0", 404, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002a0, 0x0007, 0, 
    0, 0 },
  { /* 0102 */ "dbreaka1", 408, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x00000291, 0x0007, 0, 
    0, 0 },
  { /* 0103 */ "dbreakc1", 412, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x000002a1, 0x0007, 0, 
    0, 0 },
  { /* 0104 */ "ibreaka0", 416, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x00000280, 0x0007, 0, 
    0, 0 },
  { /* 0105 */ "ibreaka1", 420, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x00000281, 0x0007, 0, 
    0, 0 },
  { /* 0106 */ "ibreakenable", 424, xtRegisterTypeSpecialReg, 0x1000, 0, 
    2, 4, 4, 0x00000260, 0x0007, 0, 
    0, 0 },
  { /* 0107 */ "icountlevel", 428, xtRegisterTypeSpecialReg, 0x1000, 0, 
    4, 4, 4, 0x000002ed, 0x0007, 0, 
    0, 0 },
  { /* 0108 */ "debugcause", 432, xtRegisterTypeSpecialReg, 0x1000, 0, 
    12, 4, 4, 0x000002e9, 0x0003, 0, 
    0, 0 },
  { /* 0109 */ "rasid", 436, xtRegisterTypeSpecialReg, 0x1000, 0, 
    32, 4, 4, 0x0000025a, 0x0007, 0, 
    0, 0 },
  { /* 0110 */ "itlbcfg", 440, xtRegisterTypeSpecialReg, 0x1000, 0, 
    18, 4, 4, 0x0000025b, 0x0007, 0, 
    0, 0 },
  { /* 0111 */ "dtlbcfg", 444, xtRegisterTypeSpecialReg, 0x1000, 0, 
    18, 4, 4, 0x0000025c, 0x0007, 0, 
    0, 0 },
  { /* 0112 */ "threadptr", 448, xtRegisterTypeUserReg, 0x110, 0, 
    32, 4, 4, 0x000003e7, 0x0006, 0, 
    0, 0 },
  { /* 0113 */ "pc", 452, xtRegisterTypeVirtual, 0x100, 0, 
    32, 4, 4, 0x00000020, 0x0006, 0, 
    0, 0 },
  { /* 0114 */ "a0", 456, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000000, 0x0006, 0, 
    0, 0 },
  { /* 0115 */ "a1", 460, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000001, 0x0006, 0, 
    0, 0 },
  { /* 0116 */ "a2", 464, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000002, 0x0006, 0, 
    0, 0 },
  { /* 0117 */ "a3", 468, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000003, 0x0006, 0, 
    0, 0 },
  { /* 0118 */ "a4", 472, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000004, 0x0006, 0, 
    0, 0 },
  { /* 0119 */ "a5", 476, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000005, 0x0006, 0, 
    0, 0 },
  { /* 0120 */ "a6", 480, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000006, 0x0006, 0, 
    0, 0 },
  { /* 0121 */ "a7", 484, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000007, 0x0006, 0, 
    0, 0 },
  { /* 0122 */ "a8", 488, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000008, 0x0006, 0, 
    0, 0 },
  { /* 0123 */ "a9", 492, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x00000009, 0x0006, 0, 
    0, 0 },
  { /* 0124 */ "a10", 496, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x0000000a, 0x0006, 0, 
    0, 0 },
  { /* 0125 */ "a11", 500, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x0000000b, 0x0006, 0, 
    0, 0 },
  { /* 0126 */ "a12", 504, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x0000000c, 0x0006, 0, 
    0, 0 },
  { /* 0127 */ "a13", 508, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x0000000d, 0x0006, 0, 
    0, 0 },
  { /* 0128 */ "a14", 512, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x0000000e, 0x0006, 0, 
    0, 0 },
  { /* 0129 */ "a15", 516, xtRegisterTypeWindow, 0x100, 0, 
    32, 4, 4, 0x0000000f, 0x0006, 0, 
    0, 0 },
  { /* 0130 */ "psintlevel", 520, xtRegisterTypeMapped, 0x1010, 0, 
    4, 4, 4, 0x00002004, 0x0006, &xtensa_mask0, 
    0, 0 },
  { /* 0131 */ "psum", 524, xtRegisterTypeMapped, 0x1010, 0, 
    1, 4, 4, 0x00002005, 0x0006, &xtensa_mask1, 
    0, 0 },
  { /* 0132 */ "pswoe", 528, xtRegisterTypeMapped, 0x1010, 0, 
    1, 4, 4, 0x00002006, 0x0006, &xtensa_mask2, 
    0, 0 },
  { /* 0133 */ "psring", 532, xtRegisterTypeMapped, 0x1010, 0, 
    2, 4, 4, 0x00002007, 0x0006, &xtensa_mask3, 
    0, 0 },
  { /* 0134 */ "psexcm", 536, xtRegisterTypeMapped, 0x1010, 0, 
    1, 4, 4, 0x00002008, 0x0006, &xtensa_mask4, 
    0, 0 },
  { /* 0135 */ "pscallinc", 540, xtRegisterTypeMapped, 0x1010, 0, 
    2, 4, 4, 0x00002009, 0x0006, &xtensa_mask5, 
    0, 0 },
  { /* 0136 */ "psowb", 544, xtRegisterTypeMapped, 0x1010, 0, 
    4, 4, 4, 0x0000200a, 0x0006, &xtensa_mask6, 
    0, 0 },
  { /* 0137 */ "litbaddr", 548, xtRegisterTypeMapped, 0x1010, 0, 
    20, 4, 4, 0x0000200b, 0x0006, &xtensa_mask7, 
    0, 0 },
  { /* 0138 */ "litben", 552, xtRegisterTypeMapped, 0x1010, 0, 
    1, 4, 4, 0x0000200c, 0x0006, &xtensa_mask8, 
    0, 0 },
  { /* 0139 */ "dbnum", 556, xtRegisterTypeMapped, 0x1010, 0, 
    4, 4, 4, 0x00002011, 0x0006, &xtensa_mask9, 
    0, 0 },
  { /* 0140 */ "asid3", 560, xtRegisterTypeMapped, 0x1010, 0, 
    8, 4, 4, 0x00002012, 0x0006, &xtensa_mask10, 
    0, 0 },
  { /* 0141 */ "asid2", 564, xtRegisterTypeMapped, 0x1010, 0, 
    8, 4, 4, 0x00002013, 0x0006, &xtensa_mask11, 
    0, 0 },
  { /* 0142 */ "asid1", 568, xtRegisterTypeMapped, 0x1010, 0, 
    8, 4, 4, 0x00002014, 0x0006, &xtensa_mask12, 
    0, 0 },
  { /* 0143 */ "instpgszid4", 572, xtRegisterTypeMapped, 0x1010, 0, 
    2, 4, 4, 0x00002015, 0x0006, &xtensa_mask13, 
    0, 0 },
  { /* 0144 */ "datapgszid4", 576, xtRegisterTypeMapped, 0x1010, 0, 
    2, 4, 4, 0x00002016, 0x0006, &xtensa_mask14, 
    0, 0 },
  { /* 0145 */ "ptbase", 580, xtRegisterTypeMapped, 0x1010, 0, 
    10, 4, 4, 0x00002017, 0x0006, &xtensa_mask15, 
    0, 0 },
};


struct gdbarch_tdep xtensa_tdep =
{
  /* target_flags */			0,
  /* spill_location */			-1,
  /* spill_size */			0,
  /* unused */				0,
  /* call_abi */			0,
  /* debug_interrupt_level */		XCHAL_DEBUGLEVEL,
  /* icache_line_bytes */		XCHAL_ICACHE_LINESIZE,
  /* dcache_line_bytes */		XCHAL_DCACHE_LINESIZE,
  /* dcache_writeback */		XCHAL_DCACHE_IS_WRITEBACK,
  /* isa_use_windowed_registers */	XCHAL_HAVE_WINDOWED,
  /* isa_use_density_instructions */	XCHAL_HAVE_DENSITY,
  /* isa_use_exceptions */		1,
  /* isa_use_ext_l32r */		0 /* XCHAL_USE_ABSOLUTE_LITERALS */,
  /* isa_max_insn_size */		3,
  /* debug_num_ibreaks */		XCHAL_NUM_IBREAK,
  /* debug_num_dbreaks */		XCHAL_NUM_DBREAK,
  /* rmap */				rmap,
  /* num_regs */			114,
  /* num_pseudo_regs */			32,
  /* num_aregs */			64,
  /* num_contexts */			0,
  /* ar_base */				0,
  /* a0_base */				114,
  /* wb_regnum */			92,
  /* ws_regnum */			93,
  /* pc_regnum */			113,
  /* ps_regnum */			96,
  /* lbeg_regnum */			64,
  /* lend_regnum */			65,
  /* lcount_regnum */			66,
  /* sar_regnum */			94,
  /* litbase_regnum */			0,
  /* debugcause_regnum */		108,
  /* exccause_regnum */			89,
  /* excvaddr_regnum */			91,
  /* max_register_raw_size */		4,
  /* max_register_virtual_size */	4,
  /* fp_layout */			0,
  /* fp_layout_bytes */			0,
  /* gregmap */				0
};
