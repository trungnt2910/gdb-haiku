/* This file is tc-z8k.h
   Copyright 1987, 1988, 1989, 1990, 1991, 1992, 1993, 1995, 1997, 1998,
   2000, 2002, 2003, 2005
   Free Software Foundation, Inc.

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#define TC_Z8K
#define TARGET_BYTES_BIG_ENDIAN 1

struct internal_reloc;

#define WORKING_DOT_WORD

#define COFF_MAGIC 0x8000
#define IGNORE_NONSTANDARD_ESCAPES
#undef WARN_SIGNED_OVERFLOW_WORD

#define TC_RELOC_MANGLE(s,a,b,c) tc_reloc_mangle(a,b,c)
extern void tc_reloc_mangle
  PARAMS ((struct fix *, struct internal_reloc *, bfd_vma));

#define LISTING_HEADER "Zilog Z8000 GAS "
#define RELOC_32 1234

#define md_operand(x)
