/* Target-dependent code for the IA-64 for GDB, the GNU debugger.
   Copyright 2000, 2004
   Free Software Foundation, Inc.

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
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include "defs.h"
#include "arch-utils.h"
#include "gdbcore.h"

/* The sigtramp code is in a non-readable (executable-only) region
   of memory called the ``gate page''.  The addresses in question
   were determined by examining the system headers.  They are
   overly generous to allow for different pages sizes. */

#define GATE_AREA_START 0xa000000000000100LL
#define GATE_AREA_END   0xa000000000020000LL

/* Offset to sigcontext structure from frame of handler */
#define IA64_LINUX_SIGCONTEXT_OFFSET 192

int
ia64_linux_in_sigtramp (CORE_ADDR pc, char *func_name)
{
  return (pc >= (CORE_ADDR) GATE_AREA_START && pc < (CORE_ADDR) GATE_AREA_END);
}

/* IA-64 GNU/Linux specific function which, given a frame address and
   a register number, returns the address at which that register may be
   found.  0 is returned for registers which aren't stored in the the
   sigcontext structure. */

CORE_ADDR
ia64_linux_sigcontext_register_address (CORE_ADDR sp, int regno)
{
  char buf[8];
  CORE_ADDR sigcontext_addr = 0;

  /* The address of the sigcontext area is found at offset 16 in the sigframe.  */
  read_memory (sp + 16, buf, 8);
  sigcontext_addr = extract_unsigned_integer (buf, 8);

  if (IA64_GR0_REGNUM <= regno && regno <= IA64_GR31_REGNUM)
    return sigcontext_addr + 200 + 8 * (regno - IA64_GR0_REGNUM);
  else if (IA64_BR0_REGNUM <= regno && regno <= IA64_BR7_REGNUM)
    return sigcontext_addr + 136 + 8 * (regno - IA64_BR0_REGNUM);
  else if (IA64_FR0_REGNUM <= regno && regno <= IA64_FR127_REGNUM)
    return sigcontext_addr + 464 + 16 * (regno - IA64_FR0_REGNUM);
  else
    switch (regno)
      {
      case IA64_IP_REGNUM :
	return sigcontext_addr + 40;
      case IA64_CFM_REGNUM :
	return sigcontext_addr + 48;
      case IA64_PSR_REGNUM :
	return sigcontext_addr + 56;		/* user mask only */
      /* sc_ar_rsc is provided, from which we could compute bspstore, but
	 I don't think it's worth it.  Anyway, if we want it, it's at offset
	 64 */
      case IA64_BSP_REGNUM :
	return sigcontext_addr + 72;
      case IA64_RNAT_REGNUM :
	return sigcontext_addr + 80;
      case IA64_CCV_REGNUM :
	return sigcontext_addr + 88;
      case IA64_UNAT_REGNUM :
	return sigcontext_addr + 96;
      case IA64_FPSR_REGNUM :
	return sigcontext_addr + 104;
      case IA64_PFS_REGNUM :
	return sigcontext_addr + 112;
      case IA64_LC_REGNUM :
	return sigcontext_addr + 120;
      case IA64_PR_REGNUM :
	return sigcontext_addr + 128;
      default :
	return 0;
      }
}
