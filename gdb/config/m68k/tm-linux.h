/* Definitions to target GDB to GNU/Linux on m680x0.

   Copyright 1996, 1998, 1999, 2000, 2002, 2003 Free Software Foundation,
   Inc.

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

#include "config/tm-linux.h"
#include "m68k/tm-m68k.h"

#include "regcache.h"

/* Number of traps that happen between exec'ing the shell to run an
   inferior, and when we finally get to the inferior code.  This is 2
   on most implementations.  */

#define START_INFERIOR_TRAPS_EXPECTED 2

/* Offsets (in target ints) into jmp_buf.  */

#define JB_ELEMENT_SIZE 4
#define JB_PC 7

/* Figure out where the longjmp will land.  Slurp the args out of the stack.
   We expect the first arg to be a pointer to the jmp_buf structure from which
   we extract the pc (JB_PC) that we will land at.  The pc is copied into ADDR.
   This routine returns true on success */

#define GET_LONGJMP_TARGET(ADDR) m68k_get_longjmp_target(ADDR)

#define IN_SIGTRAMP(pc,name) m68k_linux_in_sigtramp (pc)
extern int m68k_linux_in_sigtramp (CORE_ADDR pc);
