/* Macro definitions for ARM running under NetBSD.
   Copyright 1994, 1999 Free Software Foundation, Inc.

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

#ifndef TM_NBSD_H
#define TM_NBSD_H

#include "arm/tm-arm.h"
#include "tm-nbsd.h"

#define JB_ELEMENT_SIZE sizeof(long)	/* jmp_buf[_JBLEN] is array of ints */
#define JB_PC	24		/* Setjmp()'s return PC saved here */

/* Return non-zero if inside a shared-library entry stub.  */
#undef IN_SOLIB_CALL_TRAMPOLINE
#define IN_SOLIB_CALL_TRAMPOLINE(pc, name) \
  STREQ ((name), "_PROCEDURE_LINKAGE_TABLE_")

/* Figure out where the longjmp will land.  Slurp the args out of the stack.
   We expect the first arg to be a pointer to the jmp_buf structure from which
   we extract the pc (JB_PC) that we will land at.  The pc is copied into ADDR.
   This routine returns true on success */

extern int
get_longjmp_target (CORE_ADDR *);

#define GET_LONGJMP_TARGET(ADDR) get_longjmp_target(ADDR)

/* By convention, NetBSD uses the "other" register names. */
#define DEFAULT_REGISTER_NAMES additional_register_names

#endif /* TM_NBSD_H */
