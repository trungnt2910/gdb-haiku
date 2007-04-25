/* Low level Alpha GNU/Linux interface, for GDB when running native.
   Copyright (C) 2005, 2006, 2007 Free Software Foundation, Inc.

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

#include "defs.h"
#include "target.h"
#include "linux-nat.h"
#include "gdbcore.h"

static CORE_ADDR
alpha_linux_register_u_offset (int regno)
{
  /* FIXME drow/2005-09-04: The hardcoded use of register_addr should go
     away.  This requires disentangling the various definitions of it
     (particularly alpha-nat.c's).  */
  return register_addr (regno, 0);
}

void _initialialize_alpha_linux_nat (void);

void
_initialize_alpha_linux_nat (void)
{
  linux_nat_add_target (linux_trad_target (alpha_linux_register_u_offset));
}
