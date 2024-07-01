/* Common target-dependent definitions for Haiku systems.

   Copyright (C) 2024 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef HAIKU_TDEP_H
#define HAIKU_TDEP_H

#include "gdb_bfd.h"

/* Derived from headers/private/system/commpage_defs.h.  */
#define HAIKU_COMMPAGE_SIZE (0x8000)

/* Haiku specific set of ABI-related routines.  */

void haiku_init_abi (struct gdbarch_info, struct gdbarch *);

/* Used by OS ABI sniffers to check for Haiku-specific symbols.  */

bool haiku_check_required_symbols (struct bfd *);

/* Opens the virtual commpage image.  */

gdb_bfd_ref_ptr haiku_bfd_open_commpage ();

/* Gets the commpage address from the target.  */

CORE_ADDR haiku_get_commpage_address ();

#endif /* HAIKU_TDEP_H */
