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

/* Haiku specific set of ABI-related routines.  */

void haiku_init_abi (struct gdbarch_info, struct gdbarch *);

/* Used by OS ABI sniffers to check for Haiku-specific symbols.  */
bool haiku_check_required_symbols (struct bfd *abfd);

#endif /* HAIKU_TDEP_H */
