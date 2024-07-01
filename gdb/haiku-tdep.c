/* Common target-dependent code for Haiku systems.

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

#include "defs.h"

#include "bfd.h"
#include "gdbarch.h"
#include "haiku-tdep.h"
#include "solib-haiku.h"

/* See haiku-tdep.h.  */

void
haiku_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  set_gdbarch_so_ops (gdbarch, &haiku_so_ops);
}

/* See haiku-tdep.h.  */

bool
haiku_check_required_symbols (bfd *abfd)
{
  long storage_needed = bfd_get_symtab_upper_bound (abfd);
  if (storage_needed <= 0)
    return false;

  gdb::unique_xmalloc_ptr<asymbol *> symbol_table (
      (asymbol **)xmalloc (storage_needed));
  long number_of_symbols = bfd_canonicalize_symtab (abfd, symbol_table.get ());

  if (number_of_symbols <= 0)
    return false;

  for (long i = 0; i < number_of_symbols; ++i)
    {
      const char *name = bfd_asymbol_name (symbol_table.get ()[i]);

      if (strcmp (name, "_gSharedObjectHaikuVersion") == 0)
        return true;
    }

  return false;
}
