/* Target-dependent code for Haiku/i386.

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

#include "haiku-tdep.h"
#include "i386-tdep.h"

static void
i386_haiku_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  i386_gdbarch_tdep *tdep = gdbarch_tdep<i386_gdbarch_tdep> (gdbarch);

  i386_elf_init_abi (info, gdbarch);
  haiku_init_abi (info, gdbarch);

  /* The offset of the PC in the jmp_buf structure.
     Found at src/system/libroot/posix/arch/x86/setjmp_internal.h.  */
  tdep->jb_pc_offset = 20;
}

static enum gdb_osabi
i386_haiku_osabi_sniffer (bfd *abfd)
{
  const char *target_name = bfd_get_target (abfd);

  if (strcmp (target_name, "elf32-i386") != 0)
    return GDB_OSABI_UNKNOWN;

  if (!haiku_check_required_symbols (abfd))
    return GDB_OSABI_UNKNOWN;

  return GDB_OSABI_HAIKU;
}

void _initialize_i386_haiku_tdep ();
void
_initialize_i386_haiku_tdep ()
{
  gdbarch_register_osabi_sniffer (bfd_arch_i386, bfd_target_elf_flavour,
                                  i386_haiku_osabi_sniffer);

  gdbarch_register_osabi (bfd_arch_i386, 0, GDB_OSABI_HAIKU,
                          i386_haiku_init_abi);
}
