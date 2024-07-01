/* Target-dependent code for Haiku/amd64.

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

#include "amd64-tdep.h"
#include "haiku-tdep.h"

static void
amd64_haiku_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  i386_gdbarch_tdep *tdep = gdbarch_tdep<i386_gdbarch_tdep> (gdbarch);

  amd64_init_abi (info, gdbarch,
                  amd64_target_description (X86_XSTATE_SSE_MASK, true));
  haiku_init_abi (info, gdbarch);

  /* The offset of the PC in the jmp_buf structure.
     Found at src/system/libroot/posix/arch/x86_64/setjmp_internal.h.  */
  tdep->jb_pc_offset = 0;
}

static enum gdb_osabi
amd64_haiku_osabi_sniffer (bfd *abfd)
{
  const char *target_name = bfd_get_target (abfd);

  if (strcmp (target_name, "elf64-x86-64") != 0)
    return GDB_OSABI_UNKNOWN;

  if (!haiku_check_required_symbols (abfd))
    return GDB_OSABI_UNKNOWN;

  return GDB_OSABI_HAIKU;
}

void _initialize_amd64_haiku_tdep ();
void
_initialize_amd64_haiku_tdep ()
{
  gdbarch_register_osabi_sniffer (bfd_arch_i386, bfd_target_elf_flavour,
                                  amd64_haiku_osabi_sniffer);

  gdbarch_register_osabi (bfd_arch_i386, bfd_mach_x86_64, GDB_OSABI_HAIKU,
                          amd64_haiku_init_abi);
}
