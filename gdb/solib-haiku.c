/* Handle shared libraries for GDB, the GNU Debugger.

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

#include "exec.h"
#include "haiku-tdep.h"
#include "inferior.h"
#include "objfiles.h"
#include "solib-haiku.h"
#include "solib-target.h"
#include "solist.h"

/* For other targets, the solib implementation usually reads hints from the
   dynamic linker in the active address space, which could be anything from a
   core file to a live inferior.

   Haiku's runtime_loader does not export such information. The nearest
   we have is the static variable sLoadedImages. We therefore have to rely on
   what the target reports.

   This is basically a wrapper around solib-target.c.  */

static void
haiku_relocate_section_addresses (solib &so, struct target_section *sec)
{
  if (so.so_name == "commpage")
  {
    CORE_ADDR commpage_address = haiku_get_commpage_address ();
    sec->addr = commpage_address;
    sec->endaddr = commpage_address + HAIKU_COMMPAGE_SIZE;

    so.addr_low = commpage_address;
    so.addr_high = commpage_address + HAIKU_COMMPAGE_SIZE;
  }
  else
  {
    solib_target_so_ops.relocate_section_addresses (so, sec);
  }
}

static void
haiku_clear_so (const solib &so)
{
  if (solib_target_so_ops.clear_so != nullptr)
    solib_target_so_ops.clear_so (so);
}

static void
haiku_clear_solib (program_space *pspace)
{
  if (solib_target_so_ops.clear_solib != nullptr)
    solib_target_so_ops.clear_solib (pspace);
}

static void
haiku_solib_create_inferior_hook (int from_tty)
{
  solib_target_so_ops.solib_create_inferior_hook (from_tty);
}

static intrusive_list<solib>
haiku_current_sos ()
{
  return solib_target_so_ops.current_sos ();
}

static int
haiku_open_symbol_file_object (int from_tty)
{
  return solib_target_so_ops.open_symbol_file_object (from_tty);
}

static int
haiku_in_dynsym_resolve_code (CORE_ADDR pc)
{
  /* No dynamic resolving implemented in Haiku yet.
     Return what the generic code has to say.  */
  return solib_target_so_ops.in_dynsym_resolve_code (pc);
}

static gdb_bfd_ref_ptr
haiku_bfd_open (const char *pathname)
{
  if (strcmp (pathname, "commpage") == 0)
    return haiku_bfd_open_commpage ();
  return solib_target_so_ops.bfd_open (pathname);
}

const struct solib_ops haiku_so_ops = {
  .relocate_section_addresses = haiku_relocate_section_addresses,
  .clear_so = haiku_clear_so,
  .clear_solib = haiku_clear_solib,
  .solib_create_inferior_hook = haiku_solib_create_inferior_hook,
  .current_sos = haiku_current_sos,
  .open_symbol_file_object = haiku_open_symbol_file_object,
  .in_dynsym_resolve_code = haiku_in_dynsym_resolve_code,
  .bfd_open = haiku_bfd_open,
};
