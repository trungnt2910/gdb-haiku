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
#include "inferior.h"
#include "nat/haiku-nat.h"
#include "objfiles.h"
#include "solib-haiku.h"
#include "solist.h"

/* For other targets, the solib implementation usually reads hints from the
   dynamic linker in the active address space, which could be anything from a
   core file to a live inferior.

   Haiku's runtime_loader does not export such information. The nearest
   we have is the static variable sLoadedImages. We therefore have to rely on
   what the loader has registered to the kernel for a living process and read
   that through get_next_image_info.

   This should suffice for now since Haiku does not support core files yet.  */

static void
haiku_relocate_main_executable ()
{
  inferior *inf = find_inferior_for_program_space (current_program_space);

  if (inf == nullptr)
    return;

  CORE_ADDR text;
  CORE_ADDR data;

  if (haiku_nat::read_offsets (inf->pid, &text, &data) < 0)
    return;

  CORE_ADDR displacement = text;

  objfile *objf = current_program_space->symfile_object_file;
  if (objf)
    {
      section_offsets new_offsets (objf->section_offsets.size (),
                                   displacement);
      objfile_relocate (objf, new_offsets);
    }
  else if (current_program_space->exec_bfd ())
    {
      asection *asect;

      bfd *exec_bfd = current_program_space->exec_bfd ();
      for (asect = exec_bfd->sections; asect != NULL; asect = asect->next)
        exec_set_section_address (bfd_get_filename (exec_bfd), asect->index,
                                  bfd_section_vma (asect) + displacement);
    }
}

static void
haiku_relocate_section_addresses (struct so_list *so,
                                  struct target_section *sec)
{
  CORE_ADDR displacement = so->addr_low;

  sec->addr += displacement;
  sec->endaddr += displacement;
}

static void
haiku_free_so (struct so_list *so)
{
  /* No-op.  */
}

static void
haiku_clear_so (struct so_list *so)
{
  /* No-op.  */
}

static void
haiku_clear_solib ()
{
  /* No-op.  */
}

static void
haiku_solib_create_inferior_hook (int from_tty)
{
  haiku_relocate_main_executable ();
}

static struct so_list *
haiku_current_sos ()
{
  inferior *inf = find_inferior_for_program_space (current_program_space);

  if (inf == nullptr)
    return nullptr;

  struct so_list *head = nullptr;
  struct so_list *tail = nullptr;

  haiku_nat::for_each_image (inf->pid, [&] (
                                           const haiku_nat::image_info &info) {
    /* Skip the main executable.  */
    if (info.is_main_executable)
      return 0;

    struct so_list *newso = XCNEW (struct so_list);

    strncpy (newso->so_original_name, info.name, SO_NAME_MAX_PATH_SIZE - 1);
    newso->so_original_name[SO_NAME_MAX_PATH_SIZE - 1] = '\0';
    strcpy (newso->so_name, newso->so_original_name);

    newso->addr_low = info.text;
    newso->addr_high = info.data + info.data_size;

    if (head == nullptr)
      head = newso;

    if (tail != nullptr)
      tail->next = newso;

    tail = newso;

    return 0;
  });

  return head;
}

static int
haiku_open_symbol_file_object (int from_ttyp)
{
  /* Generally unused.  */
  return 0;
}

static int
haiku_in_dynsym_resolve_code (CORE_ADDR pc)
{
  /* No dynamic resolving implemented in Haiku yet.  */
  return 0;
}

const struct target_so_ops haiku_so_ops =
{
  .relocate_section_addresses = haiku_relocate_section_addresses,
  .free_so = haiku_free_so,
  .clear_so = haiku_clear_so,
  .clear_solib = haiku_clear_solib,
  .solib_create_inferior_hook = haiku_solib_create_inferior_hook,
  .current_sos = haiku_current_sos,
  .open_symbol_file_object = haiku_open_symbol_file_object,
  .in_dynsym_resolve_code = haiku_in_dynsym_resolve_code,
  .bfd_open = solib_bfd_open,
  // TODO: Set the B_TEAM_DEBUG_IMAGES flag.
  // .update_breakpoints = haiku_update_breakpoints,
};
