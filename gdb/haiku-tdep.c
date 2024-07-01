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
#include "elf-bfd.h"
#include "gdbarch.h"
#include "haiku-tdep.h"
#include "inferior.h"
#include "osdata.h"
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

/* See haiku-tdep.h.  */

gdb_bfd_ref_ptr
haiku_bfd_open_commpage ()
{
  /* Get any valid BFD object as a template.
     Otherwise, GDB will complain with a segfault.  */
  bfd *tmpbfd = current_inferior ()->pspace->exec_bfd ();
  if (tmpbfd == nullptr)
    tmpbfd = current_inferior ()->pspace->core_bfd ();
  if (tmpbfd == nullptr)
    return nullptr;

  /* Create a hollow BFD object.  */
  bfd *nbfd = bfd_create ("commpage", tmpbfd);
  if (nbfd == nullptr)
    return nullptr;

  /* Close in case of failure.  */
  std::unique_ptr<bfd, decltype (&bfd_close)> bfd_deleter (nbfd, bfd_close);

  /* Prepare the BFD for writing.  */
  if (!bfd_make_writable (nbfd))
    return nullptr;

  asection *section = bfd_make_section (nbfd, ".text");
  section->size = HAIKU_COMMPAGE_SIZE;

  /* Read the commpage symbols from the target.  */
  std::unique_ptr<osdata> comm_data = get_osdata ("comm");
  gdb_assert (comm_data->type == "comm");

  size_t sym_count = comm_data->items.size ();

  asymbol **symtab
      = (asymbol **)bfd_alloc (nbfd, (sym_count + 1) * sizeof (asymbol *));

  for (size_t i = 0; i < sym_count; ++i)
    {
      elf_symbol_type *sym = (elf_symbol_type *)bfd_make_empty_symbol (nbfd);
      sym->symbol.section = section;

      for (const auto &[name, value] : comm_data->items[i].columns)
        {
          if (name == "name")
            {
              char *tmp = (char *)bfd_alloc (nbfd, value.size () + 1);
              memcpy (tmp, value.c_str (), value.size () + 1);
              bfd_set_asymbol_name (&sym->symbol, tmp);
            }
          else if (name == "value")
            {
              sym->symbol.value = strtoulst (value.c_str (), nullptr, 10);
              sym->internal_elf_sym.st_value = sym->symbol.value;
            }
          else if (name == "size")
            {
              sym->internal_elf_sym.st_size
                  = strtoulst (value.c_str (), nullptr, 10);
            }
          else if (name == "type")
            {
              sym->symbol.flags = BSF_GLOBAL;
              for (char flag : value)
                {
                  switch (flag)
                    {
                    case 'f':
                      sym->symbol.flags |= BSF_FUNCTION;
                      break;
                    case 'o':
                      sym->symbol.flags |= BSF_OBJECT;
                      break;
                    }
                }
            }
        }

      symtab[i] = (asymbol *)sym;
    }

  symtab[sym_count] = nullptr;

  /* Write the symbol table.  */
  if (!bfd_set_symtab (nbfd, symtab, sym_count))
    return nullptr;

  /* Prepare the BFD for reading by GDB.  */
  if (!bfd_make_readable (nbfd))
    return nullptr;

  bfd_deleter.release ();

  return gdb_bfd_ref_ptr::new_reference (nbfd);
}

/* See haiku-tdep.h.  */

CORE_ADDR
haiku_get_commpage_address ()
{
  /* Read the images from the target.  */
  std::unique_ptr<osdata> images = get_osdata ("images");
  gdb_assert (images->type == "images");

  std::string current_team = std::to_string (current_inferior ()->pid);

  for (const auto &item : images->items)
    {
      bool matches_team = false;
      bool matches_name = false;
      const char *text_value = nullptr;

      for (const auto &[name, value] : item.columns)
        {
          if (name == "team")
            matches_team = value == current_team;
          else if (name == "name")
            matches_name = value == "commpage";
          else if (name == "text")
            text_value = value.c_str ();
        }

      if (matches_team && matches_name && text_value != nullptr)
        return string_to_core_addr (text_value);
    }

  return 0;
}
