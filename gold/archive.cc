// archive.cc -- archive support for gold

// Copyright 2006, 2007, 2008 Free Software Foundation, Inc.
// Written by Ian Lance Taylor <iant@google.com>.

// This file is part of gold.

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
// MA 02110-1301, USA.

#include "gold.h"

#include <cerrno>
#include <cstring>
#include <climits>
#include <vector>
#include "libiberty.h"
#include "filenames.h"

#include "elfcpp.h"
#include "options.h"
#include "mapfile.h"
#include "fileread.h"
#include "readsyms.h"
#include "symtab.h"
#include "object.h"
#include "archive.h"

namespace gold
{

// The header of an entry in the archive.  This is all readable text,
// padded with spaces where necesary.  If the contents of an archive
// are all text file, the entire archive is readable.

struct Archive::Archive_header
{
  // The entry name.
  char ar_name[16];
  // The file modification time.
  char ar_date[12];
  // The user's UID in decimal.
  char ar_uid[6];
  // The user's GID in decimal.
  char ar_gid[6];
  // The file mode in octal.
  char ar_mode[8];
  // The file size in decimal.
  char ar_size[10];
  // The final magic code.
  char ar_fmag[2];
};

// Archive methods.

const char Archive::armag[sarmag] =
{
  '!', '<', 'a', 'r', 'c', 'h', '>', '\n'
};

const char Archive::armagt[sarmag] =
{
  '!', '<', 't', 'h', 'i', 'n', '>', '\n'
};

const char Archive::arfmag[2] = { '`', '\n' };

// Set up the archive: read the symbol map and the extended name
// table.

void
Archive::setup()
{
  // We need to ignore empty archives.
  if (this->input_file_->file().filesize() == sarmag)
    return;

  // The first member of the archive should be the symbol table.
  std::string armap_name;
  section_size_type armap_size =
    convert_to_section_size_type(this->read_header(sarmag, false,
						   &armap_name, NULL));
  off_t off = sarmag;
  if (armap_name.empty())
    {
      this->read_armap(sarmag + sizeof(Archive_header), armap_size);
      off = sarmag + sizeof(Archive_header) + armap_size;
    }
  else if (!this->input_file_->options().whole_archive())
    gold_error(_("%s: no archive symbol table (run ranlib)"),
	       this->name().c_str());

  // See if there is an extended name table.  We cache these views
  // because it is likely that we will want to read the following
  // header in the add_symbols routine.
  if ((off & 1) != 0)
    ++off;
  std::string xname;
  section_size_type extended_size =
    convert_to_section_size_type(this->read_header(off, true, &xname, NULL));
  if (xname == "/")
    {
      const unsigned char* p = this->get_view(off + sizeof(Archive_header),
                                              extended_size, false, true);
      const char* px = reinterpret_cast<const char*>(p);
      this->extended_names_.assign(px, extended_size);
    }
}

// Unlock any nested archives.

void
Archive::unlock_nested_archives()
{
  for (Nested_archive_table::iterator p = this->nested_archives_.begin();
       p != this->nested_archives_.end();
       ++p)
    {
      p->second->unlock(this->task_);
    }
}

// Read the archive symbol map.

void
Archive::read_armap(off_t start, section_size_type size)
{
  // Read in the entire armap.
  const unsigned char* p = this->get_view(start, size, true, false);

  // Numbers in the armap are always big-endian.
  const elfcpp::Elf_Word* pword = reinterpret_cast<const elfcpp::Elf_Word*>(p);
  unsigned int nsyms = elfcpp::Swap<32, true>::readval(pword);
  ++pword;

  // Note that the addition is in units of sizeof(elfcpp::Elf_Word).
  const char* pnames = reinterpret_cast<const char*>(pword + nsyms);
  section_size_type names_size =
    reinterpret_cast<const char*>(p) + size - pnames;
  this->armap_names_.assign(pnames, names_size);

  this->armap_.resize(nsyms);

  section_offset_type name_offset = 0;
  for (unsigned int i = 0; i < nsyms; ++i)
    {
      this->armap_[i].name_offset = name_offset;
      this->armap_[i].file_offset = elfcpp::Swap<32, true>::readval(pword);
      name_offset += strlen(pnames + name_offset) + 1;
      ++pword;
    }

  if (static_cast<section_size_type>(name_offset) > names_size)
    gold_error(_("%s: bad archive symbol table names"),
	       this->name().c_str());

  // This array keeps track of which symbols are for archive elements
  // which we have already included in the link.
  this->armap_checked_.resize(nsyms);
}

// Read the header of an archive member at OFF.  Fail if something
// goes wrong.  Return the size of the member.  Set *PNAME to the name
// of the member.

off_t
Archive::read_header(off_t off, bool cache, std::string* pname,
                     off_t* nested_off)
{
  const unsigned char* p = this->get_view(off, sizeof(Archive_header), true,
					  cache);
  const Archive_header* hdr = reinterpret_cast<const Archive_header*>(p);
  return this->interpret_header(hdr, off,  pname, nested_off);
}

// Interpret the header of HDR, the header of the archive member at
// file offset OFF.  Fail if something goes wrong.  Return the size of
// the member.  Set *PNAME to the name of the member.

off_t
Archive::interpret_header(const Archive_header* hdr, off_t off,
                          std::string* pname, off_t* nested_off)
{
  if (memcmp(hdr->ar_fmag, arfmag, sizeof arfmag) != 0)
    {
      gold_error(_("%s: malformed archive header at %zu"),
		 this->name().c_str(), static_cast<size_t>(off));
      return this->input_file_->file().filesize() - off;
    }

  const int size_string_size = sizeof hdr->ar_size;
  char size_string[size_string_size + 1];
  memcpy(size_string, hdr->ar_size, size_string_size);
  char* ps = size_string + size_string_size;
  while (ps[-1] == ' ')
    --ps;
  *ps = '\0';

  errno = 0;
  char* end;
  off_t member_size = strtol(size_string, &end, 10);
  if (*end != '\0'
      || member_size < 0
      || (member_size == LONG_MAX && errno == ERANGE))
    {
      gold_error(_("%s: malformed archive header size at %zu"),
		 this->name().c_str(), static_cast<size_t>(off));
      return this->input_file_->file().filesize() - off;
    }

  if (hdr->ar_name[0] != '/')
    {
      const char* name_end = strchr(hdr->ar_name, '/');
      if (name_end == NULL
	  || name_end - hdr->ar_name >= static_cast<int>(sizeof hdr->ar_name))
	{
	  gold_error(_("%s: malformed archive header name at %zu"),
		     this->name().c_str(), static_cast<size_t>(off));
	  return this->input_file_->file().filesize() - off;
	}
      pname->assign(hdr->ar_name, name_end - hdr->ar_name);
      if (nested_off != NULL)
        *nested_off = 0;
    }
  else if (hdr->ar_name[1] == ' ')
    {
      // This is the symbol table.
      pname->clear();
    }
  else if (hdr->ar_name[1] == '/')
    {
      // This is the extended name table.
      pname->assign(1, '/');
    }
  else
    {
      errno = 0;
      long x = strtol(hdr->ar_name + 1, &end, 10);
      long y = 0;
      if (*end == ':')
        y = strtol(end + 1, &end, 10);
      if (*end != ' '
	  || x < 0
	  || (x == LONG_MAX && errno == ERANGE)
	  || static_cast<size_t>(x) >= this->extended_names_.size())
	{
	  gold_error(_("%s: bad extended name index at %zu"),
		     this->name().c_str(), static_cast<size_t>(off));
	  return this->input_file_->file().filesize() - off;
	}

      const char* name = this->extended_names_.data() + x;
      const char* name_end = strchr(name, '\n');
      if (static_cast<size_t>(name_end - name) > this->extended_names_.size()
	  || name_end[-1] != '/')
	{
	  gold_error(_("%s: bad extended name entry at header %zu"),
		     this->name().c_str(), static_cast<size_t>(off));
	  return this->input_file_->file().filesize() - off;
	}
      pname->assign(name, name_end - 1 - name);
      if (nested_off != NULL)
        *nested_off = y;
    }

  return member_size;
}

// Select members from the archive and add them to the link.  We walk
// through the elements in the archive map, and look each one up in
// the symbol table.  If it exists as a strong undefined symbol, we
// pull in the corresponding element.  We have to do this in a loop,
// since pulling in one element may create new undefined symbols which
// may be satisfied by other objects in the archive.

void
Archive::add_symbols(Symbol_table* symtab, Layout* layout,
		     Input_objects* input_objects, Mapfile* mapfile)
{
  if (this->input_file_->options().whole_archive())
    return this->include_all_members(symtab, layout, input_objects,
				     mapfile);

  const size_t armap_size = this->armap_.size();

  // This is a quick optimization, since we usually see many symbols
  // in a row with the same offset.  last_seen_offset holds the last
  // offset we saw that was present in the seen_offsets_ set.
  off_t last_seen_offset = -1;

  // Track which symbols in the symbol table we've already found to be
  // defined.

  bool added_new_object;
  do
    {
      added_new_object = false;
      for (size_t i = 0; i < armap_size; ++i)
	{
          if (this->armap_checked_[i])
            continue;
	  if (this->armap_[i].file_offset == last_seen_offset)
            {
              this->armap_checked_[i] = true;
              continue;
            }
	  if (this->seen_offsets_.find(this->armap_[i].file_offset)
              != this->seen_offsets_.end())
	    {
              this->armap_checked_[i] = true;
	      last_seen_offset = this->armap_[i].file_offset;
	      continue;
	    }

	  const char* sym_name = (this->armap_names_.data()
				  + this->armap_[i].name_offset);
	  Symbol* sym = symtab->lookup(sym_name);
	  if (sym == NULL)
	    {
	      // Check whether the symbol was named in a -u option.
	      if (!parameters->options().is_undefined(sym_name))
		continue;
	    }
	  else if (!sym->is_undefined())
	    {
              this->armap_checked_[i] = true;
	      continue;
	    }
	  else if (sym->binding() == elfcpp::STB_WEAK)
	    continue;

	  // We want to include this object in the link.
	  last_seen_offset = this->armap_[i].file_offset;
	  this->seen_offsets_.insert(last_seen_offset);
          this->armap_checked_[i] = true;

	  std::string why;
	  if (sym == NULL)
	    {
	      why = "-u ";
	      why += sym_name;
	    }
	  this->include_member(symtab, layout, input_objects,
			       last_seen_offset, mapfile, sym, why.c_str());

	  added_new_object = true;
	}
    }
  while (added_new_object);
}

// Include all the archive members in the link.  This is for --whole-archive.

void
Archive::include_all_members(Symbol_table* symtab, Layout* layout,
                             Input_objects* input_objects, Mapfile* mapfile)
{
  off_t off = sarmag;
  off_t filesize = this->input_file_->file().filesize();
  while (true)
    {
      if (filesize - off < static_cast<off_t>(sizeof(Archive_header)))
        {
          if (filesize != off)
	    gold_error(_("%s: short archive header at %zu"),
		       this->name().c_str(), static_cast<size_t>(off));
          break;
        }

      unsigned char hdr_buf[sizeof(Archive_header)];
      this->input_file_->file().read(off, sizeof(Archive_header), hdr_buf);

      const Archive_header* hdr =
	reinterpret_cast<const Archive_header*>(hdr_buf);
      std::string name;
      off_t size = this->interpret_header(hdr, off, &name, NULL);
      if (name.empty())
        {
          // Symbol table.
        }
      else if (name == "/")
        {
          // Extended name table.
        }
      else
        this->include_member(symtab, layout, input_objects, off,
			     mapfile, NULL, "--whole-archive");

      off += sizeof(Archive_header);
      if (!this->is_thin_archive_)
        off += size;
      if ((off & 1) != 0)
        ++off;
    }
}

// Include an archive member in the link.  OFF is the file offset of
// the member header.  WHY is the reason we are including this member.

void
Archive::include_member(Symbol_table* symtab, Layout* layout,
			Input_objects* input_objects, off_t off,
			Mapfile* mapfile, Symbol* sym, const char* why)
{
  std::string n;
  off_t nested_off;
  this->read_header(off, false, &n, &nested_off);

  if (mapfile != NULL)
    mapfile->report_include_archive_member(this, n, sym, why);

  Input_file* input_file;
  off_t memoff;

  if (!this->is_thin_archive_)
    {
      input_file = this->input_file_;
      memoff = off + static_cast<off_t>(sizeof(Archive_header));
    }
  else
    {
      // Adjust a relative pathname so that it is relative
      // to the directory containing the archive.
      if (!IS_ABSOLUTE_PATH(n.c_str()))
        {
          const char *arch_path = this->name().c_str();
          const char *basename = lbasename(arch_path);
          if (basename > arch_path)
            n.replace(0, 0, this->name().substr(0, basename - arch_path));
        }
      if (nested_off > 0)
        {
          // This is a member of a nested archive.  Open the containing
          // archive if we don't already have it open, then do a recursive
          // call to include the member from that archive.
          Archive* arch;
          Nested_archive_table::const_iterator p =
            this->nested_archives_.find(n);
          if (p != this->nested_archives_.end())
            arch = p->second;
          else
            {
              Input_file_argument* input_file_arg =
                new Input_file_argument(n.c_str(), false, "", false,
                                        parameters->options());
              input_file = new Input_file(input_file_arg);
              if (!input_file->open(parameters->options(), *this->dirpath_,
                                    this->task_))
                return;
              arch = new Archive(n, input_file, false, this->dirpath_,
                                 this->task_);
              arch->setup();
              std::pair<Nested_archive_table::iterator, bool> ins =
                this->nested_archives_.insert(std::make_pair(n, arch));
              gold_assert(ins.second);
            }
          arch->include_member(symtab, layout, input_objects, nested_off,
			       NULL, NULL, NULL);
          return;
        }
      // This is an external member of a thin archive.  Open the
      // file as a regular relocatable object file.
      Input_file_argument* input_file_arg =
          new Input_file_argument(n.c_str(), false, "", false,
                                  this->input_file_->options());
      input_file = new Input_file(input_file_arg);
      if (!input_file->open(parameters->options(), *this->dirpath_,
                            this->task_))
        {
          return;
        }
      memoff = 0;
    }

  off_t filesize = input_file->file().filesize();
  int read_size = elfcpp::Elf_sizes<64>::ehdr_size;
  if (filesize - memoff < read_size)
    read_size = filesize - memoff;

  if (read_size < 4)
    {
      gold_error(_("%s: member at %zu is not an ELF object"),
		 this->name().c_str(), static_cast<size_t>(off));
      return;
    }

  const unsigned char* ehdr = input_file->file().get_view(memoff, 0, read_size,
							  true, false);

  static unsigned char elfmagic[4] =
    {
      elfcpp::ELFMAG0, elfcpp::ELFMAG1,
      elfcpp::ELFMAG2, elfcpp::ELFMAG3
    };
  if (memcmp(ehdr, elfmagic, 4) != 0)
    {
      gold_error(_("%s: member at %zu is not an ELF object"),
		 this->name().c_str(), static_cast<size_t>(off));
      return;
    }

  Object* obj = make_elf_object((std::string(this->input_file_->filename())
				 + "(" + n + ")"),
				input_file, memoff, ehdr, read_size);

  if (input_objects->add_object(obj))
    {
      Read_symbols_data sd;
      obj->read_symbols(&sd);
      obj->layout(symtab, layout, &sd);
      obj->add_symbols(symtab, &sd);
    }
  else
    {
      // FIXME: We need to close the descriptor here.
      delete obj;
    }

  if (this->is_thin_archive_)
    {
      // Opening the file locked it.  Unlock it now.
      input_file->file().unlock(this->task_);
    }
}

// Add_archive_symbols methods.

Add_archive_symbols::~Add_archive_symbols()
{
  if (this->this_blocker_ != NULL)
    delete this->this_blocker_;
  // next_blocker_ is deleted by the task associated with the next
  // input file.
}

// Return whether we can add the archive symbols.  We are blocked by
// this_blocker_.  We block next_blocker_.  We also lock the file.

Task_token*
Add_archive_symbols::is_runnable()
{
  if (this->this_blocker_ != NULL && this->this_blocker_->is_blocked())
    return this->this_blocker_;
  return NULL;
}

void
Add_archive_symbols::locks(Task_locker* tl)
{
  tl->add(this, this->next_blocker_);
  tl->add(this, this->archive_->token());
}

void
Add_archive_symbols::run(Workqueue*)
{
  this->archive_->add_symbols(this->symtab_, this->layout_,
			      this->input_objects_, this->mapfile_);

  this->archive_->unlock_nested_archives();

  this->archive_->release();
  this->archive_->clear_uncached_views();

  if (this->input_group_ != NULL)
    this->input_group_->add_archive(this->archive_);
  else
    {
      // We no longer need to know about this archive.
      delete this->archive_;
      this->archive_ = NULL;
    }
}

} // End namespace gold.
