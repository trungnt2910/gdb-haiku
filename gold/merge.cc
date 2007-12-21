// merge.cc -- handle section merging for gold

// Copyright 2006, 2007 Free Software Foundation, Inc.
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

#include <cstdlib>
#include <algorithm>

#include "merge.h"

namespace gold
{

// Class Object_merge_map.

// Destructor.

Object_merge_map::~Object_merge_map()
{
  for (Section_merge_maps::iterator p = this->section_merge_maps_.begin();
       p != this->section_merge_maps_.end();
       ++p)
    delete p->second;
}

// Get the Input_merge_map to use for an input section, or NULL.

Object_merge_map::Input_merge_map*
Object_merge_map::get_input_merge_map(unsigned int shndx)
{
  gold_assert(shndx != -1U);
  if (shndx == this->first_shnum_)
    return &this->first_map_;
  if (shndx == this->second_shnum_)
    return &this->second_map_;
  Section_merge_maps::const_iterator p = this->section_merge_maps_.find(shndx);
  if (p != this->section_merge_maps_.end())
    return p->second;
  return NULL;
}

// Get or create the Input_merge_map to use for an input section.

Object_merge_map::Input_merge_map*
Object_merge_map::get_or_make_input_merge_map(const Merge_map* merge_map,
					      unsigned int shndx)
{
  Input_merge_map* map = this->get_input_merge_map(shndx);
  if (map != NULL)
    {
      // For a given input section in a given object, every mapping
      // must be done with the same Merge_map.
      gold_assert(map->merge_map == merge_map);
      return map;
    }

  // We need to create a new entry.
  if (this->first_shnum_ == -1U)
    {
      this->first_shnum_ = shndx;
      this->first_map_.merge_map = merge_map;
      return &this->first_map_;
    }
  if (this->second_shnum_ == -1U)
    {
      this->second_shnum_ = shndx;
      this->second_map_.merge_map = merge_map;
      return &this->second_map_;
    }

  Input_merge_map* new_map = new Input_merge_map;
  new_map->merge_map = merge_map;
  this->section_merge_maps_[shndx] = new_map;
  return new_map;
}

// Add a mapping.

void
Object_merge_map::add_mapping(const Merge_map* merge_map, unsigned int shndx,
			      section_offset_type input_offset,
			      section_size_type length,
			      section_offset_type output_offset)
{
  Input_merge_map* map = this->get_or_make_input_merge_map(merge_map, shndx);

  // Try to merge the new entry in the last one we saw.
  if (!map->entries.empty())
    {
      Input_merge_entry& entry(map->entries.back());

      // Use section_size_type to avoid signed/unsigned warnings.
      section_size_type input_offset_u = input_offset;
      section_size_type output_offset_u = output_offset;

      // If this entry is not in order, we need to sort the vector
      // before looking anything up.
      if (input_offset_u < entry.input_offset + entry.length)
	{
	  gold_assert(input_offset < entry.input_offset);
	  gold_assert(input_offset_u + length
		      <= static_cast<section_size_type>(entry.input_offset));
	  map->sorted = false;
	}
      else if (entry.input_offset + entry.length == input_offset_u
	       && (output_offset == -1
		   ? entry.output_offset == -1
		   : entry.output_offset + entry.length == output_offset_u))
	{
	  entry.length += length;
	  return;
	}
    }

  Input_merge_entry entry;
  entry.input_offset = input_offset;
  entry.length = length;
  entry.output_offset = output_offset;
  map->entries.push_back(entry);
}

// Get the output offset for an input address.

inline bool
Object_merge_map::get_output_offset(const Merge_map* merge_map,
				    unsigned int shndx,
				    section_offset_type input_offset,
				    section_offset_type *output_offset)
{
  Input_merge_map* map = this->get_input_merge_map(shndx);
  if (map == NULL
      || (merge_map != NULL && map->merge_map != merge_map))
    return false;

  if (!map->sorted)
    {
      std::sort(map->entries.begin(), map->entries.end(),
		Input_merge_compare());
      map->sorted = true;
    }

  Input_merge_entry entry;
  entry.input_offset = input_offset;
  std::vector<Input_merge_entry>::const_iterator p =
    std::lower_bound(map->entries.begin(), map->entries.end(),
		     entry, Input_merge_compare());
  if (p == map->entries.end() || p->input_offset > input_offset)
    {
      if (p == map->entries.begin())
	return false;
      --p;
      gold_assert(p->input_offset <= input_offset);
    }

  if (input_offset - p->input_offset
      >= static_cast<section_offset_type>(p->length))
    return false;

  *output_offset = p->output_offset;
  if (*output_offset != -1)
    *output_offset += (input_offset - p->input_offset);
  return true;
}

// Return whether this is the merge map for section SHNDX.

inline bool
Object_merge_map::is_merge_section_for(const Merge_map* merge_map,
				       unsigned int shndx)
{
  Input_merge_map* map = this->get_input_merge_map(shndx);
  return map != NULL && map->merge_map == merge_map;
}

// Initialize a mapping from input offsets to output addresses.

template<int size>
void
Object_merge_map::initialize_input_to_output_map(
    unsigned int shndx,
    typename elfcpp::Elf_types<size>::Elf_Addr starting_address,
    Unordered_map<section_offset_type,
		  typename elfcpp::Elf_types<size>::Elf_Addr>* initialize_map)
{
  Input_merge_map* map = this->get_input_merge_map(shndx);
  gold_assert(map != NULL);

  for (Input_merge_map::Entries::const_iterator p = map->entries.begin();
       p != map->entries.end();
       ++p)
    {
      section_offset_type output_offset = p->output_offset;
      if (output_offset != -1)
	output_offset += starting_address;
      else
	{
	  // If we see a relocation against an address we have chosen
	  // to discard, we relocate to zero.  FIXME: We could also
	  // issue a warning in this case; that would require
	  // reporting this somehow and checking it in the routines in
	  // reloc.h.
	  output_offset = 0;
	}
      initialize_map->insert(std::make_pair(p->input_offset, output_offset));
    }
}

// Class Merge_map.

// Add a mapping for the bytes from OFFSET to OFFSET + LENGTH in input
// section SHNDX in object OBJECT to an OUTPUT_OFFSET in merged data
// in an output section.

void
Merge_map::add_mapping(Relobj* object, unsigned int shndx,
		       section_offset_type offset, section_size_type length,
		       section_offset_type output_offset)
{
  Object_merge_map* object_merge_map = object->merge_map();
  if (object_merge_map == NULL)
    {
      object_merge_map = new Object_merge_map();
      object->set_merge_map(object_merge_map);
    }

  object_merge_map->add_mapping(this, shndx, offset, length, output_offset);
}

// Return the output offset for an input address.  The input address
// is at offset OFFSET in section SHNDX in OBJECT.  This sets
// *OUTPUT_OFFSET to the offset in the merged data in the output
// section.  This returns true if the mapping is known, false
// otherwise.

bool
Merge_map::get_output_offset(const Relobj* object, unsigned int shndx,
			     section_offset_type offset,
			     section_offset_type* output_offset) const
{
  Object_merge_map* object_merge_map = object->merge_map();
  if (object_merge_map == NULL)
    return false;
  return object_merge_map->get_output_offset(this, shndx, offset,
					     output_offset);
}

// Return whether this is the merge section for SHNDX in OBJECT.

bool
Merge_map::is_merge_section_for(const Relobj* object, unsigned int shndx) const
{
  Object_merge_map* object_merge_map = object->merge_map();
  if (object_merge_map == NULL)
    return false;
  return object_merge_map->is_merge_section_for(this, shndx);
}

// Class Output_merge_base.

// Return the output offset for an input offset.  The input address is
// at offset OFFSET in section SHNDX in OBJECT.  If we know the
// offset, set *POUTPUT and return true.  Otherwise return false.

bool
Output_merge_base::do_output_offset(const Relobj* object,
				    unsigned int shndx,
				    section_offset_type offset,
				    section_offset_type* poutput) const
{
  return this->merge_map_.get_output_offset(object, shndx, offset, poutput);
}

// Return whether this is the merge section for SHNDX in OBJECT.

bool
Output_merge_base::do_is_merge_section_for(const Relobj* object,
					   unsigned int shndx) const
{
  return this->merge_map_.is_merge_section_for(object, shndx);
}

// Class Output_merge_data.

// Compute the hash code for a fixed-size constant.

size_t
Output_merge_data::Merge_data_hash::operator()(Merge_data_key k) const
{
  const unsigned char* p = this->pomd_->constant(k);
  section_size_type entsize =
    convert_to_section_size_type(this->pomd_->entsize());

  // Fowler/Noll/Vo (FNV) hash (type FNV-1a).
  if (sizeof(size_t) == 8)
    {
      size_t result = static_cast<size_t>(14695981039346656037ULL);
      for (section_size_type i = 0; i < entsize; ++i)
	{
	  result &= (size_t) *p++;
	  result *= 1099511628211ULL;
	}
      return result;
    }
  else
    {
      size_t result = 2166136261UL;
      for (section_size_type i = 0; i < entsize; ++i)
	{
	  result ^= (size_t) *p++;
	  result *= 16777619UL;
	}
      return result;
    }
}

// Return whether one hash table key equals another.

bool
Output_merge_data::Merge_data_eq::operator()(Merge_data_key k1,
					     Merge_data_key k2) const
{
  const unsigned char* p1 = this->pomd_->constant(k1);
  const unsigned char* p2 = this->pomd_->constant(k2);
  return memcmp(p1, p2, this->pomd_->entsize()) == 0;
}

// Add a constant to the end of the section contents.

void
Output_merge_data::add_constant(const unsigned char* p)
{
  section_size_type entsize = convert_to_section_size_type(this->entsize());
  section_size_type addralign =
    convert_to_section_size_type(this->addralign());
  section_size_type addsize = std::max(entsize, addralign);
  if (this->len_ + addsize > this->alc_)
    {
      if (this->alc_ == 0)
	this->alc_ = 128 * addsize;
      else
	this->alc_ *= 2;
      this->p_ = static_cast<unsigned char*>(realloc(this->p_, this->alc_));
      if (this->p_ == NULL)
	gold_nomem();
    }

  memcpy(this->p_ + this->len_, p, entsize);
  if (addsize > entsize)
    memset(this->p_ + this->len_ + entsize, 0, addsize - entsize);
  this->len_ += addsize;
}

// Add the input section SHNDX in OBJECT to a merged output section
// which holds fixed length constants.  Return whether we were able to
// handle the section; if not, it will be linked as usual without
// constant merging.

bool
Output_merge_data::do_add_input_section(Relobj* object, unsigned int shndx)
{
  section_size_type len;
  const unsigned char* p = object->section_contents(shndx, &len, false);

  section_size_type entsize = convert_to_section_size_type(this->entsize());

  if (len % entsize != 0)
    return false;

  this->input_count_ += len / entsize;

  for (section_size_type i = 0; i < len; i += entsize, p += entsize)
    {
      // Add the constant to the section contents.  If we find that it
      // is already in the hash table, we will remove it again.
      Merge_data_key k = this->len_;
      this->add_constant(p);

      std::pair<Merge_data_hashtable::iterator, bool> ins =
	this->hashtable_.insert(k);

      if (!ins.second)
	{
	  // Key was already present.  Remove the copy we just added.
	  this->len_ -= entsize;
	  k = *ins.first;
	}

      // Record the offset of this constant in the output section.
      this->add_mapping(object, shndx, i, entsize, k);
    }

  return true;
}

// Set the final data size in a merged output section with fixed size
// constants.

void
Output_merge_data::set_final_data_size()
{
  // Release the memory we don't need.
  this->p_ = static_cast<unsigned char*>(realloc(this->p_, this->len_));
  gold_assert(this->p_ != NULL);
  this->set_data_size(this->len_);
}

// Write the data of a merged output section with fixed size constants
// to the file.

void
Output_merge_data::do_write(Output_file* of)
{
  of->write(this->offset(), this->p_, this->len_);
}

// Write the data to a buffer.

void
Output_merge_data::do_write_to_buffer(unsigned char* buffer)
{
  memcpy(buffer, this->p_, this->len_);
}

// Print merge stats to stderr.

void
Output_merge_data::do_print_merge_stats(const char* section_name)
{
  fprintf(stderr,
	  _("%s: %s merged constants size: %lu; input: %zu; output: %zu\n"),
	  program_name, section_name,
	  static_cast<unsigned long>(this->entsize()),
	  this->input_count_, this->hashtable_.size());
}

// Class Output_merge_string.

// Add an input section to a merged string section.

template<typename Char_type>
bool
Output_merge_string<Char_type>::do_add_input_section(Relobj* object,
						     unsigned int shndx)
{
  section_size_type len;
  const unsigned char* pdata = object->section_contents(shndx, &len, false);

  const Char_type* p = reinterpret_cast<const Char_type*>(pdata);
  const Char_type* pend = p + len;

  if (len % sizeof(Char_type) != 0)
    {
      object->error(_("mergeable string section length not multiple of "
		      "character size"));
      return false;
    }

  size_t count = 0;

  // The index I is in bytes, not characters.
  section_size_type i = 0;
  while (i < len)
    {
      const Char_type* pl;
      for (pl = p; *pl != 0; ++pl)
	{
	  if (pl >= pend)
	    {
	      object->error(_("entry in mergeable string section "
			      "not null terminated"));
	      break;
	    }
	}

      Stringpool::Key key;
      const Char_type* str = this->stringpool_.add_with_length(p, pl - p, true,
							       &key);

      section_size_type bytelen_with_null = ((pl - p) + 1) * sizeof(Char_type);
      this->merged_strings_.push_back(Merged_string(object, shndx, i, str,
						    bytelen_with_null, key));

      p = pl + 1;
      i += bytelen_with_null;
      ++count;
    }

  this->input_count_ += count;

  return true;
}

// Finalize the mappings from the input sections to the output
// section, and return the final data size.

template<typename Char_type>
section_size_type
Output_merge_string<Char_type>::finalize_merged_data()
{
  this->stringpool_.set_string_offsets();

  for (typename Merged_strings::const_iterator p =
	 this->merged_strings_.begin();
       p != this->merged_strings_.end();
       ++p)
    {
      section_offset_type offset =
	this->stringpool_.get_offset_from_key(p->stringpool_key);
      this->add_mapping(p->object, p->shndx, p->offset, p->length, offset);
    }

  // Save some memory.
  this->merged_strings_.clear();

  return this->stringpool_.get_strtab_size();
}

template<typename Char_type>
void
Output_merge_string<Char_type>::set_final_data_size()
{
  const off_t final_data_size = this->finalize_merged_data();
  this->set_data_size(final_data_size);
}

// Write out a merged string section.

template<typename Char_type>
void
Output_merge_string<Char_type>::do_write(Output_file* of)
{
  this->stringpool_.write(of, this->offset());
}

// Write a merged string section to a buffer.

template<typename Char_type>
void
Output_merge_string<Char_type>::do_write_to_buffer(unsigned char* buffer)
{
  this->stringpool_.write_to_buffer(buffer, this->data_size());
}

// Return the name of the types of string to use with
// do_print_merge_stats.

template<typename Char_type>
const char*
Output_merge_string<Char_type>::string_name()
{
  gold_unreachable();
  return NULL;
}

template<>
const char*
Output_merge_string<char>::string_name()
{
  return "strings";
}

template<>
const char*
Output_merge_string<uint16_t>::string_name()
{
  return "16-bit strings";
}

template<>
const char*
Output_merge_string<uint32_t>::string_name()
{
  return "32-bit strings";
}

// Print merge stats to stderr.

template<typename Char_type>
void
Output_merge_string<Char_type>::do_print_merge_stats(const char* section_name)
{
  char buf[200];
  snprintf(buf, sizeof buf, "%s merged %s", section_name, this->string_name());
  fprintf(stderr, _("%s: %s input: %zu\n"),
	  program_name, buf, this->input_count_);
  this->stringpool_.print_stats(buf);
}

// Instantiate the templates we need.

template
class Output_merge_string<char>;

template
class Output_merge_string<uint16_t>;

template
class Output_merge_string<uint32_t>;

#if defined(HAVE_TARGET_32_LITTLE) || defined(HAVE_TARGET_32_BIG)
template
void
Object_merge_map::initialize_input_to_output_map<32>(
    unsigned int shndx,
    elfcpp::Elf_types<32>::Elf_Addr starting_address,
    Unordered_map<section_offset_type, elfcpp::Elf_types<32>::Elf_Addr>*);
#endif

#if defined(HAVE_TARGET_64_LITTLE) || defined(HAVE_TARGET_64_BIG)
template
void
Object_merge_map::initialize_input_to_output_map<64>(
    unsigned int shndx,
    elfcpp::Elf_types<64>::Elf_Addr starting_address,
    Unordered_map<section_offset_type, elfcpp::Elf_types<64>::Elf_Addr>*);
#endif

} // End namespace gold.
