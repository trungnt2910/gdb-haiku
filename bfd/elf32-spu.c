/* SPU specific support for 32-bit ELF

   Copyright 2006, 2007, 2008 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/spu.h"
#include "elf32-spu.h"

/* We use RELA style relocs.  Don't define USE_REL.  */

static bfd_reloc_status_type spu_elf_rel9 (bfd *, arelent *, asymbol *,
					   void *, asection *,
					   bfd *, char **);

/* Values of type 'enum elf_spu_reloc_type' are used to index this
   array, so it must be declared in the order of that type.  */

static reloc_howto_type elf_howto_table[] = {
  HOWTO (R_SPU_NONE,       0, 0,  0, FALSE,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_NONE",
	 FALSE, 0, 0x00000000, FALSE),
  HOWTO (R_SPU_ADDR10,     4, 2, 10, FALSE, 14, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR10",
	 FALSE, 0, 0x00ffc000, FALSE),
  HOWTO (R_SPU_ADDR16,     2, 2, 16, FALSE,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR16",
	 FALSE, 0, 0x007fff80, FALSE),
  HOWTO (R_SPU_ADDR16_HI, 16, 2, 16, FALSE,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR16_HI",
	 FALSE, 0, 0x007fff80, FALSE),
  HOWTO (R_SPU_ADDR16_LO,  0, 2, 16, FALSE,  7, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_ADDR16_LO",
	 FALSE, 0, 0x007fff80, FALSE),
  HOWTO (R_SPU_ADDR18,     0, 2, 18, FALSE,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR18",
	 FALSE, 0, 0x01ffff80, FALSE),
  HOWTO (R_SPU_ADDR32,     0, 2, 32, FALSE,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_ADDR32",
	 FALSE, 0, 0xffffffff, FALSE),
  HOWTO (R_SPU_REL16,      2, 2, 16,  TRUE,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_REL16",
	 FALSE, 0, 0x007fff80, TRUE),
  HOWTO (R_SPU_ADDR7,      0, 2,  7, FALSE, 14, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_ADDR7",
	 FALSE, 0, 0x001fc000, FALSE),
  HOWTO (R_SPU_REL9,       2, 2,  9,  TRUE,  0, complain_overflow_signed,
	 spu_elf_rel9,          "SPU_REL9",
	 FALSE, 0, 0x0180007f, TRUE),
  HOWTO (R_SPU_REL9I,      2, 2,  9,  TRUE,  0, complain_overflow_signed,
	 spu_elf_rel9,          "SPU_REL9I",
	 FALSE, 0, 0x0000c07f, TRUE),
  HOWTO (R_SPU_ADDR10I,    0, 2, 10, FALSE, 14, complain_overflow_signed,
	 bfd_elf_generic_reloc, "SPU_ADDR10I",
	 FALSE, 0, 0x00ffc000, FALSE),
  HOWTO (R_SPU_ADDR16I,    0, 2, 16, FALSE,  7, complain_overflow_signed,
	 bfd_elf_generic_reloc, "SPU_ADDR16I",
	 FALSE, 0, 0x007fff80, FALSE),
  HOWTO (R_SPU_REL32,      0, 2, 32, TRUE,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_REL32",
	 FALSE, 0, 0xffffffff, TRUE),
  HOWTO (R_SPU_ADDR16X,    0, 2, 16, FALSE,  7, complain_overflow_bitfield,
	 bfd_elf_generic_reloc, "SPU_ADDR16X",
	 FALSE, 0, 0x007fff80, FALSE),
  HOWTO (R_SPU_PPU32,      0, 2, 32, FALSE,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_PPU32",
	 FALSE, 0, 0xffffffff, FALSE),
  HOWTO (R_SPU_PPU64,      0, 4, 64, FALSE,  0, complain_overflow_dont,
	 bfd_elf_generic_reloc, "SPU_PPU64",
	 FALSE, 0, -1, FALSE),
};

static struct bfd_elf_special_section const spu_elf_special_sections[] = {
  { ".toe", 4, 0, SHT_NOBITS, SHF_ALLOC },
  { NULL, 0, 0, 0, 0 }
};

static enum elf_spu_reloc_type
spu_elf_bfd_to_reloc_type (bfd_reloc_code_real_type code)
{
  switch (code)
    {
    default:
      return R_SPU_NONE;
    case BFD_RELOC_SPU_IMM10W:
      return R_SPU_ADDR10;
    case BFD_RELOC_SPU_IMM16W:
      return R_SPU_ADDR16;
    case BFD_RELOC_SPU_LO16:
      return R_SPU_ADDR16_LO;
    case BFD_RELOC_SPU_HI16:
      return R_SPU_ADDR16_HI;
    case BFD_RELOC_SPU_IMM18:
      return R_SPU_ADDR18;
    case BFD_RELOC_SPU_PCREL16:
      return R_SPU_REL16;
    case BFD_RELOC_SPU_IMM7:
      return R_SPU_ADDR7;
    case BFD_RELOC_SPU_IMM8:
      return R_SPU_NONE;
    case BFD_RELOC_SPU_PCREL9a:
      return R_SPU_REL9;
    case BFD_RELOC_SPU_PCREL9b:
      return R_SPU_REL9I;
    case BFD_RELOC_SPU_IMM10:
      return R_SPU_ADDR10I;
    case BFD_RELOC_SPU_IMM16:
      return R_SPU_ADDR16I;
    case BFD_RELOC_32:
      return R_SPU_ADDR32;
    case BFD_RELOC_32_PCREL:
      return R_SPU_REL32;
    case BFD_RELOC_SPU_PPU32:
      return R_SPU_PPU32;
    case BFD_RELOC_SPU_PPU64:
      return R_SPU_PPU64;
    }
}

static void
spu_elf_info_to_howto (bfd *abfd ATTRIBUTE_UNUSED,
		       arelent *cache_ptr,
		       Elf_Internal_Rela *dst)
{
  enum elf_spu_reloc_type r_type;

  r_type = (enum elf_spu_reloc_type) ELF32_R_TYPE (dst->r_info);
  BFD_ASSERT (r_type < R_SPU_max);
  cache_ptr->howto = &elf_howto_table[(int) r_type];
}

static reloc_howto_type *
spu_elf_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			   bfd_reloc_code_real_type code)
{
  enum elf_spu_reloc_type r_type = spu_elf_bfd_to_reloc_type (code);

  if (r_type == R_SPU_NONE)
    return NULL;

  return elf_howto_table + r_type;
}

static reloc_howto_type *
spu_elf_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			   const char *r_name)
{
  unsigned int i;

  for (i = 0; i < sizeof (elf_howto_table) / sizeof (elf_howto_table[0]); i++)
    if (elf_howto_table[i].name != NULL
	&& strcasecmp (elf_howto_table[i].name, r_name) == 0)
      return &elf_howto_table[i];

  return NULL;
}

/* Apply R_SPU_REL9 and R_SPU_REL9I relocs.  */

static bfd_reloc_status_type
spu_elf_rel9 (bfd *abfd, arelent *reloc_entry, asymbol *symbol,
	      void *data, asection *input_section,
	      bfd *output_bfd, char **error_message)
{
  bfd_size_type octets;
  bfd_vma val;
  long insn;

  /* If this is a relocatable link (output_bfd test tells us), just
     call the generic function.  Any adjustment will be done at final
     link time.  */
  if (output_bfd != NULL)
    return bfd_elf_generic_reloc (abfd, reloc_entry, symbol, data,
				  input_section, output_bfd, error_message);

  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;
  octets = reloc_entry->address * bfd_octets_per_byte (abfd);

  /* Get symbol value.  */
  val = 0;
  if (!bfd_is_com_section (symbol->section))
    val = symbol->value;
  if (symbol->section->output_section)
    val += symbol->section->output_section->vma;

  val += reloc_entry->addend;

  /* Make it pc-relative.  */
  val -= input_section->output_section->vma + input_section->output_offset;

  val >>= 2;
  if (val + 256 >= 512)
    return bfd_reloc_overflow;

  insn = bfd_get_32 (abfd, (bfd_byte *) data + octets);

  /* Move two high bits of value to REL9I and REL9 position.
     The mask will take care of selecting the right field.  */
  val = (val & 0x7f) | ((val & 0x180) << 7) | ((val & 0x180) << 16);
  insn &= ~reloc_entry->howto->dst_mask;
  insn |= val & reloc_entry->howto->dst_mask;
  bfd_put_32 (abfd, insn, (bfd_byte *) data + octets);
  return bfd_reloc_ok;
}

static bfd_boolean
spu_elf_new_section_hook (bfd *abfd, asection *sec)
{
  if (!sec->used_by_bfd)
    {
      struct _spu_elf_section_data *sdata;

      sdata = bfd_zalloc (abfd, sizeof (*sdata));
      if (sdata == NULL)
	return FALSE;
      sec->used_by_bfd = sdata;
    }

  return _bfd_elf_new_section_hook (abfd, sec);
}

/* Specially mark defined symbols named _EAR_* with BSF_KEEP so that
   strip --strip-unneeded will not remove them.  */

static void
spu_elf_backend_symbol_processing (bfd *abfd ATTRIBUTE_UNUSED, asymbol *sym)
{
  if (sym->name != NULL
      && sym->section != bfd_abs_section_ptr
      && strncmp (sym->name, "_EAR_", 5) == 0)
    sym->flags |= BSF_KEEP;
}

/* SPU ELF linker hash table.  */

struct spu_link_hash_table
{
  struct elf_link_hash_table elf;

  /* Shortcuts to overlay sections.  */
  asection *ovtab;
  asection *toe;
  asection **ovl_sec;

  /* Count of stubs in each overlay section.  */
  unsigned int *stub_count;

  /* The stub section for each overlay section.  */
  asection **stub_sec;

  struct elf_link_hash_entry *ovly_load;
  struct elf_link_hash_entry *ovly_return;
  unsigned long ovly_load_r_symndx;

  /* Number of overlay buffers.  */
  unsigned int num_buf;

  /* Total number of overlays.  */
  unsigned int num_overlays;

  /* Set if we should emit symbols for stubs.  */
  unsigned int emit_stub_syms:1;

  /* Set if we want stubs on calls out of overlay regions to
     non-overlay regions.  */
  unsigned int non_overlay_stubs : 1;

  /* Set on error.  */
  unsigned int stub_err : 1;

  /* Set if stack size analysis should be done.  */
  unsigned int stack_analysis : 1;

  /* Set if __stack_* syms will be emitted.  */
  unsigned int emit_stack_syms : 1;
};

/* Hijack the generic got fields for overlay stub accounting.  */

struct got_entry
{
  struct got_entry *next;
  unsigned int ovl;
  bfd_vma addend;
  bfd_vma stub_addr;
};

#define spu_hash_table(p) \
  ((struct spu_link_hash_table *) ((p)->hash))

/* Create a spu ELF linker hash table.  */

static struct bfd_link_hash_table *
spu_elf_link_hash_table_create (bfd *abfd)
{
  struct spu_link_hash_table *htab;

  htab = bfd_malloc (sizeof (*htab));
  if (htab == NULL)
    return NULL;

  if (!_bfd_elf_link_hash_table_init (&htab->elf, abfd,
				      _bfd_elf_link_hash_newfunc,
				      sizeof (struct elf_link_hash_entry)))
    {
      free (htab);
      return NULL;
    }

  memset (&htab->ovtab, 0,
	  sizeof (*htab) - offsetof (struct spu_link_hash_table, ovtab));

  htab->elf.init_got_refcount.refcount = 0;
  htab->elf.init_got_refcount.glist = NULL;
  htab->elf.init_got_offset.offset = 0;
  htab->elf.init_got_offset.glist = NULL;
  return &htab->elf.root;
}

/* Find the symbol for the given R_SYMNDX in IBFD and set *HP and *SYMP
   to (hash, NULL) for global symbols, and (NULL, sym) for locals.  Set
   *SYMSECP to the symbol's section.  *LOCSYMSP caches local syms.  */

static bfd_boolean
get_sym_h (struct elf_link_hash_entry **hp,
	   Elf_Internal_Sym **symp,
	   asection **symsecp,
	   Elf_Internal_Sym **locsymsp,
	   unsigned long r_symndx,
	   bfd *ibfd)
{
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;

  if (r_symndx >= symtab_hdr->sh_info)
    {
      struct elf_link_hash_entry **sym_hashes = elf_sym_hashes (ibfd);
      struct elf_link_hash_entry *h;

      h = sym_hashes[r_symndx - symtab_hdr->sh_info];
      while (h->root.type == bfd_link_hash_indirect
	     || h->root.type == bfd_link_hash_warning)
	h = (struct elf_link_hash_entry *) h->root.u.i.link;

      if (hp != NULL)
	*hp = h;

      if (symp != NULL)
	*symp = NULL;

      if (symsecp != NULL)
	{
	  asection *symsec = NULL;
	  if (h->root.type == bfd_link_hash_defined
	      || h->root.type == bfd_link_hash_defweak)
	    symsec = h->root.u.def.section;
	  *symsecp = symsec;
	}
    }
  else
    {
      Elf_Internal_Sym *sym;
      Elf_Internal_Sym *locsyms = *locsymsp;

      if (locsyms == NULL)
	{
	  locsyms = (Elf_Internal_Sym *) symtab_hdr->contents;
	  if (locsyms == NULL)
	    {
	      size_t symcount = symtab_hdr->sh_info;

	      /* If we are reading symbols into the contents, then
		 read the global syms too.  This is done to cache
		 syms for later stack analysis.  */
	      if ((unsigned char **) locsymsp == &symtab_hdr->contents)
		symcount = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
	      locsyms = bfd_elf_get_elf_syms (ibfd, symtab_hdr, symcount, 0,
					      NULL, NULL, NULL);
	    }
	  if (locsyms == NULL)
	    return FALSE;
	  *locsymsp = locsyms;
	}
      sym = locsyms + r_symndx;

      if (hp != NULL)
	*hp = NULL;

      if (symp != NULL)
	*symp = sym;

      if (symsecp != NULL)
	*symsecp = bfd_section_from_elf_index (ibfd, sym->st_shndx);
    }

  return TRUE;
}

/* Create the note section if not already present.  This is done early so
   that the linker maps the sections to the right place in the output.  */

bfd_boolean
spu_elf_create_sections (struct bfd_link_info *info,
			 int stack_analysis,
			 int emit_stack_syms)
{
  bfd *ibfd;
  struct spu_link_hash_table *htab = spu_hash_table (info);

  /* Stash some options away where we can get at them later.  */
  htab->stack_analysis = stack_analysis;
  htab->emit_stack_syms = emit_stack_syms;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    if (bfd_get_section_by_name (ibfd, SPU_PTNOTE_SPUNAME) != NULL)
      break;

  if (ibfd == NULL)
    {
      /* Make SPU_PTNOTE_SPUNAME section.  */
      asection *s;
      size_t name_len;
      size_t size;
      bfd_byte *data;
      flagword flags;

      ibfd = info->input_bfds;
      flags = SEC_LOAD | SEC_READONLY | SEC_HAS_CONTENTS | SEC_IN_MEMORY;
      s = bfd_make_section_anyway_with_flags (ibfd, SPU_PTNOTE_SPUNAME, flags);
      if (s == NULL
	  || !bfd_set_section_alignment (ibfd, s, 4))
	return FALSE;

      name_len = strlen (bfd_get_filename (info->output_bfd)) + 1;
      size = 12 + ((sizeof (SPU_PLUGIN_NAME) + 3) & -4);
      size += (name_len + 3) & -4;

      if (!bfd_set_section_size (ibfd, s, size))
	return FALSE;

      data = bfd_zalloc (ibfd, size);
      if (data == NULL)
	return FALSE;

      bfd_put_32 (ibfd, sizeof (SPU_PLUGIN_NAME), data + 0);
      bfd_put_32 (ibfd, name_len, data + 4);
      bfd_put_32 (ibfd, 1, data + 8);
      memcpy (data + 12, SPU_PLUGIN_NAME, sizeof (SPU_PLUGIN_NAME));
      memcpy (data + 12 + ((sizeof (SPU_PLUGIN_NAME) + 3) & -4),
	      bfd_get_filename (info->output_bfd), name_len);
      s->contents = data;
    }

  return TRUE;
}

/* qsort predicate to sort sections by vma.  */

static int
sort_sections (const void *a, const void *b)
{
  const asection *const *s1 = a;
  const asection *const *s2 = b;
  bfd_signed_vma delta = (*s1)->vma - (*s2)->vma;

  if (delta != 0)
    return delta < 0 ? -1 : 1;

  return (*s1)->index - (*s2)->index;
}

/* Identify overlays in the output bfd, and number them.  */

bfd_boolean
spu_elf_find_overlays (struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  asection **alloc_sec;
  unsigned int i, n, ovl_index, num_buf;
  asection *s;
  bfd_vma ovl_end;

  if (info->output_bfd->section_count < 2)
    return FALSE;

  alloc_sec
    = bfd_malloc (info->output_bfd->section_count * sizeof (*alloc_sec));
  if (alloc_sec == NULL)
    return FALSE;

  /* Pick out all the alloced sections.  */
  for (n = 0, s = info->output_bfd->sections; s != NULL; s = s->next)
    if ((s->flags & SEC_ALLOC) != 0
	&& (s->flags & (SEC_LOAD | SEC_THREAD_LOCAL)) != SEC_THREAD_LOCAL
	&& s->size != 0)
      alloc_sec[n++] = s;

  if (n == 0)
    {
      free (alloc_sec);
      return FALSE;
    }

  /* Sort them by vma.  */
  qsort (alloc_sec, n, sizeof (*alloc_sec), sort_sections);

  /* Look for overlapping vmas.  Any with overlap must be overlays.
     Count them.  Also count the number of overlay regions.  */
  ovl_end = alloc_sec[0]->vma + alloc_sec[0]->size;
  for (ovl_index = 0, num_buf = 0, i = 1; i < n; i++)
    {
      s = alloc_sec[i];
      if (s->vma < ovl_end)
	{
	  asection *s0 = alloc_sec[i - 1];

	  if (spu_elf_section_data (s0)->u.o.ovl_index == 0)
	    {
	      alloc_sec[ovl_index] = s0;
	      spu_elf_section_data (s0)->u.o.ovl_index = ++ovl_index;
	      spu_elf_section_data (s0)->u.o.ovl_buf = ++num_buf;
	    }
	  alloc_sec[ovl_index] = s;
	  spu_elf_section_data (s)->u.o.ovl_index = ++ovl_index;
	  spu_elf_section_data (s)->u.o.ovl_buf = num_buf;
	  if (s0->vma != s->vma)
	    {
	      info->callbacks->einfo (_("%X%P: overlay sections %A and %A "
					"do not start at the same address.\n"),
				      s0, s);
	      return FALSE;
	    }
	  if (ovl_end < s->vma + s->size)
	    ovl_end = s->vma + s->size;
	}
      else
	ovl_end = s->vma + s->size;
    }

  htab->num_overlays = ovl_index;
  htab->num_buf = num_buf;
  htab->ovl_sec = alloc_sec;
  htab->ovly_load = elf_link_hash_lookup (&htab->elf, "__ovly_load",
					  FALSE, FALSE, FALSE);
  htab->ovly_return = elf_link_hash_lookup (&htab->elf, "__ovly_return",
					    FALSE, FALSE, FALSE);
  return ovl_index != 0;
}

/* Support two sizes of overlay stubs, a slower more compact stub of two
   intructions, and a faster stub of four instructions.  */
#ifndef OVL_STUB_SIZE
/* Default to faster.  */
#define OVL_STUB_SIZE 16
/* #define OVL_STUB_SIZE 8 */
#endif
#define BRSL	0x33000000
#define BR	0x32000000
#define NOP	0x40200000
#define LNOP	0x00200000
#define ILA	0x42000000

/* Return true for all relative and absolute branch instructions.
   bra   00110000 0..
   brasl 00110001 0..
   br    00110010 0..
   brsl  00110011 0..
   brz   00100000 0..
   brnz  00100001 0..
   brhz  00100010 0..
   brhnz 00100011 0..  */

static bfd_boolean
is_branch (const unsigned char *insn)
{
  return (insn[0] & 0xec) == 0x20 && (insn[1] & 0x80) == 0;
}

/* Return true for all indirect branch instructions.
   bi     00110101 000
   bisl   00110101 001
   iret   00110101 010
   bisled 00110101 011
   biz    00100101 000
   binz   00100101 001
   bihz   00100101 010
   bihnz  00100101 011  */

static bfd_boolean
is_indirect_branch (const unsigned char *insn)
{
  return (insn[0] & 0xef) == 0x25 && (insn[1] & 0x80) == 0;
}

/* Return true for branch hint instructions.
   hbra  0001000..
   hbrr  0001001..  */

static bfd_boolean
is_hint (const unsigned char *insn)
{
  return (insn[0] & 0xfc) == 0x10;
}

/* True if INPUT_SECTION might need overlay stubs.  */

static bfd_boolean
maybe_needs_stubs (asection *input_section, bfd *output_bfd)
{
  /* No stubs for debug sections and suchlike.  */
  if ((input_section->flags & SEC_ALLOC) == 0)
    return FALSE;

  /* No stubs for link-once sections that will be discarded.  */
  if (input_section->output_section == NULL
      || input_section->output_section->owner != output_bfd)
    return FALSE;

  /* Don't create stubs for .eh_frame references.  */
  if (strcmp (input_section->name, ".eh_frame") == 0)
    return FALSE;

  return TRUE;
}

enum _stub_type
{
  no_stub,
  ovl_stub,
  nonovl_stub,
  stub_error
};

/* Return non-zero if this reloc symbol should go via an overlay stub.
   Return 2 if the stub must be in non-overlay area.  */

static enum _stub_type
needs_ovl_stub (struct elf_link_hash_entry *h,
		Elf_Internal_Sym *sym,
		asection *sym_sec,
		asection *input_section,
		Elf_Internal_Rela *irela,
		bfd_byte *contents,
		struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  enum elf_spu_reloc_type r_type;
  unsigned int sym_type;
  bfd_boolean branch;
  enum _stub_type ret = no_stub;

  if (sym_sec == NULL
      || sym_sec->output_section == NULL
      || sym_sec->output_section->owner != info->output_bfd
      || spu_elf_section_data (sym_sec->output_section) == NULL)
    return ret;

  if (h != NULL)
    {
      /* Ensure no stubs for user supplied overlay manager syms.  */
      if (h == htab->ovly_load || h == htab->ovly_return)
	return ret;

      /* setjmp always goes via an overlay stub, because then the return
	 and hence the longjmp goes via __ovly_return.  That magically
	 makes setjmp/longjmp between overlays work.  */
      if (strncmp (h->root.root.string, "setjmp", 6) == 0
	  && (h->root.root.string[6] == '\0' || h->root.root.string[6] == '@'))
	ret = ovl_stub;
    }

  /* Usually, symbols in non-overlay sections don't need stubs.  */
  if (spu_elf_section_data (sym_sec->output_section)->u.o.ovl_index == 0
      && !htab->non_overlay_stubs)
    return ret;

  if (h != NULL)
    sym_type = h->type;
  else
    sym_type = ELF_ST_TYPE (sym->st_info);

  r_type = ELF32_R_TYPE (irela->r_info);
  branch = FALSE;
  if (r_type == R_SPU_REL16 || r_type == R_SPU_ADDR16)
    {
      bfd_byte insn[4];

      if (contents == NULL)
	{
	  contents = insn;
	  if (!bfd_get_section_contents (input_section->owner,
					 input_section,
					 contents,
					 irela->r_offset, 4))
	    return stub_error;
	}
      else
	contents += irela->r_offset;

      if (is_branch (contents) || is_hint (contents))
	{
	  branch = TRUE;
	  if ((contents[0] & 0xfd) == 0x31
	      && sym_type != STT_FUNC
	      && contents == insn)
	    {
	      /* It's common for people to write assembly and forget
		 to give function symbols the right type.  Handle
		 calls to such symbols, but warn so that (hopefully)
		 people will fix their code.  We need the symbol
		 type to be correct to distinguish function pointer
		 initialisation from other pointer initialisations.  */
	      const char *sym_name;

	      if (h != NULL)
		sym_name = h->root.root.string;
	      else
		{
		  Elf_Internal_Shdr *symtab_hdr;
		  symtab_hdr = &elf_tdata (input_section->owner)->symtab_hdr;
		  sym_name = bfd_elf_sym_name (input_section->owner,
					       symtab_hdr,
					       sym,
					       sym_sec);
		}
	      (*_bfd_error_handler) (_("warning: call to non-function"
				       " symbol %s defined in %B"),
				     sym_sec->owner, sym_name);

	    }
	}
    }

  if (sym_type != STT_FUNC
      && !branch
      && (sym_sec->flags & SEC_CODE) == 0)
    return ret;

  /* A reference from some other section to a symbol in an overlay
     section needs a stub.  */
  if (spu_elf_section_data (sym_sec->output_section)->u.o.ovl_index
       != spu_elf_section_data (input_section->output_section)->u.o.ovl_index)
    return ovl_stub;

  /* If this insn isn't a branch then we are possibly taking the
     address of a function and passing it out somehow.  */
  return !branch && sym_type == STT_FUNC ? nonovl_stub : ret;
}

static bfd_boolean
count_stub (struct spu_link_hash_table *htab,
	    bfd *ibfd,
	    asection *isec,
	    enum _stub_type stub_type,
	    struct elf_link_hash_entry *h,
	    const Elf_Internal_Rela *irela)
{
  unsigned int ovl = 0;
  struct got_entry *g, **head;
  bfd_vma addend;

  /* If this instruction is a branch or call, we need a stub
     for it.  One stub per function per overlay.
     If it isn't a branch, then we are taking the address of
     this function so need a stub in the non-overlay area
     for it.  One stub per function.  */
  if (stub_type != nonovl_stub)
    ovl = spu_elf_section_data (isec->output_section)->u.o.ovl_index;

  if (h != NULL)
    head = &h->got.glist;
  else
    {
      if (elf_local_got_ents (ibfd) == NULL)
	{
	  bfd_size_type amt = (elf_tdata (ibfd)->symtab_hdr.sh_info
			       * sizeof (*elf_local_got_ents (ibfd)));
	  elf_local_got_ents (ibfd) = bfd_zmalloc (amt);
	  if (elf_local_got_ents (ibfd) == NULL)
	    return FALSE;
	}
      head = elf_local_got_ents (ibfd) + ELF32_R_SYM (irela->r_info);
    }

  addend = 0;
  if (irela != NULL)
    addend = irela->r_addend;

  if (ovl == 0)
    {
      struct got_entry *gnext;

      for (g = *head; g != NULL; g = g->next)
	if (g->addend == addend && g->ovl == 0)
	  break;

      if (g == NULL)
	{
	  /* Need a new non-overlay area stub.  Zap other stubs.  */
	  for (g = *head; g != NULL; g = gnext)
	    {
	      gnext = g->next;
	      if (g->addend == addend)
		{
		  htab->stub_count[g->ovl] -= 1;
		  free (g);
		}
	    }
	}
    }
  else
    {
      for (g = *head; g != NULL; g = g->next)
	if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
	  break;
    }

  if (g == NULL)
    {
      g = bfd_malloc (sizeof *g);
      if (g == NULL)
	return FALSE;
      g->ovl = ovl;
      g->addend = addend;
      g->stub_addr = (bfd_vma) -1;
      g->next = *head;
      *head = g;

      htab->stub_count[ovl] += 1;
    }

  return TRUE;
}

/* Two instruction overlay stubs look like:

   brsl $75,__ovly_load
   .word target_ovl_and_address

   ovl_and_address is a word with the overlay number in the top 14 bits
   and local store address in the bottom 18 bits.

   Four instruction overlay stubs look like:

   ila $78,ovl_number
   lnop
   ila $79,target_address
   br __ovly_load  */

static bfd_boolean
build_stub (struct spu_link_hash_table *htab,
	    bfd *ibfd,
	    asection *isec,
	    enum _stub_type stub_type,
	    struct elf_link_hash_entry *h,
	    const Elf_Internal_Rela *irela,
	    bfd_vma dest,
	    asection *dest_sec)
{
  unsigned int ovl;
  struct got_entry *g, **head;
  asection *sec;
  bfd_vma addend, val, from, to;

  ovl = 0;
  if (stub_type != nonovl_stub)
    ovl = spu_elf_section_data (isec->output_section)->u.o.ovl_index;

  if (h != NULL)
    head = &h->got.glist;
  else
    head = elf_local_got_ents (ibfd) + ELF32_R_SYM (irela->r_info);

  addend = 0;
  if (irela != NULL)
    addend = irela->r_addend;

  for (g = *head; g != NULL; g = g->next)
    if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
      break;
  if (g == NULL)
    abort ();

  if (g->ovl == 0 && ovl != 0)
    return TRUE;

  if (g->stub_addr != (bfd_vma) -1)
    return TRUE;

  sec = htab->stub_sec[ovl];
  dest += dest_sec->output_offset + dest_sec->output_section->vma;
  from = sec->size + sec->output_offset + sec->output_section->vma;
  g->stub_addr = from;
  to = (htab->ovly_load->root.u.def.value
	+ htab->ovly_load->root.u.def.section->output_offset
	+ htab->ovly_load->root.u.def.section->output_section->vma);
  val = to - from;
  if (OVL_STUB_SIZE == 16)
    val -= 12;
  if (((dest | to | from) & 3) != 0
      || val + 0x20000 >= 0x40000)
    {
      htab->stub_err = 1;
      return FALSE;
    }
  ovl = spu_elf_section_data (dest_sec->output_section)->u.o.ovl_index;

  if (OVL_STUB_SIZE == 16)
    {
      bfd_put_32 (sec->owner, ILA + ((ovl << 7) & 0x01ffff80) + 78,
		  sec->contents + sec->size);
      bfd_put_32 (sec->owner, LNOP,
		  sec->contents + sec->size + 4);
      bfd_put_32 (sec->owner, ILA + ((dest << 7) & 0x01ffff80) + 79,
		  sec->contents + sec->size + 8);
      bfd_put_32 (sec->owner, BR + ((val << 5) & 0x007fff80),
		  sec->contents + sec->size + 12);
    }
  else if (OVL_STUB_SIZE == 8)
    {
      bfd_put_32 (sec->owner, BRSL + ((val << 5) & 0x007fff80) + 75,
		  sec->contents + sec->size);

      val = (dest & 0x3ffff) | (ovl << 14);
      bfd_put_32 (sec->owner, val,
		  sec->contents + sec->size + 4);
    }
  else
    abort ();
  sec->size += OVL_STUB_SIZE;

  if (htab->emit_stub_syms)
    {
      size_t len;
      char *name;
      int add;

      len = 8 + sizeof (".ovl_call.") - 1;
      if (h != NULL)
	len += strlen (h->root.root.string);
      else
	len += 8 + 1 + 8;
      add = 0;
      if (irela != NULL)
	add = (int) irela->r_addend & 0xffffffff;
      if (add != 0)
	len += 1 + 8;
      name = bfd_malloc (len);
      if (name == NULL)
	return FALSE;

      sprintf (name, "%08x.ovl_call.", g->ovl);
      if (h != NULL)
	strcpy (name + 8 + sizeof (".ovl_call.") - 1, h->root.root.string);
      else
	sprintf (name + 8 + sizeof (".ovl_call.") - 1, "%x:%x",
		 dest_sec->id & 0xffffffff,
		 (int) ELF32_R_SYM (irela->r_info) & 0xffffffff);
      if (add != 0)
	sprintf (name + len - 9, "+%x", add);

      h = elf_link_hash_lookup (&htab->elf, name, TRUE, TRUE, FALSE);
      free (name);
      if (h == NULL)
	return FALSE;
      if (h->root.type == bfd_link_hash_new)
	{
	  h->root.type = bfd_link_hash_defined;
	  h->root.u.def.section = sec;
	  h->root.u.def.value = sec->size - OVL_STUB_SIZE;
	  h->size = OVL_STUB_SIZE;
	  h->type = STT_FUNC;
	  h->ref_regular = 1;
	  h->def_regular = 1;
	  h->ref_regular_nonweak = 1;
	  h->forced_local = 1;
	  h->non_elf = 0;
	}
    }

  return TRUE;
}

/* Called via elf_link_hash_traverse to allocate stubs for any _SPUEAR_
   symbols.  */

static bfd_boolean
allocate_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
  /* Symbols starting with _SPUEAR_ need a stub because they may be
     invoked by the PPU.  */
  if ((h->root.type == bfd_link_hash_defined
       || h->root.type == bfd_link_hash_defweak)
      && h->def_regular
      && strncmp (h->root.root.string, "_SPUEAR_", 8) == 0)
    {
      struct spu_link_hash_table *htab = inf;

      count_stub (htab, NULL, NULL, nonovl_stub, h, NULL);
    }
  
  return TRUE;
}

static bfd_boolean
build_spuear_stubs (struct elf_link_hash_entry *h, void *inf)
{
  /* Symbols starting with _SPUEAR_ need a stub because they may be
     invoked by the PPU.  */
  if ((h->root.type == bfd_link_hash_defined
       || h->root.type == bfd_link_hash_defweak)
      && h->def_regular
      && strncmp (h->root.root.string, "_SPUEAR_", 8) == 0)
    {
      struct spu_link_hash_table *htab = inf;

      build_stub (htab, NULL, NULL, nonovl_stub, h, NULL,
		  h->root.u.def.value, h->root.u.def.section);
    }
  
  return TRUE;
}

/* Size or build stubs.  */

static bfd_boolean
process_stubs (struct bfd_link_info *info, bfd_boolean build)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    {
      extern const bfd_target bfd_elf32_spu_vec;
      Elf_Internal_Shdr *symtab_hdr;
      asection *isec;
      Elf_Internal_Sym *local_syms = NULL;
      void *psyms;

      if (ibfd->xvec != &bfd_elf32_spu_vec)
	continue;

      /* We'll need the symbol table in a second.  */
      symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
      if (symtab_hdr->sh_info == 0)
	continue;

      /* Arrange to read and keep global syms for later stack analysis.  */
      psyms = &local_syms;
      if (htab->stack_analysis)
	psyms = &symtab_hdr->contents;

      /* Walk over each section attached to the input bfd.  */
      for (isec = ibfd->sections; isec != NULL; isec = isec->next)
	{
	  Elf_Internal_Rela *internal_relocs, *irelaend, *irela;

	  /* If there aren't any relocs, then there's nothing more to do.  */
	  if ((isec->flags & SEC_RELOC) == 0
	      || isec->reloc_count == 0)
	    continue;

	  if (!maybe_needs_stubs (isec, info->output_bfd))
	    continue;

	  /* Get the relocs.  */
	  internal_relocs = _bfd_elf_link_read_relocs (ibfd, isec, NULL, NULL,
						       info->keep_memory);
	  if (internal_relocs == NULL)
	    goto error_ret_free_local;

	  /* Now examine each relocation.  */
	  irela = internal_relocs;
	  irelaend = irela + isec->reloc_count;
	  for (; irela < irelaend; irela++)
	    {
	      enum elf_spu_reloc_type r_type;
	      unsigned int r_indx;
	      asection *sym_sec;
	      Elf_Internal_Sym *sym;
	      struct elf_link_hash_entry *h;
	      enum _stub_type stub_type;

	      r_type = ELF32_R_TYPE (irela->r_info);
	      r_indx = ELF32_R_SYM (irela->r_info);

	      if (r_type >= R_SPU_max)
		{
		  bfd_set_error (bfd_error_bad_value);
		error_ret_free_internal:
		  if (elf_section_data (isec)->relocs != internal_relocs)
		    free (internal_relocs);
		error_ret_free_local:
		  if (local_syms != NULL
		      && (symtab_hdr->contents
			  != (unsigned char *) local_syms))
		    free (local_syms);
		  return FALSE;
		}

	      /* Determine the reloc target section.  */
	      if (!get_sym_h (&h, &sym, &sym_sec, psyms, r_indx, ibfd))
		goto error_ret_free_internal;

	      stub_type = needs_ovl_stub (h, sym, sym_sec, isec, irela,
					  NULL, info);
	      if (stub_type == no_stub)
		continue;
	      else if (stub_type == stub_error)
		goto error_ret_free_internal;

	      if (htab->stub_count == NULL)
		{
		  bfd_size_type amt;
		  amt = (htab->num_overlays + 1) * sizeof (*htab->stub_count);
		  htab->stub_count = bfd_zmalloc (amt);
		  if (htab->stub_count == NULL)
		    goto error_ret_free_internal;
		}

	      if (!build)
		{
		  if (!count_stub (htab, ibfd, isec, stub_type, h, irela))
		    goto error_ret_free_internal;
		}
	      else
		{
		  bfd_vma dest;

		  if (h != NULL)
		    dest = h->root.u.def.value;
		  else
		    dest = sym->st_value;
		  dest += irela->r_addend;
		  if (!build_stub (htab, ibfd, isec, stub_type, h, irela,
				   dest, sym_sec))
		    goto error_ret_free_internal;
		}
	    }

	  /* We're done with the internal relocs, free them.  */
	  if (elf_section_data (isec)->relocs != internal_relocs)
	    free (internal_relocs);
	}

      if (local_syms != NULL
	  && symtab_hdr->contents != (unsigned char *) local_syms)
	{
	  if (!info->keep_memory)
	    free (local_syms);
	  else
	    symtab_hdr->contents = (unsigned char *) local_syms;
	}
    }

  return TRUE;
}

/* Allocate space for overlay call and return stubs.  */

int
spu_elf_size_stubs (struct bfd_link_info *info,
		    void (*place_spu_section) (asection *, asection *,
					       const char *),
		    int non_overlay_stubs)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  bfd *ibfd;
  bfd_size_type amt;
  flagword flags;
  unsigned int i;
  asection *stub;

  htab->non_overlay_stubs = non_overlay_stubs;
  if (!process_stubs (info, FALSE))
    return 0;

  elf_link_hash_traverse (&htab->elf, allocate_spuear_stubs, htab);
  if (htab->stub_err)
    return 0;

  if (htab->stub_count == NULL)
    return 1;

  ibfd = info->input_bfds;
  amt = (htab->num_overlays + 1) * sizeof (*htab->stub_sec);
  htab->stub_sec = bfd_zmalloc (amt);
  if (htab->stub_sec == NULL)
    return 0;

  flags = (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_READONLY
	   | SEC_HAS_CONTENTS | SEC_IN_MEMORY);
  stub = bfd_make_section_anyway_with_flags (ibfd, ".stub", flags);
  htab->stub_sec[0] = stub;
  if (stub == NULL
      || !bfd_set_section_alignment (ibfd, stub, 3 + (OVL_STUB_SIZE > 8)))
    return 0;
  stub->size = htab->stub_count[0] * OVL_STUB_SIZE;
  (*place_spu_section) (stub, NULL, ".text");

  for (i = 0; i < htab->num_overlays; ++i)
    {
      asection *osec = htab->ovl_sec[i];
      unsigned int ovl = spu_elf_section_data (osec)->u.o.ovl_index;
      stub = bfd_make_section_anyway_with_flags (ibfd, ".stub", flags);
      htab->stub_sec[ovl] = stub;
      if (stub == NULL
	  || !bfd_set_section_alignment (ibfd, stub, 3 + (OVL_STUB_SIZE > 8)))
	return 0;
      stub->size = htab->stub_count[ovl] * OVL_STUB_SIZE;
      (*place_spu_section) (stub, osec, NULL);
    }

 /* htab->ovtab consists of two arrays.
    .	struct {
    .	  u32 vma;
    .	  u32 size;
    .	  u32 file_off;
    .	  u32 buf;
    .	} _ovly_table[];
    .
    .	struct {
    .	  u32 mapped;
    .	} _ovly_buf_table[];
    .  */

  flags = (SEC_ALLOC | SEC_LOAD
	   | SEC_HAS_CONTENTS | SEC_IN_MEMORY);
  htab->ovtab = bfd_make_section_anyway_with_flags (ibfd, ".ovtab", flags);
  if (htab->ovtab == NULL
      || !bfd_set_section_alignment (ibfd, htab->ovtab, 4))
    return 0;

  htab->ovtab->size = htab->num_overlays * 16 + 16 + htab->num_buf * 4;
  (*place_spu_section) (htab->ovtab, NULL, ".data");

  htab->toe = bfd_make_section_anyway_with_flags (ibfd, ".toe", SEC_ALLOC);
  if (htab->toe == NULL
      || !bfd_set_section_alignment (ibfd, htab->toe, 4))
    return 0;
  htab->toe->size = 16;
  (*place_spu_section) (htab->toe, NULL, ".toe");

  return 2;
}

/* Functions to handle embedded spu_ovl.o object.  */

static void *
ovl_mgr_open (struct bfd *nbfd ATTRIBUTE_UNUSED, void *stream)
{
  return stream;
}

static file_ptr
ovl_mgr_pread (struct bfd *abfd ATTRIBUTE_UNUSED,
	       void *stream,
	       void *buf,
	       file_ptr nbytes,
	       file_ptr offset)
{
  struct _ovl_stream *os;
  size_t count;
  size_t max;

  os = (struct _ovl_stream *) stream;
  max = (const char *) os->end - (const char *) os->start;

  if ((ufile_ptr) offset >= max)
    return 0;

  count = nbytes;
  if (count > max - offset)
    count = max - offset;

  memcpy (buf, (const char *) os->start + offset, count);
  return count;
}

bfd_boolean
spu_elf_open_builtin_lib (bfd **ovl_bfd, const struct _ovl_stream *stream)
{
  *ovl_bfd = bfd_openr_iovec ("builtin ovl_mgr",
			      "elf32-spu",
			      ovl_mgr_open,
			      (void *) stream,
			      ovl_mgr_pread,
			      NULL,
			      NULL);
  return *ovl_bfd != NULL;
}

/* Define an STT_OBJECT symbol.  */

static struct elf_link_hash_entry *
define_ovtab_symbol (struct spu_link_hash_table *htab, const char *name)
{
  struct elf_link_hash_entry *h;

  h = elf_link_hash_lookup (&htab->elf, name, TRUE, FALSE, FALSE);
  if (h == NULL)
    return NULL;

  if (h->root.type != bfd_link_hash_defined
      || !h->def_regular)
    {
      h->root.type = bfd_link_hash_defined;
      h->root.u.def.section = htab->ovtab;
      h->type = STT_OBJECT;
      h->ref_regular = 1;
      h->def_regular = 1;
      h->ref_regular_nonweak = 1;
      h->non_elf = 0;
    }
  else
    {
      (*_bfd_error_handler) (_("%B is not allowed to define %s"),
			     h->root.u.def.section->owner,
			     h->root.root.string);
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }

  return h;
}

/* Fill in all stubs and the overlay tables.  */

bfd_boolean
spu_elf_build_stubs (struct bfd_link_info *info, int emit_syms)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  struct elf_link_hash_entry *h;
  bfd_byte *p;
  asection *s;
  bfd *obfd;
  unsigned int i;

  htab->emit_stub_syms = emit_syms;
  if (htab->stub_count == NULL)
    return TRUE;

  for (i = 0; i <= htab->num_overlays; i++)
    if (htab->stub_sec[i]->size != 0)
      {
	htab->stub_sec[i]->contents = bfd_zalloc (htab->stub_sec[i]->owner,
						  htab->stub_sec[i]->size);
	if (htab->stub_sec[i]->contents == NULL)
	  return FALSE;
	htab->stub_sec[i]->rawsize = htab->stub_sec[i]->size;
	htab->stub_sec[i]->size = 0;
      }

  h = elf_link_hash_lookup (&htab->elf, "__ovly_load", FALSE, FALSE, FALSE);
  htab->ovly_load = h;
  BFD_ASSERT (h != NULL
	      && (h->root.type == bfd_link_hash_defined
		  || h->root.type == bfd_link_hash_defweak)
	      && h->def_regular);

  s = h->root.u.def.section->output_section;
  if (spu_elf_section_data (s)->u.o.ovl_index)
    {
      (*_bfd_error_handler) (_("%s in overlay section"),
			     h->root.u.def.section->owner);
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  h = elf_link_hash_lookup (&htab->elf, "__ovly_return", FALSE, FALSE, FALSE);
  htab->ovly_return = h;

  /* Fill in all the stubs.  */
  process_stubs (info, TRUE);

  elf_link_hash_traverse (&htab->elf, build_spuear_stubs, htab);
  if (htab->stub_err)
    return FALSE;

  for (i = 0; i <= htab->num_overlays; i++)
    {
      if (htab->stub_sec[i]->size != htab->stub_sec[i]->rawsize)
	{
	  (*_bfd_error_handler)  (_("stubs don't match calculated size"));
	  bfd_set_error (bfd_error_bad_value);
	  return FALSE;
	}
      htab->stub_sec[i]->rawsize = 0;
    }

  if (htab->stub_err)
    {
      (*_bfd_error_handler) (_("overlay stub relocation overflow"));
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  htab->ovtab->contents = bfd_zalloc (htab->ovtab->owner, htab->ovtab->size);
  if (htab->ovtab->contents == NULL)
    return FALSE;

  /* Write out _ovly_table.  */
  p = htab->ovtab->contents;
  /* set low bit of .size to mark non-overlay area as present.  */
  p[7] = 1;
  obfd = htab->ovtab->output_section->owner;
  for (s = obfd->sections; s != NULL; s = s->next)
    {
      unsigned int ovl_index = spu_elf_section_data (s)->u.o.ovl_index;

      if (ovl_index != 0)
	{
	  unsigned long off = ovl_index * 16;
	  unsigned int ovl_buf = spu_elf_section_data (s)->u.o.ovl_buf;

	  bfd_put_32 (htab->ovtab->owner, s->vma, p + off);
	  bfd_put_32 (htab->ovtab->owner, (s->size + 15) & -16, p + off + 4);
	  /* file_off written later in spu_elf_modify_program_headers.  */
	  bfd_put_32 (htab->ovtab->owner, ovl_buf, p + off + 12);
	}
    }

  h = define_ovtab_symbol (htab, "_ovly_table");
  if (h == NULL)
    return FALSE;
  h->root.u.def.value = 16;
  h->size = htab->num_overlays * 16;

  h = define_ovtab_symbol (htab, "_ovly_table_end");
  if (h == NULL)
    return FALSE;
  h->root.u.def.value = htab->num_overlays * 16 + 16;
  h->size = 0;

  h = define_ovtab_symbol (htab, "_ovly_buf_table");
  if (h == NULL)
    return FALSE;
  h->root.u.def.value = htab->num_overlays * 16 + 16;
  h->size = htab->num_buf * 4;

  h = define_ovtab_symbol (htab, "_ovly_buf_table_end");
  if (h == NULL)
    return FALSE;
  h->root.u.def.value = htab->num_overlays * 16 + 16 + htab->num_buf * 4;
  h->size = 0;

  h = define_ovtab_symbol (htab, "_EAR_");
  if (h == NULL)
    return FALSE;
  h->root.u.def.section = htab->toe;
  h->root.u.def.value = 0;
  h->size = 16;

  return TRUE;
}

/* Check that all loadable section VMAs lie in the range
   LO .. HI inclusive.  */

asection *
spu_elf_check_vma (struct bfd_link_info *info, bfd_vma lo, bfd_vma hi)
{
  struct elf_segment_map *m;
  unsigned int i;
  bfd *abfd = info->output_bfd;

  for (m = elf_tdata (abfd)->segment_map; m != NULL; m = m->next)
    if (m->p_type == PT_LOAD)
      for (i = 0; i < m->count; i++)
	if (m->sections[i]->size != 0
	    && (m->sections[i]->vma < lo
		|| m->sections[i]->vma > hi
		|| m->sections[i]->vma + m->sections[i]->size - 1 > hi))
	  return m->sections[i];

  return NULL;
}

/* OFFSET in SEC (presumably) is the beginning of a function prologue.
   Search for stack adjusting insns, and return the sp delta.  */

static int
find_function_stack_adjust (asection *sec, bfd_vma offset)
{
  int unrecog;
  int reg[128];

  memset (reg, 0, sizeof (reg));
  for (unrecog = 0; offset + 4 <= sec->size && unrecog < 32; offset += 4)
    {
      unsigned char buf[4];
      int rt, ra;
      int imm;

      /* Assume no relocs on stack adjusing insns.  */
      if (!bfd_get_section_contents (sec->owner, sec, buf, offset, 4))
	break;

      if (buf[0] == 0x24 /* stqd */)
	continue;

      rt = buf[3] & 0x7f;
      ra = ((buf[2] & 0x3f) << 1) | (buf[3] >> 7);
      /* Partly decoded immediate field.  */
      imm = (buf[1] << 9) | (buf[2] << 1) | (buf[3] >> 7);

      if (buf[0] == 0x1c /* ai */)
	{
	  imm >>= 7;
	  imm = (imm ^ 0x200) - 0x200;
	  reg[rt] = reg[ra] + imm;

	  if (rt == 1 /* sp */)
	    {
	      if (imm > 0)
		break;
	      return reg[rt];
	    }
	}
      else if (buf[0] == 0x18 && (buf[1] & 0xe0) == 0 /* a */)
	{
	  int rb = ((buf[1] & 0x1f) << 2) | ((buf[2] & 0xc0) >> 6);

	  reg[rt] = reg[ra] + reg[rb];
	  if (rt == 1)
	    return reg[rt];
	}
      else if ((buf[0] & 0xfc) == 0x40 /* il, ilh, ilhu, ila */)
	{
	  if (buf[0] >= 0x42 /* ila */)
	    imm |= (buf[0] & 1) << 17;
	  else
	    {
	      imm &= 0xffff;

	      if (buf[0] == 0x40 /* il */)
		{
		  if ((buf[1] & 0x80) == 0)
		    goto unknown_insn;
		  imm = (imm ^ 0x8000) - 0x8000;
		}
	      else if ((buf[1] & 0x80) == 0 /* ilhu */)
		imm <<= 16;
	    }
	  reg[rt] = imm;
	  continue;
	}
      else if (buf[0] == 0x60 && (buf[1] & 0x80) != 0 /* iohl */)
	{
	  reg[rt] |= imm & 0xffff;
	  continue;
	}
      else if (buf[0] == 0x04 /* ori */)
	{
	  imm >>= 7;
	  imm = (imm ^ 0x200) - 0x200;
	  reg[rt] = reg[ra] | imm;
	  continue;
	}
      else if ((buf[0] == 0x33 && imm == 1 /* brsl .+4 */)
	       || (buf[0] == 0x08 && (buf[1] & 0xe0) == 0 /* sf */))
	{
	  /* Used in pic reg load.  Say rt is trashed.  */
	  reg[rt] = 0;
	  continue;
	}
      else if (is_branch (buf) || is_indirect_branch (buf))
	/* If we hit a branch then we must be out of the prologue.  */
	break;
    unknown_insn:
      ++unrecog;
    }

  return 0;
}

/* qsort predicate to sort symbols by section and value.  */

static Elf_Internal_Sym *sort_syms_syms;
static asection **sort_syms_psecs;

static int
sort_syms (const void *a, const void *b)
{
  Elf_Internal_Sym *const *s1 = a;
  Elf_Internal_Sym *const *s2 = b;
  asection *sec1,*sec2;
  bfd_signed_vma delta;

  sec1 = sort_syms_psecs[*s1 - sort_syms_syms];
  sec2 = sort_syms_psecs[*s2 - sort_syms_syms];

  if (sec1 != sec2)
    return sec1->index - sec2->index;

  delta = (*s1)->st_value - (*s2)->st_value;
  if (delta != 0)
    return delta < 0 ? -1 : 1;

  delta = (*s2)->st_size - (*s1)->st_size;
  if (delta != 0)
    return delta < 0 ? -1 : 1;

  return *s1 < *s2 ? -1 : 1;
}

struct call_info
{
  struct function_info *fun;
  struct call_info *next;
  unsigned int is_tail : 1;
};

struct function_info
{
  /* List of functions called.  Also branches to hot/cold part of
     function.  */
  struct call_info *call_list;
  /* For hot/cold part of function, point to owner.  */
  struct function_info *start;
  /* Symbol at start of function.  */
  union {
    Elf_Internal_Sym *sym;
    struct elf_link_hash_entry *h;
  } u;
  /* Function section.  */
  asection *sec;
  /* Address range of (this part of) function.  */
  bfd_vma lo, hi;
  /* Stack usage.  */
  int stack;
  /* Set if global symbol.  */
  unsigned int global : 1;
  /* Set if known to be start of function (as distinct from a hunk
     in hot/cold section.  */
  unsigned int is_func : 1;
  /* Flags used during call tree traversal.  */
  unsigned int visit1 : 1;
  unsigned int non_root : 1;
  unsigned int visit2 : 1;
  unsigned int marking : 1;
  unsigned int visit3 : 1;
};

struct spu_elf_stack_info
{
  int num_fun;
  int max_fun;
  /* Variable size array describing functions, one per contiguous
     address range belonging to a function.  */
  struct function_info fun[1];
};

/* Allocate a struct spu_elf_stack_info with MAX_FUN struct function_info
   entries for section SEC.  */

static struct spu_elf_stack_info *
alloc_stack_info (asection *sec, int max_fun)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  bfd_size_type amt;

  amt = sizeof (struct spu_elf_stack_info);
  amt += (max_fun - 1) * sizeof (struct function_info);
  sec_data->u.i.stack_info = bfd_zmalloc (amt);
  if (sec_data->u.i.stack_info != NULL)
    sec_data->u.i.stack_info->max_fun = max_fun;
  return sec_data->u.i.stack_info;
}

/* Add a new struct function_info describing a (part of a) function
   starting at SYM_H.  Keep the array sorted by address.  */

static struct function_info *
maybe_insert_function (asection *sec,
		       void *sym_h,
		       bfd_boolean global,
		       bfd_boolean is_func)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  int i;
  bfd_vma off, size;

  if (sinfo == NULL)
    {
      sinfo = alloc_stack_info (sec, 20);
      if (sinfo == NULL)
	return NULL;
    }

  if (!global)
    {
      Elf_Internal_Sym *sym = sym_h;
      off = sym->st_value;
      size = sym->st_size;
    }
  else
    {
      struct elf_link_hash_entry *h = sym_h;
      off = h->root.u.def.value;
      size = h->size;
    }

  for (i = sinfo->num_fun; --i >= 0; )
    if (sinfo->fun[i].lo <= off)
      break;

  if (i >= 0)
    {
      /* Don't add another entry for an alias, but do update some
	 info.  */
      if (sinfo->fun[i].lo == off)
	{
	  /* Prefer globals over local syms.  */
	  if (global && !sinfo->fun[i].global)
	    {
	      sinfo->fun[i].global = TRUE;
	      sinfo->fun[i].u.h = sym_h;
	    }
	  if (is_func)
	    sinfo->fun[i].is_func = TRUE;
	  return &sinfo->fun[i];
	}
      /* Ignore a zero-size symbol inside an existing function.  */
      else if (sinfo->fun[i].hi > off && size == 0)
	return &sinfo->fun[i];
    }

  if (++i < sinfo->num_fun)
    memmove (&sinfo->fun[i + 1], &sinfo->fun[i],
	     (sinfo->num_fun - i) * sizeof (sinfo->fun[i]));
  else if (i >= sinfo->max_fun)
    {
      bfd_size_type amt = sizeof (struct spu_elf_stack_info);
      bfd_size_type old = amt;

      old += (sinfo->max_fun - 1) * sizeof (struct function_info);
      sinfo->max_fun += 20 + (sinfo->max_fun >> 1);
      amt += (sinfo->max_fun - 1) * sizeof (struct function_info);
      sinfo = bfd_realloc (sinfo, amt);
      if (sinfo == NULL)
	return NULL;
      memset ((char *) sinfo + old, 0, amt - old);
      sec_data->u.i.stack_info = sinfo;
    }
  sinfo->fun[i].is_func = is_func;
  sinfo->fun[i].global = global;
  sinfo->fun[i].sec = sec;
  if (global)
    sinfo->fun[i].u.h = sym_h;
  else
    sinfo->fun[i].u.sym = sym_h;
  sinfo->fun[i].lo = off;
  sinfo->fun[i].hi = off + size;
  sinfo->fun[i].stack = -find_function_stack_adjust (sec, off);
  sinfo->num_fun += 1;
  return &sinfo->fun[i];
}

/* Return the name of FUN.  */

static const char *
func_name (struct function_info *fun)
{
  asection *sec;
  bfd *ibfd;
  Elf_Internal_Shdr *symtab_hdr;

  while (fun->start != NULL)
    fun = fun->start;

  if (fun->global)
    return fun->u.h->root.root.string;

  sec = fun->sec;
  if (fun->u.sym->st_name == 0)
    {
      size_t len = strlen (sec->name);
      char *name = bfd_malloc (len + 10);
      if (name == NULL)
	return "(null)";
      sprintf (name, "%s+%lx", sec->name,
	       (unsigned long) fun->u.sym->st_value & 0xffffffff);
      return name;
    }
  ibfd = sec->owner;
  symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
  return bfd_elf_sym_name (ibfd, symtab_hdr, fun->u.sym, sec);
}

/* Read the instruction at OFF in SEC.  Return true iff the instruction
   is a nop, lnop, or stop 0 (all zero insn).  */

static bfd_boolean
is_nop (asection *sec, bfd_vma off)
{
  unsigned char insn[4];

  if (off + 4 > sec->size
      || !bfd_get_section_contents (sec->owner, sec, insn, off, 4))
    return FALSE;
  if ((insn[0] & 0xbf) == 0 && (insn[1] & 0xe0) == 0x20)
    return TRUE;
  if (insn[0] == 0 && insn[1] == 0 && insn[2] == 0 && insn[3] == 0)
    return TRUE;
  return FALSE;
}

/* Extend the range of FUN to cover nop padding up to LIMIT.
   Return TRUE iff some instruction other than a NOP was found.  */

static bfd_boolean
insns_at_end (struct function_info *fun, bfd_vma limit)
{
  bfd_vma off = (fun->hi + 3) & -4;

  while (off < limit && is_nop (fun->sec, off))
    off += 4;
  if (off < limit)
    {
      fun->hi = off;
      return TRUE;
    }
  fun->hi = limit;
  return FALSE;
}

/* Check and fix overlapping function ranges.  Return TRUE iff there
   are gaps in the current info we have about functions in SEC.  */

static bfd_boolean
check_function_ranges (asection *sec, struct bfd_link_info *info)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  int i;
  bfd_boolean gaps = FALSE;

  if (sinfo == NULL)
    return FALSE;

  for (i = 1; i < sinfo->num_fun; i++)
    if (sinfo->fun[i - 1].hi > sinfo->fun[i].lo)
      {
	/* Fix overlapping symbols.  */
	const char *f1 = func_name (&sinfo->fun[i - 1]);
	const char *f2 = func_name (&sinfo->fun[i]);

	info->callbacks->einfo (_("warning: %s overlaps %s\n"), f1, f2);
	sinfo->fun[i - 1].hi = sinfo->fun[i].lo;
      }
    else if (insns_at_end (&sinfo->fun[i - 1], sinfo->fun[i].lo))
      gaps = TRUE;

  if (sinfo->num_fun == 0)
    gaps = TRUE;
  else
    {
      if (sinfo->fun[0].lo != 0)
	gaps = TRUE;
      if (sinfo->fun[sinfo->num_fun - 1].hi > sec->size)
	{
	  const char *f1 = func_name (&sinfo->fun[sinfo->num_fun - 1]);

	  info->callbacks->einfo (_("warning: %s exceeds section size\n"), f1);
	  sinfo->fun[sinfo->num_fun - 1].hi = sec->size;
	}
      else if (insns_at_end (&sinfo->fun[sinfo->num_fun - 1], sec->size))
	gaps = TRUE;
    }
  return gaps;
}

/* Search current function info for a function that contains address
   OFFSET in section SEC.  */

static struct function_info *
find_function (asection *sec, bfd_vma offset, struct bfd_link_info *info)
{
  struct _spu_elf_section_data *sec_data = spu_elf_section_data (sec);
  struct spu_elf_stack_info *sinfo = sec_data->u.i.stack_info;
  int lo, hi, mid;

  lo = 0;
  hi = sinfo->num_fun;
  while (lo < hi)
    {
      mid = (lo + hi) / 2;
      if (offset < sinfo->fun[mid].lo)
	hi = mid;
      else if (offset >= sinfo->fun[mid].hi)
	lo = mid + 1;
      else
	return &sinfo->fun[mid];
    }
  info->callbacks->einfo (_("%A:0x%v not found in function table\n"),
			  sec, offset);
  return NULL;
}

/* Add CALLEE to CALLER call list if not already present.  */

static bfd_boolean
insert_callee (struct function_info *caller, struct call_info *callee)
{
  struct call_info *p;
  for (p = caller->call_list; p != NULL; p = p->next)
    if (p->fun == callee->fun)
      {
	/* Tail calls use less stack than normal calls.  Retain entry
	   for normal call over one for tail call.  */
	p->is_tail &= callee->is_tail;
	if (!p->is_tail)
	  {
	    p->fun->start = NULL;
	    p->fun->is_func = TRUE;
	  }
	return FALSE;
      }
  callee->next = caller->call_list;
  caller->call_list = callee;
  return TRUE;
}

/* Rummage through the relocs for SEC, looking for function calls.
   If CALL_TREE is true, fill in call graph.  If CALL_TREE is false,
   mark destination symbols on calls as being functions.  Also
   look at branches, which may be tail calls or go to hot/cold
   section part of same function.  */

static bfd_boolean
mark_functions_via_relocs (asection *sec,
			   struct bfd_link_info *info,
			   int call_tree)
{
  Elf_Internal_Rela *internal_relocs, *irelaend, *irela;
  Elf_Internal_Shdr *symtab_hdr = &elf_tdata (sec->owner)->symtab_hdr;
  Elf_Internal_Sym *syms;
  void *psyms;
  static bfd_boolean warned;

  internal_relocs = _bfd_elf_link_read_relocs (sec->owner, sec, NULL, NULL,
					       info->keep_memory);
  if (internal_relocs == NULL)
    return FALSE;

  symtab_hdr = &elf_tdata (sec->owner)->symtab_hdr;
  psyms = &symtab_hdr->contents;
  syms = *(Elf_Internal_Sym **) psyms;
  irela = internal_relocs;
  irelaend = irela + sec->reloc_count;
  for (; irela < irelaend; irela++)
    {
      enum elf_spu_reloc_type r_type;
      unsigned int r_indx;
      asection *sym_sec;
      Elf_Internal_Sym *sym;
      struct elf_link_hash_entry *h;
      bfd_vma val;
      unsigned char insn[4];
      bfd_boolean is_call;
      struct function_info *caller;
      struct call_info *callee;

      r_type = ELF32_R_TYPE (irela->r_info);
      if (r_type != R_SPU_REL16
	  && r_type != R_SPU_ADDR16)
	continue;

      r_indx = ELF32_R_SYM (irela->r_info);
      if (!get_sym_h (&h, &sym, &sym_sec, psyms, r_indx, sec->owner))
	return FALSE;

      if (sym_sec == NULL
	  || sym_sec->output_section == NULL
	  || sym_sec->output_section->owner != sec->output_section->owner)
	continue;

      if (!bfd_get_section_contents (sec->owner, sec, insn,
				     irela->r_offset, 4))
	return FALSE;
      if (!is_branch (insn))
	continue;

      if ((sym_sec->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE))
	  != (SEC_ALLOC | SEC_LOAD | SEC_CODE))
	{
	  if (!call_tree)
	    warned = TRUE;
	  if (!call_tree || !warned)
	    info->callbacks->einfo (_("%B(%A+0x%v): call to non-code section"
				      " %B(%A), stack analysis incomplete\n"),
				    sec->owner, sec, irela->r_offset,
				    sym_sec->owner, sym_sec);
	  continue;
	}

      is_call = (insn[0] & 0xfd) == 0x31;

      if (h)
	val = h->root.u.def.value;
      else
	val = sym->st_value;
      val += irela->r_addend;

      if (!call_tree)
	{
	  struct function_info *fun;

	  if (irela->r_addend != 0)
	    {
	      Elf_Internal_Sym *fake = bfd_zmalloc (sizeof (*fake));
	      if (fake == NULL)
		return FALSE;
	      fake->st_value = val;
	      fake->st_shndx
		= _bfd_elf_section_from_bfd_section (sym_sec->owner, sym_sec);
	      sym = fake;
	    }
	  if (sym)
	    fun = maybe_insert_function (sym_sec, sym, FALSE, is_call);
	  else
	    fun = maybe_insert_function (sym_sec, h, TRUE, is_call);
	  if (fun == NULL)
	    return FALSE;
	  if (irela->r_addend != 0
	      && fun->u.sym != sym)
	    free (sym);
	  continue;
	}

      caller = find_function (sec, irela->r_offset, info);
      if (caller == NULL)
	return FALSE;
      callee = bfd_malloc (sizeof *callee);
      if (callee == NULL)
	return FALSE;

      callee->fun = find_function (sym_sec, val, info);
      if (callee->fun == NULL)
	return FALSE;
      callee->is_tail = !is_call;
      if (!insert_callee (caller, callee))
	free (callee);
      else if (!is_call
	       && !callee->fun->is_func
	       && callee->fun->stack == 0)
	{
	  /* This is either a tail call or a branch from one part of
	     the function to another, ie. hot/cold section.  If the
	     destination has been called by some other function then
	     it is a separate function.  We also assume that functions
	     are not split across input files.  */
	  if (sec->owner != sym_sec->owner)
	    {
	      callee->fun->start = NULL;
	      callee->fun->is_func = TRUE;
	    }
	  else if (callee->fun->start == NULL)
	    callee->fun->start = caller;
	  else
	    {
	      struct function_info *callee_start;
	      struct function_info *caller_start;
	      callee_start = callee->fun;
	      while (callee_start->start)
		callee_start = callee_start->start;
	      caller_start = caller;
	      while (caller_start->start)
		caller_start = caller_start->start;
	      if (caller_start != callee_start)
		{
		  callee->fun->start = NULL;
		  callee->fun->is_func = TRUE;
		}
	    }
	}
    }

  return TRUE;
}

/* Handle something like .init or .fini, which has a piece of a function.
   These sections are pasted together to form a single function.  */

static bfd_boolean
pasted_function (asection *sec, struct bfd_link_info *info)
{
  struct bfd_link_order *l;
  struct _spu_elf_section_data *sec_data;
  struct spu_elf_stack_info *sinfo;
  Elf_Internal_Sym *fake;
  struct function_info *fun, *fun_start;

  fake = bfd_zmalloc (sizeof (*fake));
  if (fake == NULL)
    return FALSE;
  fake->st_value = 0;
  fake->st_size = sec->size;
  fake->st_shndx
    = _bfd_elf_section_from_bfd_section (sec->owner, sec);
  fun = maybe_insert_function (sec, fake, FALSE, FALSE);
  if (!fun)
    return FALSE;

  /* Find a function immediately preceding this section.  */
  fun_start = NULL;
  for (l = sec->output_section->map_head.link_order; l != NULL; l = l->next)
    {
      if (l->u.indirect.section == sec)
	{
	  if (fun_start != NULL)
	    fun->start = fun_start;
	  return TRUE;
	}
      if (l->type == bfd_indirect_link_order
	  && (sec_data = spu_elf_section_data (l->u.indirect.section)) != NULL
	  && (sinfo = sec_data->u.i.stack_info) != NULL
	  && sinfo->num_fun != 0)
	fun_start = &sinfo->fun[sinfo->num_fun - 1];
    }

  info->callbacks->einfo (_("%A link_order not found\n"), sec);
  return FALSE;
}

/* We're only interested in code sections.  Testing SEC_IN_MEMORY excludes
   overlay stub sections.  */

static bfd_boolean
interesting_section (asection *s, bfd *obfd)
{
  return (s->output_section != NULL
	  && s->output_section->owner == obfd
	  && ((s->flags & (SEC_ALLOC | SEC_LOAD | SEC_CODE | SEC_IN_MEMORY))
	      == (SEC_ALLOC | SEC_LOAD | SEC_CODE))
	  && s->size != 0);
}

/* Map address ranges in code sections to functions.  */

static bfd_boolean
discover_functions (struct bfd_link_info *info)
{
  bfd *ibfd;
  int bfd_idx;
  Elf_Internal_Sym ***psym_arr;
  asection ***sec_arr;
  bfd_boolean gaps = FALSE;

  bfd_idx = 0;
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    bfd_idx++;

  psym_arr = bfd_zmalloc (bfd_idx * sizeof (*psym_arr));
  if (psym_arr == NULL)
    return FALSE;
  sec_arr = bfd_zmalloc (bfd_idx * sizeof (*sec_arr));
  if (sec_arr == NULL)
    return FALSE;

  
  for (ibfd = info->input_bfds, bfd_idx = 0;
       ibfd != NULL;
       ibfd = ibfd->link_next, bfd_idx++)
    {
      extern const bfd_target bfd_elf32_spu_vec;
      Elf_Internal_Shdr *symtab_hdr;
      asection *sec;
      size_t symcount;
      Elf_Internal_Sym *syms, *sy, **psyms, **psy;
      asection **psecs, **p;

      if (ibfd->xvec != &bfd_elf32_spu_vec)
	continue;

      /* Read all the symbols.  */
      symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
      symcount = symtab_hdr->sh_size / symtab_hdr->sh_entsize;
      if (symcount == 0)
	continue;

      syms = (Elf_Internal_Sym *) symtab_hdr->contents;
      if (syms == NULL)
	{
	  syms = bfd_elf_get_elf_syms (ibfd, symtab_hdr, symcount, 0,
				       NULL, NULL, NULL);
	  symtab_hdr->contents = (void *) syms;
	  if (syms == NULL)
	    return FALSE;
	}

      /* Select defined function symbols that are going to be output.  */
      psyms = bfd_malloc ((symcount + 1) * sizeof (*psyms));
      if (psyms == NULL)
	return FALSE;
      psym_arr[bfd_idx] = psyms;
      psecs = bfd_malloc (symcount * sizeof (*psecs));
      if (psecs == NULL)
	return FALSE;
      sec_arr[bfd_idx] = psecs;
      for (psy = psyms, p = psecs, sy = syms; sy < syms + symcount; ++p, ++sy)
	if (ELF_ST_TYPE (sy->st_info) == STT_NOTYPE
	    || ELF_ST_TYPE (sy->st_info) == STT_FUNC)
	  {
	    asection *s;

	    *p = s = bfd_section_from_elf_index (ibfd, sy->st_shndx);
	    if (s != NULL && interesting_section (s, info->output_bfd))
	      *psy++ = sy;
	  }
      symcount = psy - psyms;
      *psy = NULL;

      /* Sort them by section and offset within section.  */
      sort_syms_syms = syms;
      sort_syms_psecs = psecs;
      qsort (psyms, symcount, sizeof (*psyms), sort_syms);

      /* Now inspect the function symbols.  */
      for (psy = psyms; psy < psyms + symcount; )
	{
	  asection *s = psecs[*psy - syms];
	  Elf_Internal_Sym **psy2;

	  for (psy2 = psy; ++psy2 < psyms + symcount; )
	    if (psecs[*psy2 - syms] != s)
	      break;

	  if (!alloc_stack_info (s, psy2 - psy))
	    return FALSE;
	  psy = psy2;
	}

      /* First install info about properly typed and sized functions.
	 In an ideal world this will cover all code sections, except
	 when partitioning functions into hot and cold sections,
	 and the horrible pasted together .init and .fini functions.  */
      for (psy = psyms; psy < psyms + symcount; ++psy)
	{
	  sy = *psy;
	  if (ELF_ST_TYPE (sy->st_info) == STT_FUNC)
	    {
	      asection *s = psecs[sy - syms];
	      if (!maybe_insert_function (s, sy, FALSE, TRUE))
		return FALSE;
	    }
	}

      for (sec = ibfd->sections; sec != NULL && !gaps; sec = sec->next)
	if (interesting_section (sec, info->output_bfd))
	  gaps |= check_function_ranges (sec, info);
    }

  if (gaps)
    {
      /* See if we can discover more function symbols by looking at
	 relocations.  */
      for (ibfd = info->input_bfds, bfd_idx = 0;
	   ibfd != NULL;
	   ibfd = ibfd->link_next, bfd_idx++)
	{
	  asection *sec;

	  if (psym_arr[bfd_idx] == NULL)
	    continue;

	  for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	    if (interesting_section (sec, info->output_bfd)
		&& sec->reloc_count != 0)
	      {
		if (!mark_functions_via_relocs (sec, info, FALSE))
		  return FALSE;
	      }
	}

      for (ibfd = info->input_bfds, bfd_idx = 0;
	   ibfd != NULL;
	   ibfd = ibfd->link_next, bfd_idx++)
	{
	  Elf_Internal_Shdr *symtab_hdr;
	  asection *sec;
	  Elf_Internal_Sym *syms, *sy, **psyms, **psy;
	  asection **psecs;

	  if ((psyms = psym_arr[bfd_idx]) == NULL)
	    continue;

	  psecs = sec_arr[bfd_idx];

	  symtab_hdr = &elf_tdata (ibfd)->symtab_hdr;
	  syms = (Elf_Internal_Sym *) symtab_hdr->contents;

	  gaps = FALSE;
	  for (sec = ibfd->sections; sec != NULL && !gaps; sec = sec->next)
	    if (interesting_section (sec, info->output_bfd))
	      gaps |= check_function_ranges (sec, info);
	  if (!gaps)
	    continue;

	  /* Finally, install all globals.  */
	  for (psy = psyms; (sy = *psy) != NULL; ++psy)
	    {
	      asection *s;

	      s = psecs[sy - syms];

	      /* Global syms might be improperly typed functions.  */
	      if (ELF_ST_TYPE (sy->st_info) != STT_FUNC
		  && ELF_ST_BIND (sy->st_info) == STB_GLOBAL)
		{
		  if (!maybe_insert_function (s, sy, FALSE, FALSE))
		    return FALSE;
		}
	    }

	  /* Some of the symbols we've installed as marking the
	     beginning of functions may have a size of zero.  Extend
	     the range of such functions to the beginning of the
	     next symbol of interest.  */
	  for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	    if (interesting_section (sec, info->output_bfd))
	      {
		struct _spu_elf_section_data *sec_data;
		struct spu_elf_stack_info *sinfo;

		sec_data = spu_elf_section_data (sec);
		sinfo = sec_data->u.i.stack_info;
		if (sinfo != NULL)
		  {
		    int fun_idx;
		    bfd_vma hi = sec->size;

		    for (fun_idx = sinfo->num_fun; --fun_idx >= 0; )
		      {
			sinfo->fun[fun_idx].hi = hi;
			hi = sinfo->fun[fun_idx].lo;
		      }
		  }
		/* No symbols in this section.  Must be .init or .fini
		   or something similar.  */
		else if (!pasted_function (sec, info))
		  return FALSE;
	      }
	}
    }

  for (ibfd = info->input_bfds, bfd_idx = 0;
       ibfd != NULL;
       ibfd = ibfd->link_next, bfd_idx++)
    {
      if (psym_arr[bfd_idx] == NULL)
	continue;

      free (psym_arr[bfd_idx]);
      free (sec_arr[bfd_idx]);
    }

  free (psym_arr);
  free (sec_arr);

  return TRUE;
}

/* Mark nodes in the call graph that are called by some other node.  */

static void
mark_non_root (struct function_info *fun)
{
  struct call_info *call;

  fun->visit1 = TRUE;
  for (call = fun->call_list; call; call = call->next)
    {
      call->fun->non_root = TRUE;
      if (!call->fun->visit1)
	mark_non_root (call->fun);
    }
}

/* Remove cycles from the call graph.  */

static void
call_graph_traverse (struct function_info *fun, struct bfd_link_info *info)
{
  struct call_info **callp, *call;

  fun->visit2 = TRUE;
  fun->marking = TRUE;

  callp = &fun->call_list;
  while ((call = *callp) != NULL)
    {
      if (!call->fun->visit2)
	call_graph_traverse (call->fun, info);
      else if (call->fun->marking)
	{
	  const char *f1 = func_name (fun);
	  const char *f2 = func_name (call->fun);

	  info->callbacks->info (_("Stack analysis will ignore the call "
				   "from %s to %s\n"),
				 f1, f2);
	  *callp = call->next;
	  continue;
	}
      callp = &call->next;
    }
  fun->marking = FALSE;
}

/* Populate call_list for each function.  */

static bfd_boolean
build_call_tree (struct bfd_link_info *info)
{
  bfd *ibfd;

  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    {
      extern const bfd_target bfd_elf32_spu_vec;
      asection *sec;

      if (ibfd->xvec != &bfd_elf32_spu_vec)
	continue;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  if (!interesting_section (sec, info->output_bfd)
	      || sec->reloc_count == 0)
	    continue;

	  if (!mark_functions_via_relocs (sec, info, TRUE))
	    return FALSE;
	}

      /* Transfer call info from hot/cold section part of function
	 to main entry.  */
      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  struct _spu_elf_section_data *sec_data;
	  struct spu_elf_stack_info *sinfo;

	  if ((sec_data = spu_elf_section_data (sec)) != NULL
	      && (sinfo = sec_data->u.i.stack_info) != NULL)
	    {
	      int i;
	      for (i = 0; i < sinfo->num_fun; ++i)
		{
		  struct function_info *start = sinfo->fun[i].start;

		  if (start != NULL)
		    {
		      struct call_info *call;

		      while (start->start != NULL)
			start = start->start;
		      call = sinfo->fun[i].call_list;
		      while (call != NULL)
			{
			  struct call_info *call_next = call->next;
			  if (!insert_callee (start, call))
			    free (call);
			  call = call_next;
			}
		      sinfo->fun[i].call_list = NULL;
		      sinfo->fun[i].non_root = TRUE;
		    }
		}
	    }
	}
    }

  /* Find the call graph root(s).  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    {
      extern const bfd_target bfd_elf32_spu_vec;
      asection *sec;

      if (ibfd->xvec != &bfd_elf32_spu_vec)
	continue;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  struct _spu_elf_section_data *sec_data;
	  struct spu_elf_stack_info *sinfo;

	  if ((sec_data = spu_elf_section_data (sec)) != NULL
	      && (sinfo = sec_data->u.i.stack_info) != NULL)
	    {
	      int i;
	      for (i = 0; i < sinfo->num_fun; ++i)
		if (!sinfo->fun[i].visit1)
		  mark_non_root (&sinfo->fun[i]);
	    }
	}
    }

  /* Remove cycles from the call graph.  We start from the root node(s)
     so that we break cycles in a reasonable place.  */
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    {
      extern const bfd_target bfd_elf32_spu_vec;
      asection *sec;

      if (ibfd->xvec != &bfd_elf32_spu_vec)
	continue;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  struct _spu_elf_section_data *sec_data;
	  struct spu_elf_stack_info *sinfo;

	  if ((sec_data = spu_elf_section_data (sec)) != NULL
	      && (sinfo = sec_data->u.i.stack_info) != NULL)
	    {
	      int i;
	      for (i = 0; i < sinfo->num_fun; ++i)
		if (!sinfo->fun[i].non_root)
		  call_graph_traverse (&sinfo->fun[i], info);
	    }
	}
    }

  return TRUE;
}

/* Descend the call graph for FUN, accumulating total stack required.  */

static bfd_vma
sum_stack (struct function_info *fun,
	   struct bfd_link_info *info,
	   int emit_stack_syms)
{
  struct call_info *call;
  struct function_info *max = NULL;
  bfd_vma max_stack = fun->stack;
  bfd_vma stack;
  const char *f1;

  if (fun->visit3)
    return max_stack;

  for (call = fun->call_list; call; call = call->next)
    {
      stack = sum_stack (call->fun, info, emit_stack_syms);
      /* Include caller stack for normal calls, don't do so for
	 tail calls.  fun->stack here is local stack usage for
	 this function.  */
      if (!call->is_tail)
	stack += fun->stack;
      if (max_stack < stack)
	{
	  max_stack = stack;
	  max = call->fun;
	}
    }

  f1 = func_name (fun);
  info->callbacks->minfo (_("%s: 0x%v 0x%v\n"),
			  f1, (bfd_vma) fun->stack, max_stack);

  if (fun->call_list)
    {
      info->callbacks->minfo (_("  calls:\n"));
      for (call = fun->call_list; call; call = call->next)
	{
	  const char *f2 = func_name (call->fun);
	  const char *ann1 = call->fun == max ? "*" : " ";
	  const char *ann2 = call->is_tail ? "t" : " ";

	  info->callbacks->minfo (_("   %s%s %s\n"), ann1, ann2, f2);
	}
    }

  /* Now fun->stack holds cumulative stack.  */
  fun->stack = max_stack;
  fun->visit3 = TRUE;

  if (emit_stack_syms)
    {
      struct spu_link_hash_table *htab = spu_hash_table (info);
      char *name = bfd_malloc (18 + strlen (f1));
      struct elf_link_hash_entry *h;

      if (name != NULL)
	{
	  if (fun->global || ELF_ST_BIND (fun->u.sym->st_info) == STB_GLOBAL)
	    sprintf (name, "__stack_%s", f1);
	  else
	    sprintf (name, "__stack_%x_%s", fun->sec->id & 0xffffffff, f1);

	  h = elf_link_hash_lookup (&htab->elf, name, TRUE, TRUE, FALSE);
	  free (name);
	  if (h != NULL
	      && (h->root.type == bfd_link_hash_new
		  || h->root.type == bfd_link_hash_undefined
		  || h->root.type == bfd_link_hash_undefweak))
	    {
	      h->root.type = bfd_link_hash_defined;
	      h->root.u.def.section = bfd_abs_section_ptr;
	      h->root.u.def.value = max_stack;
	      h->size = 0;
	      h->type = 0;
	      h->ref_regular = 1;
	      h->def_regular = 1;
	      h->ref_regular_nonweak = 1;
	      h->forced_local = 1;
	      h->non_elf = 0;
	    }
	}
    }

  return max_stack;
}

/* Provide an estimate of total stack required.  */

static bfd_boolean
spu_elf_stack_analysis (struct bfd_link_info *info, int emit_stack_syms)
{
  bfd *ibfd;
  bfd_vma max_stack = 0;

  if (!discover_functions (info))
    return FALSE;

  if (!build_call_tree (info))
    return FALSE;

  info->callbacks->info (_("Stack size for call graph root nodes.\n"));
  info->callbacks->minfo (_("\nStack size for functions.  "
			    "Annotations: '*' max stack, 't' tail call\n"));
  for (ibfd = info->input_bfds; ibfd != NULL; ibfd = ibfd->link_next)
    {
      extern const bfd_target bfd_elf32_spu_vec;
      asection *sec;

      if (ibfd->xvec != &bfd_elf32_spu_vec)
	continue;

      for (sec = ibfd->sections; sec != NULL; sec = sec->next)
	{
	  struct _spu_elf_section_data *sec_data;
	  struct spu_elf_stack_info *sinfo;

	  if ((sec_data = spu_elf_section_data (sec)) != NULL
	      && (sinfo = sec_data->u.i.stack_info) != NULL)
	    {
	      int i;
	      for (i = 0; i < sinfo->num_fun; ++i)
		{
		  if (!sinfo->fun[i].non_root)
		    {
		      bfd_vma stack;
		      const char *f1;

		      stack = sum_stack (&sinfo->fun[i], info,
					 emit_stack_syms);
		      f1 = func_name (&sinfo->fun[i]);
		      info->callbacks->info (_("  %s: 0x%v\n"),
					      f1, stack);
		      if (max_stack < stack)
			max_stack = stack;
		    }
		}
	    }
	}
    }

  info->callbacks->info (_("Maximum stack required is 0x%v\n"), max_stack);
  return TRUE;
}

/* Perform a final link.  */

static bfd_boolean
spu_elf_final_link (bfd *output_bfd, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (htab->stack_analysis
      && !spu_elf_stack_analysis (info, htab->emit_stack_syms))
    info->callbacks->einfo ("%X%P: stack analysis error: %E\n");

  return bfd_elf_final_link (output_bfd, info);
}

/* Called when not normally emitting relocs, ie. !info->relocatable
   and !info->emitrelocations.  Returns a count of special relocs
   that need to be emitted.  */

static unsigned int
spu_elf_count_relocs (asection *sec, Elf_Internal_Rela *relocs)
{
  unsigned int count = 0;
  Elf_Internal_Rela *relend = relocs + sec->reloc_count;

  for (; relocs < relend; relocs++)
    {
      int r_type = ELF32_R_TYPE (relocs->r_info);
      if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
	++count;
    }

  return count;
}

/* Apply RELOCS to CONTENTS of INPUT_SECTION from INPUT_BFD.  */

static int
spu_elf_relocate_section (bfd *output_bfd,
			  struct bfd_link_info *info,
			  bfd *input_bfd,
			  asection *input_section,
			  bfd_byte *contents,
			  Elf_Internal_Rela *relocs,
			  Elf_Internal_Sym *local_syms,
			  asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  Elf_Internal_Rela *rel, *relend;
  struct spu_link_hash_table *htab;
  int ret = TRUE;
  bfd_boolean emit_these_relocs = FALSE;
  bfd_boolean stubs;

  htab = spu_hash_table (info);
  stubs = (htab->stub_sec != NULL
	   && maybe_needs_stubs (input_section, output_bfd));
  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  sym_hashes = (struct elf_link_hash_entry **) (elf_sym_hashes (input_bfd));

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      int r_type;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      Elf_Internal_Sym *sym;
      asection *sec;
      struct elf_link_hash_entry *h;
      const char *sym_name;
      bfd_vma relocation;
      bfd_vma addend;
      bfd_reloc_status_type r;
      bfd_boolean unresolved_reloc;
      bfd_boolean warned;

      r_symndx = ELF32_R_SYM (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);
      if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
	{
	  emit_these_relocs = TRUE;
	  continue;
	}

      howto = elf_howto_table + r_type;
      unresolved_reloc = FALSE;
      warned = FALSE;
      h = NULL;
      sym = NULL;
      sec = NULL;
      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  sym_name = bfd_elf_sym_name (input_bfd, symtab_hdr, sym, sec);
	  relocation = _bfd_elf_rela_local_sym (output_bfd, sym, &sec, rel);
	}
      else
	{
	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation,
				   unresolved_reloc, warned);
	  sym_name = h->root.root.string;
	}

      if (sec != NULL && elf_discarded_section (sec))
	{
	  /* For relocs against symbols from removed linkonce sections,
	     or sections discarded by a linker script, we just want the
	     section contents zeroed.  Avoid any special processing.  */
	  _bfd_clear_contents (howto, input_bfd, contents + rel->r_offset);
	  rel->r_info = 0;
	  rel->r_addend = 0;
	  continue;
	}

      if (info->relocatable)
	continue;

      if (unresolved_reloc)
	{
	  (*_bfd_error_handler)
	    (_("%B(%s+0x%lx): unresolvable %s relocation against symbol `%s'"),
	     input_bfd,
	     bfd_get_section_name (input_bfd, input_section),
	     (long) rel->r_offset,
	     howto->name,
	     sym_name);
	  ret = FALSE;
	}

      /* If this symbol is in an overlay area, we may need to relocate
	 to the overlay stub.  */
      addend = rel->r_addend;
      if (stubs)
	{
	  enum _stub_type stub_type;

	  stub_type = needs_ovl_stub (h, sym, sec, input_section, rel,
				      contents, info);
	  if (stub_type != no_stub)
	    {
	      unsigned int ovl = 0;
	      struct got_entry *g, **head;

	      if (stub_type != nonovl_stub)
		ovl = (spu_elf_section_data (input_section->output_section)
		       ->u.o.ovl_index);

	      if (h != NULL)
		head = &h->got.glist;
	      else
		head = elf_local_got_ents (input_bfd) + r_symndx;

	      for (g = *head; g != NULL; g = g->next)
		if (g->addend == addend && (g->ovl == ovl || g->ovl == 0))
		  break;
	      if (g == NULL)
		abort ();

	      relocation = g->stub_addr;
	      addend = 0;
	    }
	}

      r = _bfd_final_link_relocate (howto,
				    input_bfd,
				    input_section,
				    contents,
				    rel->r_offset, relocation, addend);

      if (r != bfd_reloc_ok)
	{
	  const char *msg = (const char *) 0;

	  switch (r)
	    {
	    case bfd_reloc_overflow:
	      if (!((*info->callbacks->reloc_overflow)
		    (info, (h ? &h->root : NULL), sym_name, howto->name,
		     (bfd_vma) 0, input_bfd, input_section, rel->r_offset)))
		return FALSE;
	      break;

	    case bfd_reloc_undefined:
	      if (!((*info->callbacks->undefined_symbol)
		    (info, sym_name, input_bfd, input_section,
		     rel->r_offset, TRUE)))
		return FALSE;
	      break;

	    case bfd_reloc_outofrange:
	      msg = _("internal error: out of range error");
	      goto common_error;

	    case bfd_reloc_notsupported:
	      msg = _("internal error: unsupported relocation error");
	      goto common_error;

	    case bfd_reloc_dangerous:
	      msg = _("internal error: dangerous error");
	      goto common_error;

	    default:
	      msg = _("internal error: unknown error");
	      /* fall through */

	    common_error:
	      ret = FALSE;
	      if (!((*info->callbacks->warning)
		    (info, msg, sym_name, input_bfd, input_section,
		     rel->r_offset)))
		return FALSE;
	      break;
	    }
	}
    }

  if (ret
      && emit_these_relocs
      && !info->relocatable
      && !info->emitrelocations)
    {
      Elf_Internal_Rela *wrel;
      Elf_Internal_Shdr *rel_hdr;

      wrel = rel = relocs;
      relend = relocs + input_section->reloc_count;
      for (; rel < relend; rel++)
	{
	  int r_type;

	  r_type = ELF32_R_TYPE (rel->r_info);
	  if (r_type == R_SPU_PPU32 || r_type == R_SPU_PPU64)
	    *wrel++ = *rel;
	}
      input_section->reloc_count = wrel - relocs;
      /* Backflips for _bfd_elf_link_output_relocs.  */
      rel_hdr = &elf_section_data (input_section)->rel_hdr;
      rel_hdr->sh_size = input_section->reloc_count * rel_hdr->sh_entsize;
      ret = 2;
    }

  return ret;
}

/* Adjust _SPUEAR_ syms to point at their overlay stubs.  */

static bfd_boolean
spu_elf_output_symbol_hook (struct bfd_link_info *info,
			    const char *sym_name ATTRIBUTE_UNUSED,
			    Elf_Internal_Sym *sym,
			    asection *sym_sec ATTRIBUTE_UNUSED,
			    struct elf_link_hash_entry *h)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);

  if (!info->relocatable
      && htab->stub_sec != NULL
      && h != NULL
      && (h->root.type == bfd_link_hash_defined
	  || h->root.type == bfd_link_hash_defweak)
      && h->def_regular
      && strncmp (h->root.root.string, "_SPUEAR_", 8) == 0)
    {
      struct got_entry *g;

      for (g = h->got.glist; g != NULL; g = g->next)
	if (g->addend == 0 && g->ovl == 0)
	  {
	    sym->st_shndx = (_bfd_elf_section_from_bfd_section
			     (htab->stub_sec[0]->output_section->owner,
			      htab->stub_sec[0]->output_section));
	    sym->st_value = g->stub_addr;
	    break;
	  }
    }

  return TRUE;
}

static int spu_plugin = 0;

void
spu_elf_plugin (int val)
{
  spu_plugin = val;
}

/* Set ELF header e_type for plugins.  */

static void
spu_elf_post_process_headers (bfd *abfd,
			      struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  if (spu_plugin)
    {
      Elf_Internal_Ehdr *i_ehdrp = elf_elfheader (abfd);

      i_ehdrp->e_type = ET_DYN;
    }
}

/* We may add an extra PT_LOAD segment for .toe.  We also need extra
   segments for overlays.  */

static int
spu_elf_additional_program_headers (bfd *abfd, struct bfd_link_info *info)
{
  struct spu_link_hash_table *htab = spu_hash_table (info);
  int extra = htab->num_overlays;
  asection *sec;

  if (extra)
    ++extra;

  sec = bfd_get_section_by_name (abfd, ".toe");
  if (sec != NULL && (sec->flags & SEC_LOAD) != 0)
    ++extra;

  return extra;
}

/* Remove .toe section from other PT_LOAD segments and put it in
   a segment of its own.  Put overlays in separate segments too.  */

static bfd_boolean
spu_elf_modify_segment_map (bfd *abfd, struct bfd_link_info *info)
{
  asection *toe, *s;
  struct elf_segment_map *m;
  unsigned int i;

  if (info == NULL)
    return TRUE;

  toe = bfd_get_section_by_name (abfd, ".toe");
  for (m = elf_tdata (abfd)->segment_map; m != NULL; m = m->next)
    if (m->p_type == PT_LOAD && m->count > 1)
      for (i = 0; i < m->count; i++)
	if ((s = m->sections[i]) == toe
	    || spu_elf_section_data (s)->u.o.ovl_index != 0)
	  {
	    struct elf_segment_map *m2;
	    bfd_vma amt;

	    if (i + 1 < m->count)
	      {
		amt = sizeof (struct elf_segment_map);
		amt += (m->count - (i + 2)) * sizeof (m->sections[0]);
		m2 = bfd_zalloc (abfd, amt);
		if (m2 == NULL)
		  return FALSE;
		m2->count = m->count - (i + 1);
		memcpy (m2->sections, m->sections + i + 1,
			m2->count * sizeof (m->sections[0]));
		m2->p_type = PT_LOAD;
		m2->next = m->next;
		m->next = m2;
	      }
	    m->count = 1;
	    if (i != 0)
	      {
		m->count = i;
		amt = sizeof (struct elf_segment_map);
		m2 = bfd_zalloc (abfd, amt);
		if (m2 == NULL)
		  return FALSE;
		m2->p_type = PT_LOAD;
		m2->count = 1;
		m2->sections[0] = s;
		m2->next = m->next;
		m->next = m2;
	      }
	    break;
	  }

  return TRUE;
}

/* Tweak the section type of .note.spu_name.  */

static bfd_boolean
spu_elf_fake_sections (bfd *obfd ATTRIBUTE_UNUSED,
		       Elf_Internal_Shdr *hdr,
		       asection *sec)
{
  if (strcmp (sec->name, SPU_PTNOTE_SPUNAME) == 0)
    hdr->sh_type = SHT_NOTE;
  return TRUE;
}

/* Tweak phdrs before writing them out.  */

static int
spu_elf_modify_program_headers (bfd *abfd, struct bfd_link_info *info)
{
  const struct elf_backend_data *bed;
  struct elf_obj_tdata *tdata;
  Elf_Internal_Phdr *phdr, *last;
  struct spu_link_hash_table *htab;
  unsigned int count;
  unsigned int i;

  if (info == NULL)
    return TRUE;

  bed = get_elf_backend_data (abfd);
  tdata = elf_tdata (abfd);
  phdr = tdata->phdr;
  count = tdata->program_header_size / bed->s->sizeof_phdr;
  htab = spu_hash_table (info);
  if (htab->num_overlays != 0)
    {
      struct elf_segment_map *m;
      unsigned int o;

      for (i = 0, m = elf_tdata (abfd)->segment_map; m; ++i, m = m->next)
	if (m->count != 0
	    && (o = spu_elf_section_data (m->sections[0])->u.o.ovl_index) != 0)
	  {
	    /* Mark this as an overlay header.  */
	    phdr[i].p_flags |= PF_OVERLAY;

	    if (htab->ovtab != NULL && htab->ovtab->size != 0)
	      {
		bfd_byte *p = htab->ovtab->contents;
		unsigned int off = o * 16 + 8;

		/* Write file_off into _ovly_table.  */
		bfd_put_32 (htab->ovtab->owner, phdr[i].p_offset, p + off);
	      }
	  }
    }

  /* Round up p_filesz and p_memsz of PT_LOAD segments to multiples
     of 16.  This should always be possible when using the standard
     linker scripts, but don't create overlapping segments if
     someone is playing games with linker scripts.  */
  last = NULL;
  for (i = count; i-- != 0; )
    if (phdr[i].p_type == PT_LOAD)
      {
	unsigned adjust;

	adjust = -phdr[i].p_filesz & 15;
	if (adjust != 0
	    && last != NULL
	    && phdr[i].p_offset + phdr[i].p_filesz > last->p_offset - adjust)
	  break;

	adjust = -phdr[i].p_memsz & 15;
	if (adjust != 0
	    && last != NULL
	    && phdr[i].p_filesz != 0
	    && phdr[i].p_vaddr + phdr[i].p_memsz > last->p_vaddr - adjust
	    && phdr[i].p_vaddr + phdr[i].p_memsz <= last->p_vaddr)
	  break;

	if (phdr[i].p_filesz != 0)
	  last = &phdr[i];
      }

  if (i == (unsigned int) -1)
    for (i = count; i-- != 0; )
      if (phdr[i].p_type == PT_LOAD)
	{
	unsigned adjust;

	adjust = -phdr[i].p_filesz & 15;
	phdr[i].p_filesz += adjust;

	adjust = -phdr[i].p_memsz & 15;
	phdr[i].p_memsz += adjust;
      }

  return TRUE;
}

#define TARGET_BIG_SYM		bfd_elf32_spu_vec
#define TARGET_BIG_NAME		"elf32-spu"
#define ELF_ARCH		bfd_arch_spu
#define ELF_MACHINE_CODE	EM_SPU
/* This matches the alignment need for DMA.  */
#define ELF_MAXPAGESIZE		0x80
#define elf_backend_rela_normal         1
#define elf_backend_can_gc_sections	1

#define bfd_elf32_bfd_reloc_type_lookup		spu_elf_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup	spu_elf_reloc_name_lookup
#define elf_info_to_howto			spu_elf_info_to_howto
#define elf_backend_count_relocs		spu_elf_count_relocs
#define elf_backend_relocate_section		spu_elf_relocate_section
#define elf_backend_symbol_processing		spu_elf_backend_symbol_processing
#define elf_backend_link_output_symbol_hook	spu_elf_output_symbol_hook
#define bfd_elf32_new_section_hook		spu_elf_new_section_hook
#define bfd_elf32_bfd_link_hash_table_create	spu_elf_link_hash_table_create

#define elf_backend_additional_program_headers	spu_elf_additional_program_headers
#define elf_backend_modify_segment_map		spu_elf_modify_segment_map
#define elf_backend_modify_program_headers	spu_elf_modify_program_headers
#define elf_backend_post_process_headers        spu_elf_post_process_headers
#define elf_backend_fake_sections		spu_elf_fake_sections
#define elf_backend_special_sections		spu_elf_special_sections
#define bfd_elf32_bfd_final_link		spu_elf_final_link

#include "elf32-target.h"
