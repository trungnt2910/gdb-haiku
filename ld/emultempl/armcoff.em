# This shell script emits a C file. -*- C -*-
# It does some substitutions.
fragment <<EOF
/* This file is is generated by a shell script.  DO NOT EDIT! */

/* emulate the original gld for the given ${EMULATION_NAME}
   Copyright 1991, 1993, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003,
   2004, 2005, 2007 Free Software Foundation, Inc.
   Written by Steve Chamberlain steve@cygnus.com

   This file is part of the GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#define TARGET_IS_${EMULATION_NAME}

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "getopt.h"

#include "ld.h"
#include "ldmain.h"
#include "ldmisc.h"

#include "ldexp.h"
#include "ldlang.h"
#include "ldfile.h"
#include "ldemul.h"

/* If TRUE, then interworking stubs which support calls to old,
   non-interworking aware ARM code should be generated.  */

static int support_old_code = 0;
static char * thumb_entry_symbol = NULL;

#define OPTION_SUPPORT_OLD_CODE		300
#define OPTION_THUMB_ENTRY		301

static void
gld${EMULATION_NAME}_add_options
  (int ns ATTRIBUTE_UNUSED, char **shortopts ATTRIBUTE_UNUSED, int nl,
   struct option **longopts, int nrl ATTRIBUTE_UNUSED,
   struct option **really_longopts ATTRIBUTE_UNUSED)
{
  static const struct option xtra_long[] = {
    {"support-old-code", no_argument, NULL, OPTION_SUPPORT_OLD_CODE},
    {"thumb-entry", required_argument, NULL, OPTION_THUMB_ENTRY},
    {NULL, no_argument, NULL, 0}
  };

  *longopts = xrealloc (*longopts,
			nl * sizeof (struct option) + sizeof (xtra_long));
  memcpy (*longopts + nl, &xtra_long, sizeof (xtra_long));
}

static void
gld${EMULATION_NAME}_list_options (FILE *file)
{
  fprintf (file, _("  --support-old-code   Support interworking with old code\n"));
  fprintf (file, _("  --thumb-entry=<sym>  Set the entry point to be Thumb symbol <sym>\n"));
}

static bfd_boolean
gld${EMULATION_NAME}_handle_option (int optc)
{
  switch (optc)
    {
    default:
      return FALSE;

    case OPTION_SUPPORT_OLD_CODE:
      support_old_code = 1;
      break;

    case OPTION_THUMB_ENTRY:
      thumb_entry_symbol = optarg;
      break;
    }

  return TRUE;
}

static void
gld${EMULATION_NAME}_before_parse (void)
{
#ifndef TARGET_			/* I.e., if not generic.  */
  ldfile_set_output_arch ("`echo ${ARCH}`", bfd_arch_unknown);
#endif /* not TARGET_ */
}

/* This is called after the sections have been attached to output
   sections, but before any sizes or addresses have been set.  */

static void
gld${EMULATION_NAME}_before_allocation (void)
{
  /* we should be able to set the size of the interworking stub section */

  /* Here we rummage through the found bfds to collect glue information */
  /* FIXME: should this be based on a command line option? krk@cygnus.com */
  {
    LANG_FOR_EACH_INPUT_STATEMENT (is)
      {
	if (! bfd_arm_process_before_allocation
	    (is->the_bfd, & link_info, support_old_code))
	  {
	    /* xgettext:c-format */
	    einfo (_("Errors encountered processing file %s"), is->filename);
	  }
      }
  }

  /* We have seen it all. Allocate it, and carry on */
  bfd_arm_allocate_interworking_sections (& link_info);

  before_allocation_default ();
}

static void
gld${EMULATION_NAME}_after_open (void)
{
  if (strstr (bfd_get_target (output_bfd), "arm") == NULL)
    {
      /* The arm backend needs special fields in the output hash structure.
	 These will only be created if the output format is an arm format,
	 hence we do not support linking and changing output formats at the
	 same time.  Use a link followed by objcopy to change output formats.  */
      einfo ("%F%X%P: error: cannot change output format whilst linking ARM binaries\n");
      return;
    }

  {
    LANG_FOR_EACH_INPUT_STATEMENT (is)
      {
	if (bfd_arm_get_bfd_for_interworking (is->the_bfd, & link_info))
	  break;
      }
  }
}

static void
gld${EMULATION_NAME}_finish (void)
{
  if (thumb_entry_symbol != NULL)
    {
      struct bfd_link_hash_entry * h;

      h = bfd_link_hash_lookup (link_info.hash, thumb_entry_symbol,
				FALSE, FALSE, TRUE);

      if (h != (struct bfd_link_hash_entry *) NULL
	  && (h->type == bfd_link_hash_defined
	      || h->type == bfd_link_hash_defweak)
	  && h->u.def.section->output_section != NULL)
	{
	  static char buffer[32];
	  bfd_vma val;

	  /* Special procesing is required for a Thumb entry symbol.  The
	     bottom bit of its address must be set.  */
	  val = (h->u.def.value
		 + bfd_get_section_vma (output_bfd,
					h->u.def.section->output_section)
		 + h->u.def.section->output_offset);

	  val |= 1;

	  /* Now convert this value into a string and store it in entry_symbol
	     where the lang_finish() function will pick it up.  */
	  buffer[0] = '0';
	  buffer[1] = 'x';

	  sprintf_vma (buffer + 2, val);

	  if (entry_symbol.name != NULL && entry_from_cmdline)
	    einfo (_("%P: warning: '--thumb-entry %s' is overriding '-e %s'\n"),
		   thumb_entry_symbol, entry_symbol.name);
	  entry_symbol.name = buffer;
	}
      else
	einfo (_("%P: warning: cannot find thumb start symbol %s\n"),
	       thumb_entry_symbol);
    }

  finish_default ();
}

static char *
gld${EMULATION_NAME}_get_script (int *isfile)
EOF

if test -n "$COMPILE_IN"
then
# Scripts compiled in.

# sed commands to quote an ld script as a C string.
sc="-f stringify.sed"

fragment <<EOF
{
  *isfile = 0;

  if (link_info.relocatable && config.build_constructors)
    return
EOF
sed $sc ldscripts/${EMULATION_NAME}.xu                 >> e${EMULATION_NAME}.c
echo '  ; else if (link_info.relocatable) return'     >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.xr                 >> e${EMULATION_NAME}.c
echo '  ; else if (!config.text_read_only) return'     >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.xbn                >> e${EMULATION_NAME}.c
echo '  ; else if (!config.magic_demand_paged) return' >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.xn                 >> e${EMULATION_NAME}.c
echo '  ; else return'                                 >> e${EMULATION_NAME}.c
sed $sc ldscripts/${EMULATION_NAME}.x                  >> e${EMULATION_NAME}.c
echo '; }'                                             >> e${EMULATION_NAME}.c

else
# Scripts read from the filesystem.

fragment <<EOF
{
  *isfile = 1;

  if (link_info.relocatable && config.build_constructors)
    return "ldscripts/${EMULATION_NAME}.xu";
  else if (link_info.relocatable)
    return "ldscripts/${EMULATION_NAME}.xr";
  else if (!config.text_read_only)
    return "ldscripts/${EMULATION_NAME}.xbn";
  else if (!config.magic_demand_paged)
    return "ldscripts/${EMULATION_NAME}.xn";
  else
    return "ldscripts/${EMULATION_NAME}.x";
}
EOF

fi

fragment <<EOF

struct ld_emulation_xfer_struct ld_${EMULATION_NAME}_emulation =
{
  gld${EMULATION_NAME}_before_parse,
  syslib_default,
  hll_default,
  after_parse_default,
  gld${EMULATION_NAME}_after_open,
  after_allocation_default,
  set_output_arch_default,
  ldemul_default_target,
  gld${EMULATION_NAME}_before_allocation,
  gld${EMULATION_NAME}_get_script,
  "${EMULATION_NAME}",
  "${OUTPUT_FORMAT}",
  gld${EMULATION_NAME}_finish,
  NULL,	/* create output section statements */
  NULL,	/* open dynamic archive */
  NULL,	/* place orphan */
  NULL,	/* set symbols */
  NULL, /* parse_args */
  gld${EMULATION_NAME}_add_options,
  gld${EMULATION_NAME}_handle_option,
  NULL,	/* unrecognised file */
  gld${EMULATION_NAME}_list_options,
  NULL,	/* recognized file */
  NULL,	/* find_potential_libraries */
  NULL	/* new_vers_pattern */
};
EOF
