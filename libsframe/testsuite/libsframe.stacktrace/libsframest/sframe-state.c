/* sframe-state.c - The SFrame state for stacktracing.

   Copyright (C) 2023 Free Software Foundation, Inc.

   This file is part of libsframest.

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

#include "config.h"
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <execinfo.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <ucontext.h>
#include <stdarg.h>
#include "ansidecl.h"
#include "sframe-api.h"
#include "sframe-stacktrace-api.h"
#include "sframe-stacktrace-regs.h"
#include "sframe-state.h"

#define _sf_printflike_(string_index, first_to_check) ATTRIBUTE_PRINTF (1, 2)

static bool _sframe_unwind_debug;	/* Control for printing out debug info.  */
static const int no_of_entries = NUM_OF_DSOS;

void
sframe_unwind_init_debug (void)
{
  static int inited;

  if (!inited)
    {
      _sframe_unwind_debug = getenv ("SFRAME_UNWIND_DEBUG") != NULL;
      inited = 1;
    }
}

_sf_printflike_ (1, 2)
static void
debug_printf (const char *format, ...)
{
  if (_sframe_unwind_debug == true)
    {
      va_list args;

      va_start (args, format);
      __builtin_vprintf (format, args);
      va_end (args);
    }
}

#if 0
/* sframe_bt_set_errno - Store the specified error code ERROR into ERRP if
   it is non-NULL.  */

static void
sframe_bt_set_errno (int *errp, int error)
{
  if (errp != NULL)
    *errp = error;
}

#endif

/* Add .sframe info in D_DATA, which is associated with
   a dynamic shared object, to D_LIST.  */

static int
sframe_add_dso (struct sframe_stinfo_list *d_list,
		struct sframe_stinfo d_data)
{
  int err = 0;

  if (!d_list->alloced)
    {
      d_list->entry = malloc (no_of_entries * sizeof (struct sframe_stinfo));
      if (!d_list->entry)
	return sframe_bt_ret_set_errno (&err, SFRAME_BT_ERR_MALLOC);

      memset (d_list->entry, 0,
	      no_of_entries * sizeof (struct sframe_stinfo));
      d_list->alloced = no_of_entries;
    }
  else if (d_list->used == d_list->alloced)
    {
      d_list->entry = realloc (d_list->entry,
			       ((d_list->alloced + no_of_entries)
				* sizeof (struct sframe_stinfo)));
      if (!d_list->entry)
	return sframe_bt_ret_set_errno (&err, SFRAME_BT_ERR_REALLOC);

      memset (&d_list->entry[d_list->alloced], 0,
	      no_of_entries * sizeof (struct sframe_stinfo));
      d_list->alloced += no_of_entries;
    }

  sframe_bt_ret_set_errno (&err, SFRAME_BT_OK);
  d_list->entry[d_list->used++] = d_data;

  return SFRAME_BT_OK;
}

/* Free up space allocated for .sframe info for CF.  */

void
sframe_free_cfi (struct sframe_state *sf)
{
  struct sframe_stinfo_list *d_list;
  int i;

  if (!sf)
    return;

  // free (sf->sui_ctx.sfdd_data);
  sframe_decoder_free (&sf->sui_ctx.sfdd_sframe_ctx);
  close (sf->sui_fd);

  d_list = &sf-> sui_dsos;
  if (!d_list)
    return;

  for (i = 0; i < d_list->used; ++i)
    {
      // free (d_list->entry[i].sfdd_data);
      sframe_decoder_free (&d_list->entry[i].sfdd_sframe_ctx);
    }

  free (d_list->entry);
}

/* Find the decode data that contains ADDR from CF.
   Return the pointer to the decode data or NULL.  */

struct sframe_stinfo *
sframe_find_context (struct sframe_state *sf, uint64_t addr)
{
  struct sframe_stinfo_list *d_list;
  struct sframe_stinfo sdec_data;
  int i;

  if (!sf)
    return NULL;

  if (sf->sui_ctx.sfdd_text_vma < addr
      && sf->sui_ctx.sfdd_text_vma + sf->sui_ctx.sfdd_text_size > addr)
    return &sf->sui_ctx;

  d_list = &sf->sui_dsos;
  for (i = 0; i < sf->sui_dsos.used; ++i)
    {
      sdec_data = d_list->entry[i];
      if ((sdec_data.sfdd_text_vma <= addr)
	  && (sdec_data.sfdd_text_vma + sdec_data.sfdd_text_size >= addr))
	return &d_list->entry[i];
    }

  return NULL;
}

/* Call decoder to create and set up the SFrame info for either the main module
   or one of the DSOs from CF, based on the input RADDR argument.  Return the
   newly created decode context or NULL.  */

sframe_decoder_ctx *
sframe_load_ctx (struct sframe_state *sf, uint64_t raddr)
{
  sframe_decoder_ctx *nctx;
  struct sframe_stinfo *cdp;

  if (!sf)
    return NULL;

  cdp = sframe_find_context (sf, raddr);
  if (!cdp)
    return NULL;

  if (!cdp->sfdd_sframe_ctx)
    {
      int err;
      nctx = sframe_decode (cdp->sfdd_data, cdp->sfdd_data_size, &err);
      if (!nctx)
	return NULL;
      cdp->sfdd_sframe_ctx = nctx;
      return nctx;
    }

  return NULL;
}

/* Check if need to do a decode context switch, based on the input RADDR
   argument, from CF. A new decode context will be created and set up if it
   isn't already done so. Return the new decode context in CTX and vma in
   CFI_VMA.  */

void
sframe_update_ctx (struct sframe_state *sf, uint64_t raddr,
		   sframe_decoder_ctx **ctx, uint64_t *cfi_vma)
{
  sframe_decoder_ctx *nctx;
  struct sframe_stinfo *cdp;

  cdp = sframe_find_context (sf, raddr);
  if (cdp)
    {
      if (!cdp->sfdd_sframe_ctx)
	{
	  int err;
	  nctx = sframe_decode (cdp->sfdd_data, cdp->sfdd_data_size, &err);
	  if (!nctx)
	    {
	      *ctx = NULL;
	      return;
	    }
	  cdp->sfdd_sframe_ctx = nctx;
	}
	*ctx = cdp->sfdd_sframe_ctx;
	*cfi_vma = cdp->sfdd_sframe_vma;
    }
}

/* Open /proc image associated with the process id and return the file
   descriptor.  */

static int
sframe_fd_open (int *errp)
{
  int fd;

  if ((fd = open ("/proc/self/mem", O_CLOEXEC)) == -1)
    {
      sframe_bt_ret_set_errno (errp, SFRAME_BT_ERR_OPEN);
      return -1;
    }

  return fd;
}

/* The callback from dl_iterate_phdr with header info in INFO.
   Return SFrame info for either the main module or a DSO in DATA.  */

int
sframe_callback (struct dl_phdr_info *info,
		 size_t size ATTRIBUTE_UNUSED,
		 void *data)
{
  struct sframe_state *sf = (struct sframe_state *) data;
  int p_type, i, fd, sframe_err;
  ssize_t len;
  uint64_t text_vma = 0;
  int text_size = 0;

  if (!data || !info)
    return 1;

  debug_printf ("-- name: %s %14p\n", info->dlpi_name, (void *)info->dlpi_addr);

  for (i = 0; i < info->dlpi_phnum; i++)
    {
      debug_printf ("  %2d: [%" PRIu64 "; memsz %" PRIu64 "] flags: 0x%x; \n", i,
		   (uint64_t) info->dlpi_phdr[i].p_vaddr,
		   (uint64_t) info->dlpi_phdr[i].p_memsz,
		   info->dlpi_phdr[i].p_flags);

      p_type = info->dlpi_phdr[i].p_type;
      if (p_type == PT_LOAD && info->dlpi_phdr[i].p_flags & PF_X)
	{
	  text_vma = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
	  text_size = info->dlpi_phdr[i].p_memsz;
	  continue;
	}
      if (p_type != PT_SFRAME)
	continue;

      if (info->dlpi_name[0] == '\0')		/* the main module.  */
	{
	  fd = sframe_fd_open (&sframe_err);
	  if (fd == -1)
	    return 1;
#if 0
	  if (lseek (fd, info->dlpi_addr + info->dlpi_phdr[i].p_vaddr,
		     SEEK_SET) == -1)
	    {
	      sframe_bt_ret_set_errno (&sframe_err, SFRAME_BT_ERR_LSEEK);
	      return 1;
	    }
#endif

	  // sf->sui_ctx.sfdd_data = malloc (info->dlpi_phdr[i].p_memsz);
	  sf->sui_ctx.sfdd_data = (char *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
#if 0
	  if (sf->sui_ctx.sfdd_data == NULL)
	    {
	      sframe_bt_ret_set_errno (&sframe_err, SFRAME_BT_ERR_MALLOC);
	      return 1;
	    }

	  len = read (fd, sf->sui_ctx.sfdd_data, info->dlpi_phdr[i].p_memsz);
	  if (len == -1 || len != (ssize_t) info->dlpi_phdr[i].p_memsz)
	    {
	      sframe_bt_ret_set_errno (&sframe_err, SFRAME_BT_ERR_READ);
	      return 1;
	    }
#endif
	  len = info->dlpi_phdr[i].p_memsz;

	  assert (text_vma);
	  sf->sui_ctx.sfdd_data_size = len;
	  sf->sui_ctx.sfdd_sframe_vma = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
	  sf->sui_fd = fd;
	  sf->sui_ctx.sfdd_text_vma = text_vma;
	  sf->sui_ctx.sfdd_text_size = text_size;
	  text_vma = 0;
	  return 0;
	}
      else
	{					/* a dynamic shared object.  */
	  struct sframe_stinfo dt;
	  memset (&dt, 0, sizeof (struct sframe_stinfo));
	  assert (sf->sui_fd);
#if 0
	  if (lseek (sf->sui_fd, info->dlpi_addr + info->dlpi_phdr[i].p_vaddr,
		     SEEK_SET) == -1)
	    {
	      sframe_bt_ret_set_errno (&sframe_err, SFRAME_BT_ERR_LSEEK);
	      return 1;
	    }
#endif

	  // dt.sfdd_data = malloc (info->dlpi_phdr[i].p_memsz);
	  dt.sfdd_data = (char *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
#if 0
	  if (dt.sfdd_data == NULL)
	    {
	      sframe_bt_ret_set_errno (&sframe_err, SFRAME_BT_ERR_MALLOC);
	      return 1;
	    }

	  len = read (sf->sui_fd, dt.sfdd_data, info->dlpi_phdr[i].p_memsz);
	  if (len == -1 || len != (ssize_t) info->dlpi_phdr[i].p_memsz)
	    {
	      sframe_bt_ret_set_errno (&sframe_err, SFRAME_BT_ERR_READ);
	      return 1;
	    }
#endif
	  len = info->dlpi_phdr[i].p_memsz;
	  assert (text_vma);
	  dt.sfdd_data_size = len;
	  dt.sfdd_sframe_vma = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
	  dt.sfdd_text_vma = text_vma;
	  dt.sfdd_text_size = text_size;
	  text_vma = 0;
	  
	  sframe_err = sframe_add_dso (&sf->sui_dsos, dt);
	  // FIXME TODO
	  if (sframe_err != SFRAME_BT_OK)
	    return 1;
	  return 0;
	}
    }

    return 0;
}
