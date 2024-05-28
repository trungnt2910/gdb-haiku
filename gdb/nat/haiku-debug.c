/* Haiku re-exports for debugging functions with conflicting names.

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

#include "gdbsupport/common-defs.h"

extern decltype (debug_printf) haiku_debug_printf;
extern decltype (debug_vprintf) haiku_debug_vprintf;

/* Re-export of debug_printf.  */

void
haiku_debug_printf (const char *format, ...)
{
  va_list ap;

  va_start (ap, format);
  debug_vprintf (format, ap);
  va_end (ap);
}

/* Re-export of debug_vprintf.  */

void
haiku_debug_vprintf (const char *format, va_list ap)
{
  debug_vprintf (format, ap);
}
