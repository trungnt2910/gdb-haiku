/* Language independent support for printing types for GDB, the GNU debugger.
   Copyright (C) 1986, 1988-1989, 1991-1993, 1999-2000, 2007-2012 Free
   Software Foundation, Inc.

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

#ifndef TYPEPRINT_H
#define TYPEPRINT_H

enum language;
struct ui_file;

struct type_print_options
{
  /* True means that no special printing flags should apply.  */
  unsigned int raw : 1;

  /* True means print methods in a class.  */
  unsigned int print_methods : 1;

  /* True means print typedefs in a class.  */
  unsigned int print_typedefs : 1;
};

extern const struct type_print_options type_print_raw_options;

void print_type_scalar (struct type * type, LONGEST, struct ui_file *);

void c_type_print_varspec_suffix (struct type *, struct ui_file *, int,
				  int, int, const struct type_print_options *);

void c_type_print_args (struct type *, struct ui_file *, int, enum language,
			const struct type_print_options *);

#endif
