/* Native-dependent code for Haiku/i386.

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

#include "haiku-nat.h"

struct i386_haiku_nat_target final : public haiku_nat_target
{
  void fetch_registers (struct regcache *, int) override;
  void store_registers (struct regcache *, int) override;
};

static i386_haiku_nat_target the_i386_haiku_nat_target;

void _initialize_i386_haiku_nat ();
void
_initialize_i386_haiku_nat ()
{
  haiku_target = &the_i386_haiku_nat_target;

  add_inf_child_target (&the_i386_haiku_nat_target);
}
