/* Haiku native-dependent definitions.

   Copyright 2005 Ingo Weinhold <bonefish@cs.tu-berlin.de>.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#ifndef HAIKU_NAT_H
#define HAIKU_NAT_H

// These types conflict with GDB ones, so we have to hack around that.
#define thread_info haiku_thread_info
#define thread_state haiku_thread_state
#define type_code haiku_type_code
#define debug_printf haiku_debug_printf
#define debug_vprintf haiku_debug_vprintf
#include <debugger.h>
#undef type_code
#undef thread_info
#undef thread_state
#undef debug_printf
#undef debug_vprintf

/* Required by haiku-nat.c, implemented in <arch>-haiku-nat.c. */

void haiku_supply_registers(int reg, struct regcache *regcache, const debug_cpu_state *cpuState);
void haiku_collect_registers(int reg, struct regcache *regcache, debug_cpu_state *cpuState);


struct haiku_image_info;

/* Function used by solib-haiku.c to iterate through the list of images of
   the inferior.
   TODO: This must go, since it works only in a native debugger. We can
   probably tunnel these data through the xfer_memory() function.
*/
struct haiku_image_info *haiku_get_next_image_info(int lastID);

#endif	/* HAIKU_NAT_H */
