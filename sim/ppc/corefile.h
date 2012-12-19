/*  This file is part of the program psim.

    Copyright (C) 1994-1996, Andrew Cagney <cagney@highland.com.au>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program; if not, see <http://www.gnu.org/licenses/>.
 
    */


#ifndef _CORE_H_
#define _CORE_H_

/* Introduction:

   The core device, positioned at the top of the device tree that
   models the architecure being simulated, acts as an interface
   between the processor engines and the modeled devices.

   On the one side the processor engines issue read and write requests
   to the core (each request further catagorised as being for an
   instruction or data subunit) while on the other side, the core is
   receiving address configuration and DMA requests from child
   devices.

   In the below a synopsis of the core object and device in PSIM is
   given, details of the object can be found in the files
   <<corefile.h>> and <<corefile.c>>.

   */

/* Core::

   At the heart of the interface between devices and processor engines
   is a single core object.  This object, in turn, has two children:

   o	a core device which exists in the device tree and provides
   	an interface to the core object to child devices.

   o	a set of access maps which provide an efficient
   	interface to the core object for the processor engines.

   */

/* basic types */

typedef struct _core core;
typedef struct _core_map core_map;

/* constructor */

INLINE_CORE\
(core *) core_create
(void);

INLINE_CORE\
(core *) core_from_device
(device *root);

INLINE_CORE\
(void) core_init
(core *memory);

/* Core map management:::

   The core ojbect manages two different types of address maps:

   o    raw-memory - the address range can be implemented using
	a simple byte array.  No device needs to be notifed of
	any accesses to the specified memory range.
        
   o	callback - Any access to the specified address range
	should be passed on to the associated device.  That device
        can in turn resolve the access - handling or aborting or
	restarting it.

   For callback maps it is possible to further order them by
   specifiying specifying a callback level (eg callback + 1).

   When the core is resolving an access it searches each of the maps
   in order.  First raw-memory and then callback maps (in assending
   order of level).  This search order makes it possible for latter
   maps to overlap earlier ones.  For instance, a device that wants to
   be notified of all accesses that are not covered by raw-memory maps
   could attach its self with an address range of the entire address
   space.

   In addition, each attached address map as an associated set of
   access attributes (readable, writeable, executable) which are
   verified as part of resolving each access.

   */

INLINE_CORE\
(void) core_attach
(core *map,
 attach_type attach,
 int address_space,
 access_type access,
 unsigned_word addr,
 unsigned nr_bytes, /* host limited */
 device *device); /*callback/default*/

/* Bugs:::

   At present there is no method for removing address maps.  That will
   be implemented in a future release.

   The operation of mapping between an address and its destination
   device or memory array is currently implemented using a simple
   linked list.  The posibility of replacing this list with a more
   powerfull data structure exists.

   */


/* Device::

   The device that corresponds to the core object is described
   separatly in the devices section.

   */

/* Access maps::

   Providing an interface between the processor engines and the core
   object are the access maps (core_map).  Three access maps are
   provided, one for each of the possible access requests that can be
   generated by a processor.

   o	read

   o    write

   o    execute

   A processor being able to request a read (or write) or write
   operation to any of the maps.  Those operations can either be
   highly efficient (by specifying a specific transfer size) or
   generic (specifying a parameterized number of bytes).

   Internally the core object takes the request, determines the
   approperiate attached address space that it should handle it passes
   it on.

   */

INLINE_CORE\
(core_map *) core_readable
(core *memory);

INLINE_CORE\
(core_map *) core_writeable
(core *memory);

INLINE_CORE\
(core_map *) core_executable
(core *memory);

/* Variable sized read/write

   Transfer (zero) a variable size block of data between the host and
   target (possibly byte swapping it).  Should any problems occure,
   the number of bytes actually transfered is returned. */

INLINE_CORE\
(unsigned) core_map_read_buffer
(core_map *map,
 void *buffer,
 unsigned_word addr,
 unsigned nr_bytes);

INLINE_CORE\
(unsigned) core_map_write_buffer
(core_map *map,
 const void *buffer,
 unsigned_word addr,
 unsigned nr_bytes);


/* Fixed sized read/write

   Transfer a fixed amout of memory between the host and target.  The
   memory always being translated and the operation always aborting
   should a problem occure */

#define DECLARE_CORE_WRITE_N(N) \
INLINE_CORE\
(void) core_map_write_##N \
(core_map *map, \
 unsigned_word addr, \
 unsigned_##N val, \
 cpu *processor, \
 unsigned_word cia);

DECLARE_CORE_WRITE_N(1)
DECLARE_CORE_WRITE_N(2)
DECLARE_CORE_WRITE_N(4)
DECLARE_CORE_WRITE_N(8)
DECLARE_CORE_WRITE_N(word)

#define DECLARE_CORE_READ_N(N) \
INLINE_CORE\
(unsigned_##N) core_map_read_##N \
(core_map *map, \
 unsigned_word addr, \
 cpu *processor, \
 unsigned_word cia);

DECLARE_CORE_READ_N(1)
DECLARE_CORE_READ_N(2)
DECLARE_CORE_READ_N(4)
DECLARE_CORE_READ_N(8)
DECLARE_CORE_READ_N(word)

#endif
