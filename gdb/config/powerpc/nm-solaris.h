/* OBSOLETE /* Native-dependent definitions for PowerPC running Solaris. */
/* OBSOLETE    Copyright 1996 Free Software Foundation, Inc. */
/* OBSOLETE  */
/* OBSOLETE    This file is part of GDB. */
/* OBSOLETE  */
/* OBSOLETE    This program is free software; you can redistribute it and/or modify */
/* OBSOLETE    it under the terms of the GNU General Public License as published by */
/* OBSOLETE    the Free Software Foundation; either version 2 of the License, or */
/* OBSOLETE    (at your option) any later version. */
/* OBSOLETE  */
/* OBSOLETE    This program is distributed in the hope that it will be useful, */
/* OBSOLETE    but WITHOUT ANY WARRANTY; without even the implied warranty of */
/* OBSOLETE    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the */
/* OBSOLETE    GNU General Public License for more details. */
/* OBSOLETE  */
/* OBSOLETE    You should have received a copy of the GNU General Public License */
/* OBSOLETE    along with this program; if not, write to the Free Software */
/* OBSOLETE    Foundation, Inc., 59 Temple Place - Suite 330, */
/* OBSOLETE    Boston, MA 02111-1307, USA.  */ */
/* OBSOLETE  */
/* OBSOLETE #include "regcache.h" */
/* OBSOLETE  */
/* OBSOLETE /* Include the generic SVR4 definitions.  */ */
/* OBSOLETE  */
/* OBSOLETE #include <nm-sysv4.h> */
/* OBSOLETE  */
/* OBSOLETE /* Before storing, we need to read all the registers.  */ */
/* OBSOLETE  */
/* OBSOLETE #define CHILD_PREPARE_TO_STORE() read_register_bytes (0, NULL, REGISTER_BYTES) */
/* OBSOLETE  */
/* OBSOLETE /* Solaris PSRVADDR support does not seem to include a place for nPC.  */ */
/* OBSOLETE  */
/* OBSOLETE #define PRSVADDR_BROKEN */
