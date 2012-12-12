/* MI Command Set - catch commands.
   Copyright (C) 2012 Free Software Foundation, Inc.

   Contributed by Intel Corporation.

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
#include "arch-utils.h"
#include "breakpoint.h"
#include "gdb.h"
#include "libiberty.h"
#include "mi-cmds.h"
#include "mi-getopt.h"
#include "mi-cmd-break.h"


/* Common path for the -catch-load and -catch-unload.  */

static void
mi_catch_load_unload (int load, char *argv[], int argc)
{
  struct solib_catchpoint *c;
  struct cleanup *back_to;
  const char *actual_cmd = load ? "-catch-load" : "-catch-unload";
  int temp = 0;
  int enabled = 1;
  int oind = 0;
  char *oarg;
  enum opt
    {
      OPT_TEMP,
      OPT_DISABLED,
    };
  static const struct mi_opt opts[] =
    {
      { "t", OPT_TEMP, 0 },
      { "d", OPT_DISABLED, 0 },
      { 0, 0, 0 }
    };

  for (;;)
    {
      int opt = mi_getopt (actual_cmd, argc, argv, opts,
                           &oind, &oarg);

      if (opt < 0)
        break;

      switch ((enum opt) opt)
        {
        case OPT_TEMP:
          temp = 1;
          break;
        case OPT_DISABLED:
          enabled = 0;
          break;
        }
    }

  if (oind >= argc)
    error (_("-catch-load/unload: Missing <library name>"));
  if (oind < argc -1)
    error (_("-catch-load/unload: Garbage following the <library name>"));

  back_to = setup_breakpoint_reporting ();

  add_solib_catchpoint (argv[oind], load, temp, enabled);

  do_cleanups (back_to);
}

/* Handler for the -catch-load.  */

void
mi_cmd_catch_load (char *cmd, char *argv[], int argc)
{
  mi_catch_load_unload (1, argv, argc);
}


/* Handler for the -catch-unload.  */

void
mi_cmd_catch_unload (char *cmd, char *argv[], int argc)
{
  mi_catch_load_unload (0, argv, argc);
}

