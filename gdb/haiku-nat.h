/* Native-dependent code for Haiku.

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

#include "inf-child.h"

/* A prototype Haiku target.  */

struct haiku_nat_target : public inf_child_target
{
  void create_inferior (const char *, const std::string &, char **,
                        int) override;

  void attach (const char *, int) override;

  void detach (inferior *, int) override;

  void resume (ptid_t, int, enum gdb_signal) override;

  ptid_t wait (ptid_t, struct target_waitstatus *, target_wait_flags) override;

  void files_info () override;

  void kill () override;

  void follow_exec (inferior *, ptid_t, const char *) override;

  bool thread_alive (ptid_t ptid) override;
  void update_thread_list () override;
  std::string pid_to_str (ptid_t) override;

  const char *thread_name (thread_info *) override;

  void stop (ptid_t) override;

  const char *pid_to_exec_file (int pid) override;

  enum target_xfer_status xfer_partial (enum target_object, const char *,
                                        gdb_byte *, const gdb_byte *, ULONGEST,
                                        ULONGEST, ULONGEST *) override;

  std::vector<mem_region> memory_map () override;

  bool supports_multi_process () override;
};

/* The final/concrete instance.  */
extern haiku_nat_target *haiku_target;
