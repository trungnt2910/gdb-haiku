/* Copyright (C) 2024 Free Software Foundation, Inc.

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

#ifndef GDBSERVER_HAIKU_LOW_H
#define GDBSERVER_HAIKU_LOW_H

/* Target ops definitions for a Haiku target.  */

class haiku_process_target : public process_stratum_target
{
public:
  int create_inferior (const char *program,
                       const std::vector<char *> &program_args) override;

  void post_create_inferior () override;

  int attach (unsigned long pid) override;

  int kill (process_info *proc) override;

  int detach (process_info *proc) override;

  void mourn (process_info *proc) override;

  void join (int pid) override;

  bool thread_alive (ptid_t pid) override;

  void resume (thread_resume *resume_info, size_t n) override;

  ptid_t wait (ptid_t ptid, target_waitstatus *status,
               target_wait_flags options) override;

  int read_memory (CORE_ADDR memaddr, unsigned char *myaddr, int len) override;

  int write_memory (CORE_ADDR memaddr, const unsigned char *myaddr,
                    int len) override;

  void request_interrupt () override;

  int read_offsets (CORE_ADDR *text, CORE_ADDR *data) override;

  int qxfer_osdata (const char *annex, unsigned char *readbuf,
                    unsigned const char *writebuf, CORE_ADDR offset,
                    int len) override;

  bool async (bool enable) override;

  int start_non_stop (bool enable) override;

  bool thread_stopped (thread_info *thread) override;

  const char *pid_to_exec_file (int pid) override;

  const char *thread_name (ptid_t thread) override;

  bool supports_qxfer_osdata () override;

  bool supports_non_stop () override;

  bool supports_multi_process () override;

  bool supports_fork_events () override;

  bool supports_exec_events () override;

  bool supports_read_offsets () override;

  bool supports_thread_stopped () override;

  bool supports_disable_randomization () override;

  bool supports_pid_to_exec_file () override;

  bool supports_catch_syscall () override;

protected:
  /* The architecture-specific "low" methods are listed below.  */

  /* Architecture-specific setup for the current process.  */
  virtual void low_arch_setup (process_info *process = nullptr) = 0;
};

extern haiku_process_target *the_haiku_target;

#endif /* GDBSERVER_HAIKU_LOW_H */
