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

#include "defs.h"
#include "inferior.h"

#include "haiku-nat.h"
#include "nat/fork-inferior.h"
#include "nat/haiku-nat.h"
#include "solib.h"

haiku_nat_target *haiku_target;

void
haiku_nat_target::create_inferior (const char *exec_file,
                                   const std::string &allargs, char **env,
                                   int from_tty)
{
  HAIKU_TRACE ("exec_file=%s", exec_file);

  inferior *inf = current_inferior ();

  /* Do not change either targets above or the same target if already present.
     The reason is the target stack is shared across multiple inferiors.  */
  int ops_already_pushed = inf->target_is_pushed (this);

  target_unpush_up unpusher;
  if (!ops_already_pushed)
    {
      /* Clear possible core file with its process_stratum.  */
      inf->push_target (this);
      unpusher.reset (this);
    }

  static const auto haiku_traceme = [] () {
    /* This happens before the child calls exec().
       The debugger is responsible for resuming the inferior before it
       loads the desired target.  */
    haiku_nat::wait_for_debugger ();
  };

  static const auto haiku_init_trace = [] (int pid) {
    HAIKU_TRACE ("haiku_init_trace: pid=%i", pid);
    if (haiku_nat::attach (pid, true) < 0)
      trace_start_error_with_name (("haiku_nat::attach"));

    /* At this stage, the child is being stopped for the first debugger event.
       It has NOT exec'ed into the desired target yet, but is still a gdbserver
       stuck in a wait_for_debugger() call.  */

    /* Consume the initial event.  */
    target_waitstatus ourstatus;
    if (haiku_nat::wait (ptid_t (pid), &ourstatus, 0) == minus_one_ptid)
      perror_with_name (("haiku_nat::wait"));

    /* Allows the child to proceed to exec.  */
    if (haiku_nat::resume (ptid_t (pid), resume_continue, 0) < 0)
      perror_with_name (("haiku_nat::continue_process"));
  };

  pid_t pid = fork_inferior (exec_file, allargs, env, haiku_traceme,
                             haiku_init_trace, nullptr, nullptr, nullptr);

  /* We have something that executes now.  We'll be running through
     the shell at this point (if startup-with-shell is true), but the
     pid shouldn't change.  */
  thread_info *thr = add_thread_silent (this, ptid_t (pid, 0, pid));
  switch_to_thread (thr);

  unpusher.release ();

  gdb_startup_inferior (pid, START_INFERIOR_TRAPS_EXPECTED);
}

void
haiku_nat_target::attach (const char *args, int from_tty)
{
  inferior *inf = current_inferior ();

  /* Do not change either targets above or the same target if already present.
     The reason is the target stack is shared across multiple inferiors.  */
  int ops_already_pushed = inf->target_is_pushed (this);

  pid_t pid = parse_pid_to_attach (args);

  if (pid == getpid ()) /* Trying to masturbate?  */
    error (_ ("I refuse to debug myself!"));

  target_unpush_up unpusher;
  if (!ops_already_pushed)
    {
      /* target_pid_to_str already uses the target.  Also clear possible core
         file with its process_stratum.  */
      inf->push_target (this);
      unpusher.reset (this);
    }

  target_announce_attach (from_tty, pid);

  if (haiku_nat::attach (pid, false) < 0)
    perror_with_name (("haiku_nat::attach"));

  inferior_appeared (inf, pid);
  inf->attach_flag = true;

  /* Always add a main thread.  */
  thread_info *thr = add_thread_silent (this, ptid_t (pid, 0, pid));
  switch_to_thread (thr);

  /* Don't consider the thread stopped until we've processed its
     initial stop.  */
  set_executing (this, thr->ptid, true);

  unpusher.release ();
}

void
haiku_nat_target::detach (inferior *inf, int from_tty)
{
  target_announce_detach (from_tty);

  if (haiku_nat::detach (inf->pid) < 0)
    perror ("haiku_nat::detach");

  switch_to_no_thread ();
  detach_inferior (inf);

  maybe_unpush_target ();
}

void
haiku_nat_target::resume (ptid_t ptid, int step, enum gdb_signal signal)
{
  if (haiku_nat::resume (ptid, step ? resume_step : resume_continue,
                         gdb_signal_to_host (signal))
      < 0)
    perror_with_name ("haiku_nat_target::resume");
}

ptid_t
haiku_nat_target::wait (ptid_t ptid, target_waitstatus *ourstatus,
                        target_wait_flags target_options)
{
  HAIKU_TRACE ("ptid=%s, ourstatus=%s, target_options=%i",
               ptid.to_string ().c_str (), ourstatus->to_string ().c_str (),
               (int)target_options.raw ());

  ptid_t wptid = haiku_nat::wait (ptid, ourstatus, target_options);

  if (wptid == minus_one_ptid)
    perror_with_name (("haiku_nat::wait"));

  if (wptid.tid () != 0 && !find_thread (wptid)
      && ourstatus->kind () != TARGET_WAITKIND_THREAD_EXITED)
    add_thread (this, wptid);

  return wptid;
}

void
haiku_nat_target::files_info ()
{
  struct inferior *inf = current_inferior ();

  gdb_printf (_ ("\tUsing the running image of %s %s.\n"),
              inf->attach_flag ? "attached" : "child",
              target_pid_to_str (ptid_t (inf->pid)).c_str ());
}

void
haiku_nat_target::kill ()
{
  if (haiku_nat::kill (inferior_ptid.pid ()) < 0)
    {
      HAIKU_TRACE ("Failed to actually kill the process: %s",
                   safe_strerror (errno));
    }

  target_mourn_inferior (inferior_ptid);
}

void
haiku_nat_target::follow_exec (inferior *follow_inf, ptid_t ptid,
                               const char *execd_pathname)
{
  inf_child_target::follow_exec (follow_inf, ptid, execd_pathname);

  /* nat/haiku-nat.c currently does not report the EXEC event when
     the corresponding native event is generated, but after the
     main executable image has been loaded.

     This means when the event is generated, all initial shared
     libraries have been registered. However, GDB treats the
     EXEC event as if the program has a clean address space and
     nukes the solib list and loaded symbols.

     We therefore call the below function to force GDB to load
     the needed symbols again.  */
  handle_solib_event ();

  invalidate_target_mem_regions ();
}

bool
haiku_nat_target::thread_alive (ptid_t ptid)
{
  return haiku_nat::thread_alive (ptid);
}

void
haiku_nat_target::update_thread_list ()
{
  delete_exited_threads ();

  pid_t pid = current_inferior ()->pid;

  haiku_nat::for_each_thread (pid, [&] (const haiku_nat::thread_info &info) {
    ptid_t ptid = ptid_t (pid, 0, info.tid);

    if (find_thread (ptid) == nullptr)
      add_thread (this, ptid);

    return 0;
  });
}

std::string
haiku_nat_target::pid_to_str (ptid_t ptid)
{
  return haiku_nat::pid_to_str (ptid);
}

const char *
haiku_nat_target::thread_name (thread_info *thr)
{
  return haiku_nat::thread_name (thr->ptid);
}

void
haiku_nat_target::stop (ptid_t ptid)
{
  if (haiku_nat::stop (ptid) < 0)
    perror_with_name ("haiku_nat::stop");
}

const char *
haiku_nat_target::pid_to_exec_file (int pid)
{
  return haiku_nat::pid_to_exec_file (pid);
}

enum target_xfer_status
haiku_nat_target::xfer_partial (enum target_object object, const char *annex,
                                gdb_byte *readbuf, const gdb_byte *writebuf,
                                ULONGEST offset, ULONGEST len,
                                ULONGEST *xfered_len)
{
  ptid_t ptid = inferior_ptid;

  switch (object)
    {
    case TARGET_OBJECT_MEMORY:
      {
        int sizeLeft = std::min ((ULONGEST)INT_MAX, len);

        if (writebuf != nullptr)
          std::ignore = haiku_nat::write_memory (
              ptid.pid (), (CORE_ADDR)offset, writebuf, &sizeLeft);
        else
          std::ignore = haiku_nat::read_memory (ptid.pid (), (CORE_ADDR)offset,
                                                readbuf, &sizeLeft);

        *xfered_len = std::min ((ULONGEST)INT_MAX, len) - sizeLeft;

        return (*xfered_len > 0) ? TARGET_XFER_OK : TARGET_XFER_EOF;
      }
      break;
    default:
      HAIKU_TRACE ("Unimplemented xfer object: %i", (int)object);
    }

  return inf_child_target::xfer_partial (object, annex, readbuf, writebuf,
                                         offset, len, xfered_len);
}

std::vector<mem_region>
haiku_nat_target::memory_map ()
{
  std::vector<mem_region> result;

  static const mem_access_mode modes[2][2] = { /* Cannot read.  */
                                               { MEM_NONE, MEM_WO },
                                               /* Can read.  */
                                               { MEM_RO, MEM_RW }
  };

  haiku_nat::for_each_area (
      current_inferior ()->pid, [&] (const haiku_nat::area_info &info) {
        result.emplace_back (info.low, info.high,
                             modes[info.can_read][info.can_write]);
        return 0;
      });

  return result;
}

bool
haiku_nat_target::supports_multi_process ()
{
  return true;
}

/* Supply other required functions */

namespace haiku_nat
{

void
debugger_output (const char *message)
{
  gdb_printf ("%s\n", message);
}

void
image_created (ptid_t ptid, const char *name, CORE_ADDR base)
{
  HAIKU_TRACE ("ptid=%s, name=%s, CORE_ADDR=%p", ptid.to_string ().c_str (),
               name, (void *)base);

  /* To be handled by solib-haiku.c.  */
}

void
image_deleted (ptid_t ptid, const char *name)
{
  HAIKU_TRACE ("ptid=%s, name=%s", ptid.to_string ().c_str (), name);

  /* To be handled by solib-haiku.c.  */
}

bool
is_catching_syscalls_for (ptid_t ptid)
{
  inferior *inf = find_inferior_ptid (haiku_target, ptid);
  if (inf == nullptr)
    return false;

  gdb::optional<scoped_restore_current_thread> maybe_restore_thread
      = maybe_switch_inferior (inf);

  return catch_syscall_enabled () > 0;
}

}
