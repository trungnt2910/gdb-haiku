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

#include "cli/cli-cmds.h"
#include "exec.h"
#include "gdb/inf-loop.h"
#include "gdbcore.h"
#include "gdbsupport/buildargv.h"
#include "gdbsupport/event-loop.h"
#include "haiku-nat.h"
#include "nat/fork-inferior.h"
#include "nat/haiku-nat.h"
#include "nat/haiku-osdata.h"
#include "objfiles.h"
#include "observable.h"
#include "solib.h"

haiku_nat_target *haiku_target;

bool debug_haiku_nat = false;

static void haiku_enable_breakpoints_if_ready (inferior *inf);

void
haiku_nat_target::create_inferior (const char *exec_file,
                                   const std::string &allargs, char **env,
                                   int from_tty)
{
  haiku_nat_debug_printf ("exec_file=%s", exec_file);

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

  if (disable_randomization)
    inf->environment.set ("DISABLE_ASLR", "1");

  static const auto haiku_traceme = [] () {
    /* This happens before the child calls exec().
       The debugger is responsible for resuming the inferior before it
       loads the desired target.  */
    haiku_nat::wait_for_debugger ();
  };

  static const auto haiku_init_trace = [] (int pid) {
    haiku_nat_debug_printf ("haiku_init_trace: pid=%i", pid);
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

  /* Do not use env here, the pointer might have been invalidated.  */
  pid_t pid = fork_inferior (exec_file, allargs, inf->environment.envp (),
                             haiku_traceme, haiku_init_trace, nullptr, nullptr,
                             nullptr);

  /* We have something that executes now.  We'll be running through
     the shell at this point (if startup-with-shell is true), but the
     pid shouldn't change.  */
  thread_info *thr = add_thread_silent (this, ptid_t (pid, 0, pid));
  switch_to_thread (thr);

  unpusher.release ();

  disable_breakpoints_before_startup ();

  gdb_startup_inferior (pid, START_INFERIOR_TRAPS_EXPECTED);

  /* Don't wait for the callbacks. Here, we know that the inferior has exec'ed
     into the requested image. If we wait further, post_create_inferior will
     perform lots of operations that interally triggers breakpoint_re_set,
     which ignores the executing_startup flag.  */
  haiku_enable_breakpoints_if_ready (inf);
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
  haiku_nat_debug_printf (
      "ptid=%s, ourstatus=%s, target_options=%i", ptid.to_string ().c_str (),
      ourstatus->to_string ().c_str (), (int)target_options.raw ());

  ptid_t wptid = haiku_nat::wait (ptid, ourstatus, target_options);

  if (wptid == minus_one_ptid)
    perror_with_name (("haiku_nat::wait"));

  if (wptid.tid () != 0 && !find_thread (wptid)
      && ourstatus->kind () != TARGET_WAITKIND_THREAD_EXITED)
    add_thread (this, wptid);

  invalidate_target_mem_regions ();

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
      haiku_nat_debug_printf ("Failed to actually kill the process: %s",
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

bool
haiku_nat_target::can_async_p ()
{
  return true;
}

bool
haiku_nat_target::is_async_p ()
{
  return haiku_nat::is_async_p ();
}

void
haiku_nat_target::async (bool enable)
{
  if (enable == is_async_p ())
    return;

  if (enable)
    {
      if (haiku_nat::async (true) < 0)
        perror_with_name ("haiku_nat::async");
      else
        {
          add_file_handler (
              haiku_nat::async_wait_fd (),
              [] (int error, gdb_client_data client_data) {
                inferior_event_handler (INF_REG_EVENT);
              },
              nullptr, "haiku-nat");
        }
    }
  else
    {
      /* Unregister this before async_wait_fd gets invalidated.  */
      delete_file_handler (haiku_nat::async_wait_fd ());
      haiku_nat::async (false);
    }
}

int
haiku_nat_target::async_wait_fd ()
{
  return haiku_nat::async_wait_fd ();
}

bool
haiku_nat_target::supports_non_stop ()
{
  return true;
}

bool
haiku_nat_target::always_non_stop_p ()
{
  return true;
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
    case TARGET_OBJECT_LIBRARIES:
      {
        if (writebuf != nullptr)
          return TARGET_XFER_UNAVAILABLE;

        if (current_inferior () == nullptr)
          return TARGET_XFER_E_IO;

        std::string document = "<library-list version=\"1.0\">\n";
        haiku_nat::for_each_image (
            current_inferior ()->pid, [&] (const haiku_nat::image_info &info) {
              if (!info.is_main_executable)
                {
                  document += string_printf (
                      "  <library name=\"%s\">"
                      "<segment address=\"%s\"/></library>\n",
                      info.name,
                      paddress (current_inferior ()->arch (), info.text));
                }
              return 0;
            });
        document += "</library-list>\n";

        if (offset >= document.size ())
          return TARGET_XFER_EOF;

        len = std::min (len, document.size () - offset);
        memcpy (readbuf, document.c_str () + offset, len);

        *xfered_len = len;

        return TARGET_XFER_OK;
      }
      break;
    case TARGET_OBJECT_OSDATA:
      {
        if (writebuf != nullptr)
          return TARGET_XFER_UNAVAILABLE;

        *xfered_len = haiku_common_xfer_osdata (annex, readbuf, offset, len);

        return (*xfered_len > 0) ? TARGET_XFER_OK : TARGET_XFER_EOF;
      }
    default:
      haiku_nat_debug_printf ("Unimplemented xfer object: %i", (int)object);
    }

  return inf_child_target::xfer_partial (object, annex, readbuf, writebuf,
                                         offset, len, xfered_len);
}

std::vector<mem_region>
haiku_nat_target::memory_map ()
{
  std::vector<mem_region> result;

  haiku_nat::for_each_area (
      current_inferior ()->pid, [&] (const haiku_nat::area_info &info) {
        /* While some regions appear read-only to the user,
           as the debugger, we can write anywhere.

           If this is set otherwise, software breakpoints in read-only
           regions (such as shared libraries) will not work.  */
        result.emplace_back (info.address, info.address + info.size, MEM_RW);
        return 0;
      });

  return result;
}

bool
haiku_nat_target::supports_multi_process ()
{
  return true;
}

bool
haiku_nat_target::supports_disable_randomization ()
{
  return true;
}

bool
haiku_nat_target::info_proc (const char *args, enum info_proc_what what)
{
  pid_t pid;
  bool do_cmdline = false;
  bool do_exe = false;
  bool do_mappings = false;
  bool do_status = false;

  switch (what)
    {
    case IP_MINIMAL:
      do_cmdline = true;
      do_exe = true;
      break;
    case IP_STAT:
    case IP_STATUS:
      do_status = true;
      break;
    case IP_MAPPINGS:
      do_mappings = true;
      break;
    case IP_CMDLINE:
      do_cmdline = true;
      break;
    case IP_EXE:
      do_exe = true;
      break;
    case IP_CWD:
      /* There is no obvious method of getting the CWD of a different team.
         _kern_get_extended_team_info might provide what we want, but the
         syscall stores the result in a private class "KMessage" instead of
         normal structs.  */
      return false;
    case IP_ALL:
      do_cmdline = true;
      do_exe = true;
      do_mappings = true;
      do_status = true;
      break;
    default:
      error (_ ("Not supported on this target."));
    }

  gdb_argv built_argv (args);
  if (built_argv.count () == 0)
    {
      pid = inferior_ptid.pid ();
      if (pid == 0)
        error (_ ("No current team: you must name one."));
    }
  else if (built_argv.count () == 1 && isdigit (built_argv[0][0]))
    pid = strtol (built_argv[0], NULL, 10);
  else
    error (_ ("Invalid arguments."));

  gdb_printf (_ ("team %d\n"), pid);

  const haiku_nat::team_info *info = nullptr;

  if (do_cmdline || do_status)
    info = haiku_nat::get_team (pid);

  if (do_cmdline)
    {
      if (info != nullptr)
        gdb_printf ("cmdline = '%s'\n", info->args);
      else
        warning (_ ("unable to fetch command line"));
    }

  if (do_exe)
    {
      const char *exe = pid_to_exec_file (pid);
      if (exe != nullptr)
        gdb_printf ("exe = '%s'\n", exe);
      else
        warning (_ ("unable to fetch executable path name"));
    }

  if (do_mappings)
    {
      bool first = true;
      if (haiku_nat::for_each_area (
              pid,
              [&] (const haiku_nat::area_info &area_info) {
                if (first)
                  {
                    gdb_printf (_ ("Mapped areas:\n\n"));
                    gdb_printf ("%6s %18s %10s %10s %6s %6s %5s %5s %s\n",
                                "ID", "address", "size", "alloc.", "prot",
                                "#-cow", "#-in", "#-out", "name");
                    first = false;
                  }

                std::string prot;
                if (area_info.can_read)
                  prot += "r";
                if (area_info.can_write)
                  prot += "w";
                if (area_info.can_exec)
                  prot += "x";
                if (area_info.is_stack)
                  prot += "s";
                if (area_info.can_clone)
                  prot += "c";

                gdb_printf ("%6s %18s %10s %10s %6s %6s %5s %5s %s\n",
                            plongest (area_info.id),
                            core_addr_to_string (area_info.address),
                            phex_nz (area_info.size, 0),
                            phex_nz (area_info.ram_size, 0), prot.c_str (),
                            pulongest (area_info.copy_count),
                            pulongest (area_info.in_count),
                            pulongest (area_info.out_count), area_info.name);

                return 0;
              })
          < 0)
        {
          warning (_ ("unable to fetch virtual memory map"));
        }
    }

  if (do_status)
    {
      if (info != nullptr)
        {
          gdb_printf ("Name: %s\n", info->name);
          gdb_printf ("Parent team: %s\n", plongest (info->parent));
          gdb_printf ("Process group: %s\n", plongest (info->group_id));
          gdb_printf ("Session id: %s\n", plongest (info->session_id));
          gdb_printf ("User IDs (real, effective): %s %s\n",
                      plongest (info->real_uid), plongest (info->uid));
          gdb_printf ("Group IDs (real, effective): %s %s\n",
                      plongest (info->real_gid), plongest (info->gid));
          gdb_printf ("Thread count: %s\n", pulongest (info->thread_count));
          gdb_printf ("Image count: %s\n", pulongest (info->image_count));
          gdb_printf ("Area count: %s\n", pulongest (info->area_count));
          gdb_printf ("Debugger nub thread: %s\n",
                      plongest (info->debugger_nub_thread));
          gdb_printf ("Debugger nub port: %s\n",
                      plongest (info->debugger_nub_port));
        }
      else
        warning (_ ("unable to fetch team information"));
    }

  return true;
}

/* Utilities.  */

static void
haiku_relocate_main_executable (inferior *inf)
{
  CORE_ADDR text;
  CORE_ADDR data;

  if (haiku_nat::read_offsets (inf->pid, &text, &data) < 0)
    return;

  CORE_ADDR displacement = text;

  if (inf->pspace->exec_bfd ())
    {
      asection *asect;

      bfd *exec_bfd = inf->pspace->exec_bfd ();
      for (asect = exec_bfd->sections; asect != NULL; asect = asect->next)
        exec_set_section_address (bfd_get_filename (exec_bfd), asect->index,
                                  bfd_section_vma (asect) + displacement);
    }

  if (inf->pspace->symfile_object_file == nullptr)
    symbol_file_add_main (inf->pspace->exec_filename.get (),
                          SYMFILE_DEFER_BP_RESET);

  objfile *objf = inf->pspace->symfile_object_file;
  /* The call above should ensure that this is filled in.  */
  gdb_assert (objf != nullptr);
  objfile_rebase (objf, displacement);

  haiku_nat_debug_printf ("rebased: %s", core_addr_to_string (displacement));
}

static void
haiku_enable_breakpoints_if_ready (inferior *inf)
{
  if (strcmp (haiku_nat::pid_to_exec_file (inf->pid),
              inf->pspace->exec_filename.get ())
      != 0)
    {
      /* Not ready yet. The inferior is still executing a wrapper
         (usually bash).  */
      return;
    }

  /* Refresh the regions so that write operations can be done correctly.  */
  invalidate_target_mem_regions ();

  /* We can get correct offsets and relocate now.  */
  haiku_relocate_main_executable (inf);

  enable_breakpoints_after_startup ();
}

/* Supply other required functions.  */

namespace haiku_nat
{

void
debugger_output (const char *message)
{
  gdb_printf ("%s\n", message);
}

void
image_created (ptid_t ptid, const image_info &info)
{
  haiku_nat_debug_printf ("ptid=%s, name=%s, text=%p",
                          ptid.to_string ().c_str (), info.name,
                          (void *)info.text);

  /* To be handled by solib-haiku.c.  */
}

void
image_deleted (ptid_t ptid, const image_info &info)
{
  haiku_nat_debug_printf ("ptid=%s, name=%s", ptid.to_string ().c_str (),
                          info.name);

  if (info.is_main_executable)
    {
      /* This means all images have been deleted. This usually signals that
         the Haiku team just called exec.

         We want to disable breakpoints for now to prevent those pointing to
         the main executable from causing issues with unrelocated addresses.
         Then, after the creation or exec call completes and the new inferior
         gets finalized, we can relocate and enable these breakpoints again.

         We also cannot disable the breakpoints later than this. After the
         event, images for the new executable starts loading. Disabling the
         breakpoints causes GDB to write bogus data back to the fresh
         binaries.  */

      disable_breakpoints_before_startup ();
      invalidate_target_mem_regions ();
    }

  /* The rest to be handled by solib-haiku.c.  */
}

bool
is_catching_syscalls_for (ptid_t ptid)
{
  inferior *inf = find_inferior_ptid (haiku_target, ptid);
  if (inf == nullptr)
    return false;

  std::optional<scoped_restore_current_thread> maybe_restore_thread
      = maybe_switch_inferior (inf);

  return catch_syscall_enabled () > 0;
}

}

/* Initialization.  */

void _initialize_haiku_nat ();
void
_initialize_haiku_nat ()
{
  /* We cannot do this in target_op's own callbacks, since they are called too
     early after attaching or an exec event. At that point, symfile_object_file
     remains invalid.

     Previous ports put this in Haiku's solib_create_inferior_hook callback.
     However, this callback is also shared by remote targets and therefore
     assumes gathering information from the address space instead of the host
     OS, which is what haiku_nat::read_offsets does under the hood. With the
     old implementation, GDB connected to gdbserver debugging PID X on the
     target would attempt to use haiku_nat::read_offsets on the same PID X
     on the local machine - this is undesired.  */

  gdb::observers::inferior_created.attach (
      [] (inferior *inf) {
        if (inf->target_is_pushed (haiku_target))
          haiku_enable_breakpoints_if_ready (inf);
      },
      "haiku");

  gdb::observers::inferior_execd.attach (
      [] (inferior *exec, inferior *foll) {
        if (foll->target_is_pushed (haiku_target))
          haiku_enable_breakpoints_if_ready (foll);
      },
      "haiku");

  add_setshow_boolean_cmd (
      "haiku-nat", class_maintenance, &debug_haiku_nat,
      _ ("Set debugging of Haiku native target."),
      _ ("Show debugging of Haiku native target."), _ ("\
When on, print debug messages relating to the Haiku native target."),
      nullptr,
      [] (struct ui_file *file, int from_tty, struct cmd_list_element *c,
          const char *value) {
        gdb_printf (file, _ ("Debugging of Haiku native targets is %s.\n"),
                    value);
      },
      &setdebuglist, &showdebuglist);
}
