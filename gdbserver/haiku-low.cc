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

#include "server.h"
#include "target.h"

#include "haiku-low.h"
#include "nat/haiku-nat.h"
#include "nat/haiku-osdata.h"

#include "gdbsupport/common-debug.h"
#include "gdbsupport/common-inferior.h"
#include "gdbsupport/eintr.h"
#include "nat/fork-inferior.h"

int using_threads = 1;

#ifdef DEVELOPMENT
bool debug_haiku_nat = true;
#else
bool debug_haiku_nat = false;
#endif

/* Implement the create_inferior method of the target_ops vector.  */

int
haiku_process_target::create_inferior (const char *program,
                                       const std::vector<char *> &program_args)
{
  haiku_nat_debug_printf ("program=%s", program);

  static const auto haiku_traceme = [] () {
    haiku_nat_debug_printf ("haiku_traceme");
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

  std::string str_program_args = construct_inferior_arguments (program_args);

  client_state &cs = get_client_state ();
  if (cs.disable_randomization)
    get_environ ()->set ("DISABLE_ASLR", "1");
  else
    get_environ ()->unset ("DISABLE_ASLR");

  pid_t pid = fork_inferior (program, str_program_args.c_str (),
                             get_environ ()->envp (), haiku_traceme,
                             haiku_init_trace, nullptr, nullptr, nullptr);

  add_process (pid, 0);

  post_fork_inferior (pid, program);

  return pid;
}

/* Implement the post_create_inferior target_ops method.  */

void
haiku_process_target::post_create_inferior ()
{
  low_arch_setup ();
}

/* Implement the attach target_ops method.  */

int
haiku_process_target::attach (unsigned long pid)
{
  /* Add the process soon since haiku_nat::attach will
     invoke our callback to report loaded libraries.  */
  process_info *process = add_process (pid, 1);

  if (haiku_nat::attach (pid, false) < 0)
    perror_with_name (("haiku_nat::attach"));

  low_arch_setup (process);

  return 0;
}

/* Implement the resume target_ops method.  */

void
haiku_process_target::resume (struct thread_resume *resume_info, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    {
      if (resume_info->thread.tid_p ())
        {
          thread_info *info = find_thread_ptid (ptid_t (
              resume_info->thread.pid (), 0, resume_info->thread.tid ()));
          if (info != nullptr)
            regcache_invalidate_thread (info);
        }
      else if (resume_info->thread.pid () > 0)
        regcache_invalidate_pid (resume_info->thread.pid ());
      else
        regcache_invalidate ();

      /* TODO: What does the step_range_[start/end] mean?  */
      if (haiku_nat::resume (resume_info->thread, resume_info->kind,
                             resume_info->sig)
          < 0)
        {
          haiku_nat_debug_printf ("Failed to actually resume the thread: %s",
                                  safe_strerror (errno));
        }
    }
}

/* Implement the wait target_ops method.  */

ptid_t
haiku_process_target::wait (ptid_t ptid, struct target_waitstatus *ourstatus,
                            target_wait_flags target_options)
{
  haiku_nat_debug_printf (
      "ptid=%s, ourstatus=%s, target_options=%i", ptid.to_string ().c_str (),
      ourstatus->to_string ().c_str (), (int)target_options.raw ());

  const auto attach_child = [&] () {
    pid_t pid = ourstatus->child_ptid ().pid ();

    process_info *process = add_process (pid, 0);

    /* The new process might have other images pre-loaded.
       Therefore, the second parameter should be false.  */
    if (haiku_nat::attach (pid, false) < 0)
      perror_with_name (("haiku_nat::attach"));

    low_arch_setup (process);

    /* Add at least the child's main thread. Otherwise, gdbserver would
       think we have no more inferiors attached and quit.  */
    add_thread (ptid_t (pid, 0, pid), nullptr);
  };

  client_state &cs = get_client_state ();

  while (true)
    {
      ptid_t wptid = haiku_nat::wait (ptid, ourstatus, target_options);

      if (wptid == minus_one_ptid)
        perror_with_name (("haiku_nat::wait"));

      if (wptid == null_ptid)
        {
          gdb_assert (target_options & TARGET_WNOHANG);
          return null_ptid;
        }

      /* Register thread in the gdbcore if a thread was not reported earlier.
         This is required after ::create_inferior, when the gdbcore does not
         know about the first internal thread.
         This may also happen on attach, when an event is registered on a
         thread that was not fully initialized during the attach stage.  */
      if (wptid.tid () != 0 && !find_thread_ptid (wptid)
          && ourstatus->kind () != TARGET_WAITKIND_THREAD_EXITED)
        add_thread (wptid, nullptr);

      switch (ourstatus->kind ())
        {
        case TARGET_WAITKIND_EXITED:
        case TARGET_WAITKIND_STOPPED:
        case TARGET_WAITKIND_SIGNALLED:
        case TARGET_WAITKIND_SYSCALL_ENTRY:
        case TARGET_WAITKIND_SYSCALL_RETURN:
          /* Pass the result to the generic code.  */
          return wptid;
        case TARGET_WAITKIND_LOADED:
          find_process_pid (wptid.pid ())->dlls_changed = true;

          /* Pass the result to the generic code.

             gdbserver core will absorb this event and convert it into a
             "stopped" event with GDB_SIGNAL_0.

             However, with dlls_changed set to true, when replying to the
             client, the message will be overwritten with a libraries changed
             notification, preventing GDB from actually breaking.  */
          return wptid;
        case TARGET_WAITKIND_FORKED:
          if (cs.report_fork_events)
            {
              attach_child ();
              return wptid;
            }
          break;
        case TARGET_WAITKIND_VFORKED:
          if (cs.report_vfork_events)
            {
              attach_child ();
              return wptid;
            }
          break;
        case TARGET_WAITKIND_VFORK_DONE:
          if (cs.report_vfork_events)
            return wptid;
          break;
        case TARGET_WAITKIND_EXECD:
          /* Always report exec events since startup relies on them.  */
          return wptid;
        case TARGET_WAITKIND_SPURIOUS:
          /* Spurious events are unhandled by the gdbserver core.  */
          /* Set wptid to -1 to continue waiting from any thread.  */
          wptid = minus_one_ptid;
          break;
        case TARGET_WAITKIND_THREAD_CREATED:
          if (cs.report_thread_events)
            return wptid;
          break;
        case TARGET_WAITKIND_THREAD_EXITED:
          remove_thread (find_thread_ptid (wptid));

          if (cs.report_thread_events)
            return wptid;

          /* The thread is dead so we cannot resume the the same wptid.  */
          wptid = ptid;
          break;
        default:
          gdb_assert_not_reached ("Unknown stopped status");
        }

      haiku_nat_debug_printf ("Event ignored: %s",
                              ourstatus->to_string ().c_str ());

      if (haiku_nat::resume (wptid, resume_continue, 0) < 0)
        perror_with_name (("haiku_nat::resume"));
    }
}

/* Implement the kill target_ops method.  */

int
haiku_process_target::kill (process_info *process)
{
  if (haiku_nat::kill (pid_of (process)) < 0)
    return -1;

  mourn (process);
  return 0;
}

/* Implement the detach target_ops method.  */

int
haiku_process_target::detach (process_info *process)
{
  if (haiku_nat::detach (pid_of (process)) < 0)
    return -1;

  mourn (process);
  return 0;
}

/* Implement the mourn target_ops method.  */

void
haiku_process_target::mourn (struct process_info *proc)
{
  for_each_thread (pid_of (proc), remove_thread);

  remove_process (proc);
}

/* Implement the join target_ops method.  */

void
haiku_process_target::join (int pid)
{
  gdb::handle_eintr (-1, ::waitpid, pid, nullptr, 0);
}

/* Implement the thread_alive target_ops method.  */

bool
haiku_process_target::thread_alive (ptid_t ptid)
{
  return haiku_nat::thread_alive (ptid);
}

/* Implement the read_memory target_ops method.  */

int
haiku_process_target::read_memory (CORE_ADDR memaddr, unsigned char *myaddr,
                                   int size)
{
  if (haiku_nat::read_memory (pid_of (current_process ()), memaddr, myaddr,
                              &size)
      < 0)
    {
      haiku_nat_debug_printf ("haiku_nat::read_memory failed: %s",
                              safe_strerror (errno));
      return errno;
    }
  return 0;
}

/* Implement the write_memory target_ops method.  */

int
haiku_process_target::write_memory (CORE_ADDR memaddr,
                                    const unsigned char *myaddr, int size)
{
  if (haiku_nat::write_memory (pid_of (current_process ()), memaddr, myaddr,
                               &size)
      < 0)
    {
      haiku_nat_debug_printf ("haiku_nat::write_memory failed: %s",
                              safe_strerror (errno));
      return errno;
    }
  return 0;
}

/* Implement the request_interrupt target_ops method.  */

void
haiku_process_target::request_interrupt ()
{
  thread_info *thread = get_first_thread ();

  if (thread == nullptr)
    return;

  ::kill (pid_of (thread), SIGINT);
}

/* Implement the read_offsets target_ops method.  */

int
haiku_process_target::read_offsets (CORE_ADDR *text, CORE_ADDR *data)
{
  if (haiku_nat::read_offsets (pid_of (current_process ()), text, data) < 0)
    return 0;
  return 1;
}

/* Implement the qxfer_osdata target_ops method.  */

int
haiku_process_target::qxfer_osdata (const char *annex, unsigned char *readbuf,
                                    unsigned const char *writebuf,
                                    CORE_ADDR offset, int len)
{
  if (writebuf != nullptr)
    return -2;
  return haiku_common_xfer_osdata (annex, readbuf, offset, len);
}

/* Implement the async target_ops method.  */

bool
haiku_process_target::async (bool enable)
{
  bool previous_enable = haiku_nat::is_async_p ();

  if (previous_enable != enable)
    {
      if (enable)
        {
          if (haiku_nat::async (true) < 0)
            warning ("haiku_nat::async failed: %s", safe_strerror (errno));
          else
            {
              add_file_handler (haiku_nat::async_wait_fd (),
                                handle_target_event, NULL, "haiku-low");
            }
        }
      else
        {
          /* Unregister this before async_wait_fd gets invalidated.  */
          delete_file_handler (haiku_nat::async_wait_fd ());
          haiku_nat::async (false);
        }
    }

  return previous_enable;
}

/* Implement the start_non_stop target_ops method.  */

int
haiku_process_target::start_non_stop (bool enable)
{
  async (enable);

  if (haiku_nat::is_async_p () != enable)
    return -1;

  /* TODO: Technically we do NOT support all-stop mode, since we do not lock
     the whole team when an event occurs. However, not accepting all-stop would
     result in annoying messages when using the GDB frontend with default
     configuration.  */
  return 0;
}

/* Implement the thread_stopped target_ops method.  */

bool
haiku_process_target::thread_stopped (thread_info *thread)
{
  return haiku_nat::thread_stopped (ptid_of (thread));
}

/* Implement the pid_to_exec_file target_ops method.  */

const char *
haiku_process_target::pid_to_exec_file (int pid)
{
  return haiku_nat::pid_to_exec_file (pid);
}

/* Implement the thread_name target_ops method.  */

const char *
haiku_process_target::thread_name (ptid_t thread)
{
  return haiku_nat::thread_name (thread);
}

/* Report supported features.  */

bool
haiku_process_target::supports_qxfer_osdata ()
{
  return true;
}

bool
haiku_process_target::supports_non_stop ()
{
  return true;
}

bool
haiku_process_target::supports_multi_process ()
{
  return true;
}

bool
haiku_process_target::supports_fork_events ()
{
  return true;
}

bool
haiku_process_target::supports_exec_events ()
{
  return true;
}

bool
haiku_process_target::supports_read_offsets ()
{
  return true;
}

bool
haiku_process_target::supports_thread_stopped ()
{
  return true;
}

bool
haiku_process_target::supports_disable_randomization ()
{
  return true;
}

bool
haiku_process_target::supports_pid_to_exec_file ()
{
  return true;
}

bool
haiku_process_target::supports_catch_syscall ()
{
  return true;
}

/* Supply other required functions */

namespace haiku_nat
{

void
debugger_output (const char *message)
{
  monitor_output (message);
}

void
image_created (ptid_t ptid, const image_info &info)
{
  haiku_nat_debug_printf ("ptid=%s, name=%s, text=%p",
                          ptid.to_string ().c_str (), info.name,
                          (void *)info.text);

  if (info.is_main_executable)
    return;

  process_info *process = find_process_pid (ptid.pid ());

  if (process == nullptr)
    return;

  process->all_dlls.emplace_back (info.name, info.text);

  /* DO NOT set info->dlls_changed here, since gdbserver will clobber an event.
     Instead, do it in wait after haiku_nat::wait gives a LOADED event.  */
}

void
image_deleted (ptid_t ptid, const image_info &info)
{
  haiku_nat_debug_printf ("ptid=%s, name=%s", ptid.to_string ().c_str (),
                          info.name);

  if (info.is_main_executable)
    return;

  process_info *process = find_process_pid (ptid.pid ());

  if (process == nullptr)
    return;

  if (info.name == nullptr)
    {
      /* Delete all images.  */
      process->all_dlls.clear ();
    }
  else
    {
      for (auto it = process->all_dlls.begin ();
           it != process->all_dlls.end ();)
        {
          if (it->name == info.name)
            {
              auto next = std::next (it);
              process->all_dlls.erase (it);
              it = next;
            }
          else
            {
              ++it;
            }
        }
    }
}

bool
is_catching_syscalls_for (ptid_t ptid)
{
  process_info *process = find_process_pid (ptid.pid ());

  if (process == nullptr)
    return false;

  return !process->syscalls_to_catch.empty ();
}

}

void
initialize_low ()
{
  set_target_ops (the_haiku_target);
}
