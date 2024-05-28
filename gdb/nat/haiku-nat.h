/* Internal interfaces for the Haiku code.

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

#ifndef NAT_HAIKU_NAT_H
#define NAT_HAIKU_NAT_H

#include <functional>

#include <unistd.h>

#include "target/resume.h"
#include "target/wait.h"

namespace haiku_nat
{

/* Attach gdb as the debugger for the process with the specified PID.
   Returns -1 on failure and 0 on success.  */

extern int attach (pid_t pid, bool is_ours);

/* Halts the current process until a debugger has been attached.  */

extern void wait_for_debugger ();

/* Fetch registers from the inferior process.  */

extern int get_cpu_state (ptid_t ptid, void *buffer);

/* Store registers to the inferior process.  */

extern int set_cpu_state (ptid_t ptid, const void *buffer);

/* Implement the resume target_ops method.

   Resume the inferior process.  */

extern int resume (ptid_t ptid, resume_kind kind, int sig);

/* Implement the wait target_ops method.

   Wait for the inferior process or thread to change state.  Store
   status through argument pointer STATUS.

   PTID = -1 to wait for any pid to do something, PTID(pid,0,0) to
   wait for any thread of process pid to do something.  Return ptid
   of child, or -1 in case of error; store status through argument
   pointer STATUS.  OPTIONS is a bit set of options defined as
   TARGET_W* above.  If options contains TARGET_WNOHANG and there's
   no child stop to report, return is
   null_ptid/TARGET_WAITKIND_IGNORE.  */

[[nodiscard]]
extern ptid_t wait (ptid_t ptid, struct target_waitstatus *ourstatus,
                    target_wait_flags target_options);

/* Implement the kill target_ops method.

   Kill process PROC.  Return -1 on failure, and 0 on success.  */

[[nodiscard]]
extern int kill (pid_t pid);

/* Implement the detach target_ops method.

   Detach from process PROC.  Return -1 on failure, and 0 on success.  */

[[nodiscard]]
extern int detach (pid_t pid);

/* Implement the thread_alive target_ops method.

   Return true iff the thread with process ID PID is alive.  */

[[nodiscard]]
extern bool thread_alive (ptid_t ptid);

/* Implement the read_memory target_ops method.

   Read LEN bytes at MEMADDR into a buffer at MYADDR.

   Returns 0 on success and -1 on failure.  */

[[nodiscard]]
extern int read_memory (pid_t pid, CORE_ADDR memaddr, unsigned char *myaddr,
                        int *sizeLeft);

/* Implement the write_memory target_ops method.

   Write LEN bytes from the buffer at MYADDR to MEMADDR.

   Returns 0 on success and -1 on failure.  */

[[nodiscard]]
extern int write_memory (pid_t pid, CORE_ADDR memaddr,
                         const unsigned char *myaddr, int *sizeLeft);

/* Implement the read_offsets target_ops method.

   Reports the text, data offsets of the executable.  This is
   needed for Haiku where the executable is relocated during load
   time.  */

[[nodiscard]]
extern int read_offsets (pid_t pid, CORE_ADDR *text, CORE_ADDR *data);

/* Implement the thread_stopped target_ops method.

   Return true if THREAD is known to be stopped now.  */

[[nodiscard]]
extern bool thread_stopped (ptid_t ptid);

/* Implement the pid_to_exec_file target_ops method.

   Return the full absolute name of the executable file that was
   run to create the process PID.  If the executable file cannot
   be determined, NULL is returned.  Otherwise, a pointer to a
   character string containing the pathname is returned.  This
   string should be copied into a buffer by the client if the string
   will not be immediately used, or if it must persist.   */

[[nodiscard]]
extern const char *pid_to_exec_file (pid_t pid);

/* Implement the thread_name target_ops method.

   Return the thread's name, or NULL if the target is unable to
   determine it.  The returned value must not be freed by the
   caller.  */

[[nodiscard]]
extern const char *thread_name (ptid_t ptid);

/* Implement the pid_to_str target_ops method.

   Converts a process id to a string.  Usually, the string just
   contains `process xyz', but on some systems it may contain
   `process xyz thread abc'.  */

[[nodiscard]]
extern std::string pid_to_str (ptid_t ptid);

/* Implement the stop target_ops method.

   Make target stop in a continuable fashion.  */

[[nodiscard]]
extern int stop (ptid_t ptid);

/* Implement the is_async_p target_ops method.

   Is the target in asynchronous execution mode?  */

[[nodiscard]]
extern bool is_async_p ();

/* Implement the async target_ops method.

   Enables/disables async target events.  */

extern int async (bool enable);

/* Implement the async_wait_fd target_ops method.  */

[[nodiscard]]
extern int async_wait_fd ();

struct image_info
{
  LONGEST id;
  CORE_ADDR text;
  ULONGEST text_size;
  CORE_ADDR data;
  ULONGEST data_size;
  const char *name;
  LONGEST sequence;
  LONGEST init_order;
  pid_t team;
  bool is_main_executable;
};

/* Calls the callback for each loaded image of the process with the specified
   PID.
   The callback should return -1 on error, 0 if the loop should continue,
   or 1 if the loop should end.
   If needs_one is true, the function returns an error if none of the callback
   invocations returns 1.

   Returns 0 on success and -1 on failure.  */
extern int
for_each_image (pid_t pid,
                const std::function<int (const image_info &info)> &callback,
                bool needs_one = false);

struct area_info
{
  LONGEST id;
  const char *name;
  ULONGEST size;
  bool can_read : 1;
  bool can_write : 1;
  bool can_exec : 1;
  bool is_stack : 1;
  bool can_clone : 1;
  pid_t team;
  ULONGEST ram_size;
  ULONGEST copy_count;
  ULONGEST in_count;
  ULONGEST out_count;
  CORE_ADDR address;
};

/* Calls the callback for each mapped area of the process with the specified
   PID.
   The callback should return -1 on error, 0 if the loop should continue,
   or 1 if the loop should end.

   Returns 0 on success and -1 on failure.  */
extern int
for_each_area (pid_t pid,
               const std::function<int (const area_info &info)> &callback);

struct thread_info
{
  ptid_t::tid_type tid;
  pid_t team;
  const char *name;
};

/* Calls the callback for each active thread of the process with the specified
   PID.
   The callback should return -1 on error, 0 if the loop should continue,
   or 1 if the loop should end.

   Returns 0 on success and -1 on failure.  */
extern int
for_each_thread (pid_t pid,
                 const std::function<int (const thread_info &info)> &callback);

struct fd_info
{
  int number;
  bool can_read : 1;
  bool can_write : 1;
  LONGEST device;
  LONGEST node;
  pid_t team;
  const char *name;
};

/* Calls the callback for each open file of the process with the specified PID.
   The callback should return -1 on error, 0 if the loop should continue,
   or 1 if the loop should end.

   Returns 0 on success and -1 on failure.  */
extern int
for_each_fd (pid_t pid,
             const std::function<int (const fd_info &info)> &callback);

struct port_info
{
  LONGEST id;
  pid_t team;
  const char *name;
  LONGEST capacity;
  LONGEST queue_count;
  LONGEST total_count;
};

/* Calls the callback for each open port of the process with the specified PID.
   The callback should return -1 on error, 0 if the loop should continue,
   or 1 if the loop should end.

   Returns 0 on success and -1 on failure.  */
extern int
for_each_port (pid_t pid,
               const std::function<int (const port_info &info)> &callback);

struct sem_info
{
  LONGEST id;
  pid_t team;
  const char *name;
  LONGEST count;
  ptid_t::tid_type latest_holder;
};

/* Calls the callback for each semaphore of the process with the specified PID.
   The callback should return -1 on error, 0 if the loop should continue,
   or 1 if the loop should end.

   Returns 0 on success and -1 on failure.  */
extern int
for_each_sem (pid_t pid,
              const std::function<int (const sem_info &info)> &callback);

struct team_info
{
  pid_t pid;
  const char *args;
  ULONGEST thread_count;
  ULONGEST image_count;
  ULONGEST area_count;
  LONGEST debugger_nub_thread;
  LONGEST debugger_nub_port;
  LONGEST uid;
  LONGEST gid;
  LONGEST real_uid;
  LONGEST real_gid;
  pid_t group_id;
  pid_t session_id;
  pid_t parent;
  const char *name;
  LONGEST start_time;
};

/* Gets the team with the specified ID.

   Returns a static buffer with the information on success
   and nullptr on failure.  */
[[nodiscard]]
const team_info *get_team (pid_t pid);

/* Calls the callback for each active team on the system.
   The callback should return -1 on error, 0 if the loop should continue,
   or 1 if the loop should end.

   Returns 0 on success and -1 on failure.  */
extern int
for_each_team (const std::function<int (const team_info &info)> &callback);

struct commpage_symbol_info
{
  const char *name;
  ULONGEST value;
  ULONGEST size;
  bool is_function : 1;
  bool is_object : 1;
};

/* Calls the callback for each known symbol on the commpage.
   The callback should return -1 on error, 0 if the loop should continue,
   or 1 if the loop should end.

   Returns 0 on success and -1 on failure.  */
extern int for_each_commpage_symbol (
    const std::function<int (const commpage_symbol_info &info)> &callback);

struct cpu_info
{
  LONGEST id;
  const char *platform;
  const char *vendor;
  ULONGEST cache_line_size;
  ULONGEST model;
  ULONGEST default_frequency;
  ULONGEST current_frequency;
  ULONGEST active_time;
  bool enabled;
};

/* Calls the callback for each CPU on the system.
   The callback should return -1 on error, 0 if the loop should continue,
   or 1 if the loop should end.

   Returns 0 on success and -1 on failure.  */
extern int
for_each_cpu (const std::function<int (const cpu_info &info)> &callback);

struct socket_info
{
  const char *family;
  const char *type;
  const char *state;
  pid_t team;
  const char *address;
  const char *peer;
  ULONGEST receive_queue_size;
  ULONGEST send_queue_size;
};

extern int
for_each_socket (const std::function<int (const socket_info &info)> &callback);

/* Utility functions that are meant to be supplied by the embedding
   application.  */

void debugger_output (const char *message);

void image_created (ptid_t ptid, const image_info &info);

void image_deleted (ptid_t ptid, const image_info &info);

bool is_catching_syscalls_for (ptid_t pid);

}

/* Tracing utility functions.  */

extern bool debug_haiku_nat;

/* Print a haiku-nat debug statement.  */

#define haiku_nat_debug_printf(fmt, ...)                                      \
  debug_prefixed_printf_cond (debug_haiku_nat, "haiku-nat", fmt, ##__VA_ARGS__)

/* Print "haiku-nat" enter/exit debug statements.  */

#define HAIKU_NAT_SCOPED_DEBUG_ENTER_EXIT                                     \
  scoped_debug_enter_exit (debug_haiku_nat, "haiku-nat")

#endif /* NAT_HAIKU_NAT_H */
