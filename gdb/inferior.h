/* Variables that describe the inferior process running under GDB:
   Where it is, why it stopped, and how to step it.

   Copyright (C) 1986, 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996,
   1998, 1999, 2000, 2001, 2003, 2004, 2005, 2006, 2007, 2008, 2009
   Free Software Foundation, Inc.

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

#if !defined (INFERIOR_H)
#define INFERIOR_H 1

struct target_waitstatus;
struct frame_info;
struct ui_file;
struct type;
struct gdbarch;
struct regcache;
struct ui_out;

/* For bpstat.  */
#include "breakpoint.h"

/* For enum target_signal.  */
#include "target.h"

/* For struct frame_id.  */
#include "frame.h"

/* Two structures are used to record inferior state.

   inferior_thread_state contains state about the program itself like its
   registers and any signal it received when it last stopped.
   This state must be restored regardless of how the inferior function call
   ends (either successfully, or after it hits a breakpoint or signal)
   if the program is to properly continue where it left off.

   inferior_status contains state regarding gdb's control of the inferior
   itself like stepping control.  It also contains session state like the
   user's currently selected frame.

   Call these routines around hand called functions, including function calls
   in conditional breakpoints for example.  */

struct inferior_thread_state;
struct inferior_status;

extern struct inferior_thread_state *save_inferior_thread_state (void);
extern struct inferior_status *save_inferior_status (void);

extern void restore_inferior_thread_state (struct inferior_thread_state *);
extern void restore_inferior_status (struct inferior_status *);

extern struct cleanup *make_cleanup_restore_inferior_thread_state (struct inferior_thread_state *);
extern struct cleanup *make_cleanup_restore_inferior_status (struct inferior_status *);

extern void discard_inferior_thread_state (struct inferior_thread_state *);
extern void discard_inferior_status (struct inferior_status *);

extern struct regcache *get_inferior_thread_state_regcache (struct inferior_thread_state *);

/* The -1 ptid, often used to indicate either an error condition
   or a "don't care" condition, i.e, "run all threads."  */
extern ptid_t minus_one_ptid;

/* The null or zero ptid, often used to indicate no process. */
extern ptid_t null_ptid;

/* Attempt to find and return an existing ptid with the given PID, LWP,
   and TID components.  If none exists, create a new one and return
   that.  */
ptid_t ptid_build (int pid, long lwp, long tid);

/* Find/Create a ptid from just a pid. */
ptid_t pid_to_ptid (int pid);

/* Fetch the pid (process id) component from a ptid. */
int ptid_get_pid (ptid_t ptid);

/* Fetch the lwp (lightweight process) component from a ptid. */
long ptid_get_lwp (ptid_t ptid);

/* Fetch the tid (thread id) component from a ptid. */
long ptid_get_tid (ptid_t ptid);

/* Compare two ptids to see if they are equal */
extern int ptid_equal (ptid_t p1, ptid_t p2);

/* Return true if PTID represents a process id.  */
extern int ptid_is_pid (ptid_t ptid);

/* Save value of inferior_ptid so that it may be restored by
   a later call to do_cleanups().  Returns the struct cleanup
   pointer needed for later doing the cleanup.  */
extern struct cleanup * save_inferior_ptid (void);

extern void set_sigint_trap (void);

extern void clear_sigint_trap (void);

/* Set/get file name for default use for standard in/out in the inferior.  */

extern void set_inferior_io_terminal (const char *terminal_name);
extern const char *get_inferior_io_terminal (void);

/* Collected pid, tid, etc. of the debugged inferior.  When there's
   no inferior, PIDGET (inferior_ptid) will be 0. */

extern ptid_t inferior_ptid;

/* Are we simulating synchronous execution? This is used in async gdb
   to implement the 'run', 'continue' etc commands, which will not
   redisplay the prompt until the execution is actually over. */
extern int sync_execution;

/* Inferior environment. */

extern struct gdb_environ *inferior_environ;

extern void clear_proceed_status (void);

extern void proceed (CORE_ADDR, enum target_signal, int);

/* When set, stop the 'step' command if we enter a function which has
   no line number information.  The normal behavior is that we step
   over such function.  */
extern int step_stop_if_no_debug;

/* If set, the inferior should be controlled in non-stop mode.  In
   this mode, each thread is controlled independently.  Execution
   commands apply only to the the selected thread by default, and stop
   events stop only the thread that had the event -- the other threads
   are kept running freely.  */
extern int non_stop;

extern void generic_mourn_inferior (void);

extern void terminal_save_ours (void);

extern void terminal_ours (void);

extern CORE_ADDR read_pc (void);

extern void write_pc (CORE_ADDR);

extern CORE_ADDR unsigned_pointer_to_address (struct type *type,
					      const gdb_byte *buf);
extern void unsigned_address_to_pointer (struct type *type, gdb_byte *buf,
					 CORE_ADDR addr);
extern CORE_ADDR signed_pointer_to_address (struct type *type,
					    const gdb_byte *buf);
extern void address_to_signed_pointer (struct type *type, gdb_byte *buf,
				       CORE_ADDR addr);

extern void wait_for_inferior (int treat_exec_as_sigtrap);

extern void fetch_inferior_event (void *);

extern void init_wait_for_inferior (void);

extern void close_exec_file (void);

extern void reopen_exec_file (void);

/* The `resume' routine should only be called in special circumstances.
   Normally, use `proceed', which handles a lot of bookkeeping.  */

extern void resume (int, enum target_signal);

/* From misc files */

extern void default_print_registers_info (struct gdbarch *gdbarch,
					  struct ui_file *file,
					  struct frame_info *frame,
					  int regnum, int all);

extern void child_terminal_info (char *, int);

extern void term_info (char *, int);

extern void terminal_ours_for_output (void);

extern void terminal_inferior (void);

extern void terminal_init_inferior (void);

extern void terminal_init_inferior_with_pgrp (int pgrp);

/* From procfs.c */

extern int proc_iterate_over_mappings (int (*)(int, CORE_ADDR));

extern ptid_t procfs_first_available (void);

/* From fork-child.c */

extern int fork_inferior (char *, char *, char **,
			  void (*)(void),
			  void (*)(int), void (*)(void), char *);


extern void startup_inferior (int);

extern char *construct_inferior_arguments (struct gdbarch *, int, char **);

/* From inflow.c */

extern void new_tty_prefork (const char *);

extern int gdb_has_a_terminal (void);

/* From infrun.c */

extern void start_remote (int from_tty);

extern void normal_stop (void);

extern int signal_stop_state (int);

extern int signal_print_state (int);

extern int signal_pass_state (int);

extern int signal_stop_update (int, int);

extern int signal_print_update (int, int);

extern int signal_pass_update (int, int);

extern void get_last_target_status(ptid_t *ptid,
                                   struct target_waitstatus *status);

extern void follow_inferior_reset_breakpoints (void);

/* Throw an error indicating the current thread is running.  */
extern void error_is_running (void);

/* Calls error_is_running if the current thread is running.  */
extern void ensure_not_running (void);

/* From infcmd.c */

extern void tty_command (char *, int);

extern void post_create_inferior (struct target_ops *, int);

extern void attach_command (char *, int);

extern char *get_inferior_args (void);

extern char *set_inferior_args (char *);

extern void set_inferior_args_vector (int, char **);

extern void registers_info (char *, int);

extern void nexti_command (char *, int);

extern void stepi_command (char *, int);

extern void continue_1 (int all_threads);

extern void continue_command (char *, int);

extern void interrupt_target_command (char *args, int from_tty);

extern void interrupt_target_1 (int all_threads);

extern void detach_command (char *, int);

extern void notice_new_inferior (ptid_t, int, int);

/* Address at which inferior stopped.  */

extern CORE_ADDR stop_pc;

/* Flag indicating that a command has proceeded the inferior past the
   current breakpoint.  */

extern int breakpoint_proceeded;

/* Nonzero if stopped due to completion of a stack dummy routine.  */

extern int stop_stack_dummy;

/* Nonzero if program stopped due to a random (unexpected) signal in
   inferior process.  */

extern int stopped_by_random_signal;

/* 1 means step over all subroutine calls.
   -1 means step over calls to undebuggable functions.  */

enum step_over_calls_kind
  {
    STEP_OVER_NONE,
    STEP_OVER_ALL,
    STEP_OVER_UNDEBUGGABLE
  };

/* Anything but NO_STOP_QUIETLY means we expect a trap and the caller
   will handle it themselves.  STOP_QUIETLY is used when running in
   the shell before the child program has been exec'd and when running
   through shared library loading.  STOP_QUIETLY_REMOTE is used when
   setting up a remote connection; it is like STOP_QUIETLY_NO_SIGSTOP
   except that there is no need to hide a signal.  */

/* It is also used after attach, due to attaching to a process. This
   is a bit trickier.  When doing an attach, the kernel stops the
   debuggee with a SIGSTOP.  On newer GNU/Linux kernels (>= 2.5.61)
   the handling of SIGSTOP for a ptraced process has changed. Earlier
   versions of the kernel would ignore these SIGSTOPs, while now
   SIGSTOP is treated like any other signal, i.e. it is not muffled.
   
   If the gdb user does a 'continue' after the 'attach', gdb passes
   the global variable stop_signal (which stores the signal from the
   attach, SIGSTOP) to the ptrace(PTRACE_CONT,...)  call.  This is
   problematic, because the kernel doesn't ignore such SIGSTOP
   now. I.e. it is reported back to gdb, which in turn presents it
   back to the user.
 
   To avoid the problem, we use STOP_QUIETLY_NO_SIGSTOP, which allows
   gdb to clear the value of stop_signal after the attach, so that it
   is not passed back down to the kernel.  */

enum stop_kind
  {
    NO_STOP_QUIETLY = 0,
    STOP_QUIETLY,
    STOP_QUIETLY_REMOTE,
    STOP_QUIETLY_NO_SIGSTOP
  };

/* Reverse execution.  */
enum exec_direction_kind
  {
    EXEC_FORWARD,
    EXEC_REVERSE,
    EXEC_ERROR
  };

extern enum exec_direction_kind execution_direction;

/* Save register contents here when executing a "finish" command or are
   about to pop a stack dummy frame, if-and-only-if proceed_to_finish is set.
   Thus this contains the return value from the called function (assuming
   values are returned in a register).  */

extern struct regcache *stop_registers;

/* True if we are debugging displaced stepping.  */
extern int debug_displaced;

/* Dump LEN bytes at BUF in hex to FILE, followed by a newline.  */
void displaced_step_dump_bytes (struct ui_file *file,
                                const gdb_byte *buf, size_t len);

/* When set, no calls to target_resumed observer will be made.  */
extern int suppress_resume_observer;


/* Possible values for gdbarch_call_dummy_location.  */
#define ON_STACK 1
#define AT_ENTRY_POINT 4
#define AT_SYMBOL 5

/* If STARTUP_WITH_SHELL is set, GDB's "run"
   will attempts to start up the debugee under a shell.
   This is in order for argument-expansion to occur. E.g.,
   (gdb) run *
   The "*" gets expanded by the shell into a list of files.
   While this is a nice feature, it turns out to interact badly
   with some of the catch-fork/catch-exec features we have added.
   In particular, if the shell does any fork/exec's before
   the exec of the target program, that can confuse GDB.
   To disable this feature, set STARTUP_WITH_SHELL to 0.
   To enable this feature, set STARTUP_WITH_SHELL to 1.
   The catch-exec traps expected during start-up will
   be 1 if target is not started up with a shell, 2 if it is.
   - RT
   If you disable this, you need to decrement
   START_INFERIOR_TRAPS_EXPECTED in tm.h. */
#define STARTUP_WITH_SHELL 1
#if !defined(START_INFERIOR_TRAPS_EXPECTED)
#define START_INFERIOR_TRAPS_EXPECTED	2
#endif

struct private_inferior;

/* GDB represents the state of each program execution with an object
   called an inferior.  An inferior typically corresponds to a process
   but is more general and applies also to targets that do not have a
   notion of processes.  Each run of an executable creates a new
   inferior, as does each attachment to an existing process.
   Inferiors have unique internal identifiers that are different from
   target process ids.  Each inferior may in turn have multiple
   threads running in it.  */

struct inferior
{
  /* Pointer to next inferior in singly-linked list of inferiors.  */
  struct inferior *next;

  /* Convenient handle (GDB inferior id).  Unique across all
     inferiors.  */
  int num;

  /* Actual target inferior id, usually, a process id.  This matches
     the ptid_t.pid member of threads of this inferior.  */
  int pid;

  /* See the definition of stop_kind above.  */
  enum stop_kind stop_soon;

  /* Nonzero if this child process was attached rather than
     forked.  */
  int attach_flag;

  /* What is left to do for an execution command after any thread of
     this inferior stops.  For continuations associated with a
     specific thread, see `struct thread_info'.  */
  struct continuation *continuations;

  /* Private data used by the target vector implementation.  */
  struct private_inferior *private;
};

/* Create an empty inferior list, or empty the existing one.  */
extern void init_inferior_list (void);

/* Add an inferior to the inferior list, print a message that a new
   inferior is found, and return the pointer to the new inferior.
   Caller may use this pointer to initialize the private inferior
   data.  */
extern struct inferior *add_inferior (int pid);

/* Same as add_inferior, but don't print new inferior notifications to
   the CLI.  */
extern struct inferior *add_inferior_silent (int pid);

/* Delete an existing inferior list entry, due to inferior exit.  */
extern void delete_inferior (int pid);

/* Same as delete_inferior, but don't print new inferior notifications
   to the CLI.  */
extern void delete_inferior_silent (int pid);

/* Delete an existing inferior list entry, due to inferior detaching.  */
extern void detach_inferior (int pid);

/* Get rid of all inferiors.  */
extern void discard_all_inferiors (void);

/* Translate the integer inferior id (GDB's homegrown id, not the system's)
   into a "pid" (which may be overloaded with extra inferior information).  */
extern int gdb_inferior_id_to_pid (int);

/* Translate a target 'pid' into the integer inferior id (GDB's
   homegrown id, not the system's).  */
extern int pid_to_gdb_inferior_id (int pid);

/* Boolean test for an already-known pid.  */
extern int in_inferior_list (int pid);

/* Boolean test for an already-known inferior id (GDB's homegrown id,
   not the system's).  */
extern int valid_gdb_inferior_id (int num);

/* Search function to lookup a inferior by target 'pid'.  */
extern struct inferior *find_inferior_pid (int pid);

/* Inferior iterator function.

   Calls a callback function once for each inferior, so long as the
   callback function returns false.  If the callback function returns
   true, the iteration will end and the current inferior will be
   returned.  This can be useful for implementing a search for a
   inferior with arbitrary attributes, or for applying some operation
   to every inferior.

   It is safe to delete the iterated inferior from the callback.  */
extern struct inferior *iterate_over_inferiors (int (*) (struct inferior *,
							 void *),
						void *);

/* Prints the list of inferiors and their details on UIOUT.

   If REQUESTED_INFERIOR is not -1, it's the GDB id of the inferior
   that should be printed.  Otherwise, all inferiors are printed.  */
extern void print_inferior (struct ui_out *uiout, int requested_inferior);

/* Returns true if the inferior list is not empty.  */
extern int have_inferiors (void);

/* Return a pointer to the current inferior.  It is an error to call
   this if there is no current inferior.  */
extern struct inferior *current_inferior (void);

#endif /* !defined (INFERIOR_H) */
