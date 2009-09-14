/* Select target systems and architectures at runtime for GDB.

   Copyright (C) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999,
   2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009
   Free Software Foundation, Inc.

   Contributed by Cygnus Support.

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
#include <errno.h>
#include "gdb_string.h"
#include "target.h"
#include "gdbcmd.h"
#include "symtab.h"
#include "inferior.h"
#include "bfd.h"
#include "symfile.h"
#include "objfiles.h"
#include "gdb_wait.h"
#include "dcache.h"
#include <signal.h>
#include "regcache.h"
#include "gdb_assert.h"
#include "gdbcore.h"
#include "exceptions.h"
#include "target-descriptions.h"
#include "gdbthread.h"
#include "solib.h"
#include "exec.h"
#include "inline-frame.h"

static void target_info (char *, int);

static void kill_or_be_killed (int);

static void default_terminal_info (char *, int);

static int default_watchpoint_addr_within_range (struct target_ops *,
						 CORE_ADDR, CORE_ADDR, int);

static int default_region_ok_for_hw_watchpoint (CORE_ADDR, int);

static int nosymbol (char *, CORE_ADDR *);

static void tcomplain (void) ATTR_NORETURN;

static int nomemory (CORE_ADDR, char *, int, int, struct target_ops *);

static int return_zero (void);

static int return_one (void);

static int return_minus_one (void);

void target_ignore (void);

static void target_command (char *, int);

static struct target_ops *find_default_run_target (char *);

static void nosupport_runtime (void);

static LONGEST default_xfer_partial (struct target_ops *ops,
				     enum target_object object,
				     const char *annex, gdb_byte *readbuf,
				     const gdb_byte *writebuf,
				     ULONGEST offset, LONGEST len);

static LONGEST current_xfer_partial (struct target_ops *ops,
				     enum target_object object,
				     const char *annex, gdb_byte *readbuf,
				     const gdb_byte *writebuf,
				     ULONGEST offset, LONGEST len);

static LONGEST target_xfer_partial (struct target_ops *ops,
				    enum target_object object,
				    const char *annex,
				    void *readbuf, const void *writebuf,
				    ULONGEST offset, LONGEST len);

static struct gdbarch *default_thread_architecture (struct target_ops *ops,
						    ptid_t ptid);

static void init_dummy_target (void);

static struct target_ops debug_target;

static void debug_to_open (char *, int);

static void debug_to_prepare_to_store (struct regcache *);

static void debug_to_files_info (struct target_ops *);

static int debug_to_insert_breakpoint (struct gdbarch *,
				       struct bp_target_info *);

static int debug_to_remove_breakpoint (struct gdbarch *,
				       struct bp_target_info *);

static int debug_to_can_use_hw_breakpoint (int, int, int);

static int debug_to_insert_hw_breakpoint (struct gdbarch *,
					  struct bp_target_info *);

static int debug_to_remove_hw_breakpoint (struct gdbarch *,
					  struct bp_target_info *);

static int debug_to_insert_watchpoint (CORE_ADDR, int, int);

static int debug_to_remove_watchpoint (CORE_ADDR, int, int);

static int debug_to_stopped_by_watchpoint (void);

static int debug_to_stopped_data_address (struct target_ops *, CORE_ADDR *);

static int debug_to_watchpoint_addr_within_range (struct target_ops *,
						  CORE_ADDR, CORE_ADDR, int);

static int debug_to_region_ok_for_hw_watchpoint (CORE_ADDR, int);

static void debug_to_terminal_init (void);

static void debug_to_terminal_inferior (void);

static void debug_to_terminal_ours_for_output (void);

static void debug_to_terminal_save_ours (void);

static void debug_to_terminal_ours (void);

static void debug_to_terminal_info (char *, int);

static void debug_to_load (char *, int);

static int debug_to_lookup_symbol (char *, CORE_ADDR *);

static int debug_to_can_run (void);

static void debug_to_notice_signals (ptid_t);

static void debug_to_stop (ptid_t);

/* NOTE: cagney/2004-09-29: Many targets reference this variable in
   wierd and mysterious ways.  Putting the variable here lets those
   wierd and mysterious ways keep building while they are being
   converted to the inferior inheritance structure.  */
struct target_ops deprecated_child_ops;

/* Pointer to array of target architecture structures; the size of the
   array; the current index into the array; the allocated size of the
   array.  */
struct target_ops **target_structs;
unsigned target_struct_size;
unsigned target_struct_index;
unsigned target_struct_allocsize;
#define	DEFAULT_ALLOCSIZE	10

/* The initial current target, so that there is always a semi-valid
   current target.  */

static struct target_ops dummy_target;

/* Top of target stack.  */

static struct target_ops *target_stack;

/* The target structure we are currently using to talk to a process
   or file or whatever "inferior" we have.  */

struct target_ops current_target;

/* Command list for target.  */

static struct cmd_list_element *targetlist = NULL;

/* Nonzero if we should trust readonly sections from the
   executable when reading memory.  */

static int trust_readonly = 0;

/* Nonzero if we should show true memory content including
   memory breakpoint inserted by gdb.  */

static int show_memory_breakpoints = 0;

/* Non-zero if we want to see trace of target level stuff.  */

static int targetdebug = 0;
static void
show_targetdebug (struct ui_file *file, int from_tty,
		  struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, _("Target debugging is %s.\n"), value);
}

static void setup_target_debug (void);

/* The option sets this.  */
static int stack_cache_enabled_p_1 = 1;
/* And set_stack_cache_enabled_p updates this.
   The reason for the separation is so that we don't flush the cache for
   on->on transitions.  */
static int stack_cache_enabled_p = 1;

/* This is called *after* the stack-cache has been set.
   Flush the cache for off->on and on->off transitions.
   There's no real need to flush the cache for on->off transitions,
   except cleanliness.  */

static void
set_stack_cache_enabled_p (char *args, int from_tty,
			   struct cmd_list_element *c)
{
  if (stack_cache_enabled_p != stack_cache_enabled_p_1)
    target_dcache_invalidate ();

  stack_cache_enabled_p = stack_cache_enabled_p_1;
}

static void
show_stack_cache_enabled_p (struct ui_file *file, int from_tty,
			    struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, _("Cache use for stack accesses is %s.\n"), value);
}

/* Cache of memory operations, to speed up remote access.  */
static DCACHE *target_dcache;

/* Invalidate the target dcache.  */

void
target_dcache_invalidate (void)
{
  dcache_invalidate (target_dcache);
}

/* The user just typed 'target' without the name of a target.  */

static void
target_command (char *arg, int from_tty)
{
  fputs_filtered ("Argument required (target name).  Try `help target'\n",
		  gdb_stdout);
}

/* Default target_has_* methods for process_stratum targets.  */

int
default_child_has_all_memory (struct target_ops *ops)
{
  /* If no inferior selected, then we can't read memory here.  */
  if (ptid_equal (inferior_ptid, null_ptid))
    return 0;

  return 1;
}

int
default_child_has_memory (struct target_ops *ops)
{
  /* If no inferior selected, then we can't read memory here.  */
  if (ptid_equal (inferior_ptid, null_ptid))
    return 0;

  return 1;
}

int
default_child_has_stack (struct target_ops *ops)
{
  /* If no inferior selected, there's no stack.  */
  if (ptid_equal (inferior_ptid, null_ptid))
    return 0;

  return 1;
}

int
default_child_has_registers (struct target_ops *ops)
{
  /* Can't read registers from no inferior.  */
  if (ptid_equal (inferior_ptid, null_ptid))
    return 0;

  return 1;
}

int
default_child_has_execution (struct target_ops *ops)
{
  /* If there's no thread selected, then we can't make it run through
     hoops.  */
  if (ptid_equal (inferior_ptid, null_ptid))
    return 0;

  return 1;
}


int
target_has_all_memory_1 (void)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_has_all_memory (t))
      return 1;

  return 0;
}

int
target_has_memory_1 (void)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_has_memory (t))
      return 1;

  return 0;
}

int
target_has_stack_1 (void)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_has_stack (t))
      return 1;

  return 0;
}

int
target_has_registers_1 (void)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_has_registers (t))
      return 1;

  return 0;
}

int
target_has_execution_1 (void)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_has_execution (t))
      return 1;

  return 0;
}

/* Add a possible target architecture to the list.  */

void
add_target (struct target_ops *t)
{
  /* Provide default values for all "must have" methods.  */
  if (t->to_xfer_partial == NULL)
    t->to_xfer_partial = default_xfer_partial;

  if (t->to_has_all_memory == NULL)
    t->to_has_all_memory = (int (*) (struct target_ops *)) return_zero;

  if (t->to_has_memory == NULL)
    t->to_has_memory = (int (*) (struct target_ops *)) return_zero;

  if (t->to_has_stack == NULL)
    t->to_has_stack = (int (*) (struct target_ops *)) return_zero;

  if (t->to_has_registers == NULL)
    t->to_has_registers = (int (*) (struct target_ops *)) return_zero;

  if (t->to_has_execution == NULL)
    t->to_has_execution = (int (*) (struct target_ops *)) return_zero;

  if (!target_structs)
    {
      target_struct_allocsize = DEFAULT_ALLOCSIZE;
      target_structs = (struct target_ops **) xmalloc
	(target_struct_allocsize * sizeof (*target_structs));
    }
  if (target_struct_size >= target_struct_allocsize)
    {
      target_struct_allocsize *= 2;
      target_structs = (struct target_ops **)
	xrealloc ((char *) target_structs,
		  target_struct_allocsize * sizeof (*target_structs));
    }
  target_structs[target_struct_size++] = t;

  if (targetlist == NULL)
    add_prefix_cmd ("target", class_run, target_command, _("\
Connect to a target machine or process.\n\
The first argument is the type or protocol of the target machine.\n\
Remaining arguments are interpreted by the target protocol.  For more\n\
information on the arguments for a particular protocol, type\n\
`help target ' followed by the protocol name."),
		    &targetlist, "target ", 0, &cmdlist);
  add_cmd (t->to_shortname, no_class, t->to_open, t->to_doc, &targetlist);
}

/* Stub functions */

void
target_ignore (void)
{
}

void
target_kill (void)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_kill != NULL)
      {
	if (targetdebug)
	  fprintf_unfiltered (gdb_stdlog, "target_kill ()\n");

        t->to_kill (t);
	return;
      }

  noprocess ();
}

void
target_load (char *arg, int from_tty)
{
  target_dcache_invalidate ();
  (*current_target.to_load) (arg, from_tty);
}

void
target_create_inferior (char *exec_file, char *args,
			char **env, int from_tty)
{
  struct target_ops *t;
  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_create_inferior != NULL)	
	{
	  t->to_create_inferior (t, exec_file, args, env, from_tty);
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog,
				"target_create_inferior (%s, %s, xxx, %d)\n",
				exec_file, args, from_tty);
	  return;
	}
    }

  internal_error (__FILE__, __LINE__,
		  "could not find a target to create inferior");
}

void
target_terminal_inferior (void)
{
  /* A background resume (``run&'') should leave GDB in control of the
     terminal.  */
  if (target_is_async_p () && !sync_execution)
    return;

  /* If GDB is resuming the inferior in the foreground, install
     inferior's terminal modes.  */
  (*current_target.to_terminal_inferior) ();
}

static int
nomemory (CORE_ADDR memaddr, char *myaddr, int len, int write,
	  struct target_ops *t)
{
  errno = EIO;			/* Can't read/write this location */
  return 0;			/* No bytes handled */
}

static void
tcomplain (void)
{
  error (_("You can't do that when your target is `%s'"),
	 current_target.to_shortname);
}

void
noprocess (void)
{
  error (_("You can't do that without a process to debug."));
}

static int
nosymbol (char *name, CORE_ADDR *addrp)
{
  return 1;			/* Symbol does not exist in target env */
}

static void
nosupport_runtime (void)
{
  if (ptid_equal (inferior_ptid, null_ptid))
    noprocess ();
  else
    error (_("No run-time support for this"));
}


static void
default_terminal_info (char *args, int from_tty)
{
  printf_unfiltered (_("No saved terminal information.\n"));
}

/* This is the default target_create_inferior and target_attach function.
   If the current target is executing, it asks whether to kill it off.
   If this function returns without calling error(), it has killed off
   the target, and the operation should be attempted.  */

static void
kill_or_be_killed (int from_tty)
{
  if (target_has_execution)
    {
      printf_unfiltered (_("You are already running a program:\n"));
      target_files_info ();
      if (query (_("Kill it? ")))
	{
	  target_kill ();
	  if (target_has_execution)
	    error (_("Killing the program did not help."));
	  return;
	}
      else
	{
	  error (_("Program not killed."));
	}
    }
  tcomplain ();
}

/* A default implementation for the to_get_ada_task_ptid target method.

   This function builds the PTID by using both LWP and TID as part of
   the PTID lwp and tid elements.  The pid used is the pid of the
   inferior_ptid.  */

static ptid_t
default_get_ada_task_ptid (long lwp, long tid)
{
  return ptid_build (ptid_get_pid (inferior_ptid), lwp, tid);
}

/* Go through the target stack from top to bottom, copying over zero
   entries in current_target, then filling in still empty entries.  In
   effect, we are doing class inheritance through the pushed target
   vectors.

   NOTE: cagney/2003-10-17: The problem with this inheritance, as it
   is currently implemented, is that it discards any knowledge of
   which target an inherited method originally belonged to.
   Consequently, new new target methods should instead explicitly and
   locally search the target stack for the target that can handle the
   request.  */

static void
update_current_target (void)
{
  struct target_ops *t;

  /* First, reset current's contents.  */
  memset (&current_target, 0, sizeof (current_target));

#define INHERIT(FIELD, TARGET) \
      if (!current_target.FIELD) \
	current_target.FIELD = (TARGET)->FIELD

  for (t = target_stack; t; t = t->beneath)
    {
      INHERIT (to_shortname, t);
      INHERIT (to_longname, t);
      INHERIT (to_doc, t);
      /* Do not inherit to_open.  */
      /* Do not inherit to_close.  */
      /* Do not inherit to_attach.  */
      INHERIT (to_post_attach, t);
      INHERIT (to_attach_no_wait, t);
      /* Do not inherit to_detach.  */
      /* Do not inherit to_disconnect.  */
      /* Do not inherit to_resume.  */
      /* Do not inherit to_wait.  */
      /* Do not inherit to_fetch_registers.  */
      /* Do not inherit to_store_registers.  */
      INHERIT (to_prepare_to_store, t);
      INHERIT (deprecated_xfer_memory, t);
      INHERIT (to_files_info, t);
      INHERIT (to_insert_breakpoint, t);
      INHERIT (to_remove_breakpoint, t);
      INHERIT (to_can_use_hw_breakpoint, t);
      INHERIT (to_insert_hw_breakpoint, t);
      INHERIT (to_remove_hw_breakpoint, t);
      INHERIT (to_insert_watchpoint, t);
      INHERIT (to_remove_watchpoint, t);
      INHERIT (to_stopped_data_address, t);
      INHERIT (to_have_steppable_watchpoint, t);
      INHERIT (to_have_continuable_watchpoint, t);
      INHERIT (to_stopped_by_watchpoint, t);
      INHERIT (to_watchpoint_addr_within_range, t);
      INHERIT (to_region_ok_for_hw_watchpoint, t);
      INHERIT (to_terminal_init, t);
      INHERIT (to_terminal_inferior, t);
      INHERIT (to_terminal_ours_for_output, t);
      INHERIT (to_terminal_ours, t);
      INHERIT (to_terminal_save_ours, t);
      INHERIT (to_terminal_info, t);
      /* Do not inherit to_kill.  */
      INHERIT (to_load, t);
      INHERIT (to_lookup_symbol, t);
      /* Do no inherit to_create_inferior.  */
      INHERIT (to_post_startup_inferior, t);
      INHERIT (to_acknowledge_created_inferior, t);
      INHERIT (to_insert_fork_catchpoint, t);
      INHERIT (to_remove_fork_catchpoint, t);
      INHERIT (to_insert_vfork_catchpoint, t);
      INHERIT (to_remove_vfork_catchpoint, t);
      /* Do not inherit to_follow_fork.  */
      INHERIT (to_insert_exec_catchpoint, t);
      INHERIT (to_remove_exec_catchpoint, t);
      INHERIT (to_has_exited, t);
      /* Do not inherit to_mourn_inferiour.  */
      INHERIT (to_can_run, t);
      INHERIT (to_notice_signals, t);
      /* Do not inherit to_thread_alive.  */
      /* Do not inherit to_find_new_threads.  */
      /* Do not inherit to_pid_to_str.  */
      INHERIT (to_extra_thread_info, t);
      INHERIT (to_stop, t);
      /* Do not inherit to_xfer_partial.  */
      INHERIT (to_rcmd, t);
      INHERIT (to_pid_to_exec_file, t);
      INHERIT (to_log_command, t);
      INHERIT (to_stratum, t);
      /* Do not inherit to_has_all_memory */
      /* Do not inherit to_has_memory */
      /* Do not inherit to_has_stack */
      /* Do not inherit to_has_registers */
      /* Do not inherit to_has_execution */
      INHERIT (to_has_thread_control, t);
      INHERIT (to_can_async_p, t);
      INHERIT (to_is_async_p, t);
      INHERIT (to_async, t);
      INHERIT (to_async_mask, t);
      INHERIT (to_find_memory_regions, t);
      INHERIT (to_make_corefile_notes, t);
      /* Do not inherit to_get_thread_local_address.  */
      INHERIT (to_can_execute_reverse, t);
      INHERIT (to_thread_architecture, t);
      /* Do not inherit to_read_description.  */
      INHERIT (to_get_ada_task_ptid, t);
      /* Do not inherit to_search_memory.  */
      INHERIT (to_supports_multi_process, t);
      INHERIT (to_magic, t);
      /* Do not inherit to_memory_map.  */
      /* Do not inherit to_flash_erase.  */
      /* Do not inherit to_flash_done.  */
    }
#undef INHERIT

  /* Clean up a target struct so it no longer has any zero pointers in
     it.  Some entries are defaulted to a method that print an error,
     others are hard-wired to a standard recursive default.  */

#define de_fault(field, value) \
  if (!current_target.field)               \
    current_target.field = value

  de_fault (to_open,
	    (void (*) (char *, int))
	    tcomplain);
  de_fault (to_close,
	    (void (*) (int))
	    target_ignore);
  de_fault (to_post_attach,
	    (void (*) (int))
	    target_ignore);
  de_fault (to_prepare_to_store,
	    (void (*) (struct regcache *))
	    noprocess);
  de_fault (deprecated_xfer_memory,
	    (int (*) (CORE_ADDR, gdb_byte *, int, int, struct mem_attrib *, struct target_ops *))
	    nomemory);
  de_fault (to_files_info,
	    (void (*) (struct target_ops *))
	    target_ignore);
  de_fault (to_insert_breakpoint,
	    memory_insert_breakpoint);
  de_fault (to_remove_breakpoint,
	    memory_remove_breakpoint);
  de_fault (to_can_use_hw_breakpoint,
	    (int (*) (int, int, int))
	    return_zero);
  de_fault (to_insert_hw_breakpoint,
	    (int (*) (struct gdbarch *, struct bp_target_info *))
	    return_minus_one);
  de_fault (to_remove_hw_breakpoint,
	    (int (*) (struct gdbarch *, struct bp_target_info *))
	    return_minus_one);
  de_fault (to_insert_watchpoint,
	    (int (*) (CORE_ADDR, int, int))
	    return_minus_one);
  de_fault (to_remove_watchpoint,
	    (int (*) (CORE_ADDR, int, int))
	    return_minus_one);
  de_fault (to_stopped_by_watchpoint,
	    (int (*) (void))
	    return_zero);
  de_fault (to_stopped_data_address,
	    (int (*) (struct target_ops *, CORE_ADDR *))
	    return_zero);
  de_fault (to_watchpoint_addr_within_range,
	    default_watchpoint_addr_within_range);
  de_fault (to_region_ok_for_hw_watchpoint,
	    default_region_ok_for_hw_watchpoint);
  de_fault (to_terminal_init,
	    (void (*) (void))
	    target_ignore);
  de_fault (to_terminal_inferior,
	    (void (*) (void))
	    target_ignore);
  de_fault (to_terminal_ours_for_output,
	    (void (*) (void))
	    target_ignore);
  de_fault (to_terminal_ours,
	    (void (*) (void))
	    target_ignore);
  de_fault (to_terminal_save_ours,
	    (void (*) (void))
	    target_ignore);
  de_fault (to_terminal_info,
	    default_terminal_info);
  de_fault (to_load,
	    (void (*) (char *, int))
	    tcomplain);
  de_fault (to_lookup_symbol,
	    (int (*) (char *, CORE_ADDR *))
	    nosymbol);
  de_fault (to_post_startup_inferior,
	    (void (*) (ptid_t))
	    target_ignore);
  de_fault (to_acknowledge_created_inferior,
	    (void (*) (int))
	    target_ignore);
  de_fault (to_insert_fork_catchpoint,
	    (void (*) (int))
	    tcomplain);
  de_fault (to_remove_fork_catchpoint,
	    (int (*) (int))
	    tcomplain);
  de_fault (to_insert_vfork_catchpoint,
	    (void (*) (int))
	    tcomplain);
  de_fault (to_remove_vfork_catchpoint,
	    (int (*) (int))
	    tcomplain);
  de_fault (to_insert_exec_catchpoint,
	    (void (*) (int))
	    tcomplain);
  de_fault (to_remove_exec_catchpoint,
	    (int (*) (int))
	    tcomplain);
  de_fault (to_has_exited,
	    (int (*) (int, int, int *))
	    return_zero);
  de_fault (to_can_run,
	    return_zero);
  de_fault (to_notice_signals,
	    (void (*) (ptid_t))
	    target_ignore);
  de_fault (to_extra_thread_info,
	    (char *(*) (struct thread_info *))
	    return_zero);
  de_fault (to_stop,
	    (void (*) (ptid_t))
	    target_ignore);
  current_target.to_xfer_partial = current_xfer_partial;
  de_fault (to_rcmd,
	    (void (*) (char *, struct ui_file *))
	    tcomplain);
  de_fault (to_pid_to_exec_file,
	    (char *(*) (int))
	    return_zero);
  de_fault (to_async,
	    (void (*) (void (*) (enum inferior_event_type, void*), void*))
	    tcomplain);
  de_fault (to_async_mask,
	    (int (*) (int))
	    return_one);
  de_fault (to_thread_architecture,
	    default_thread_architecture);
  current_target.to_read_description = NULL;
  de_fault (to_get_ada_task_ptid,
            (ptid_t (*) (long, long))
            default_get_ada_task_ptid);
  de_fault (to_supports_multi_process,
	    (int (*) (void))
	    return_zero);
#undef de_fault

  /* Finally, position the target-stack beneath the squashed
     "current_target".  That way code looking for a non-inherited
     target method can quickly and simply find it.  */
  current_target.beneath = target_stack;

  if (targetdebug)
    setup_target_debug ();
}

/* Push a new target type into the stack of the existing target accessors,
   possibly superseding some of the existing accessors.

   Result is zero if the pushed target ended up on top of the stack,
   nonzero if at least one target is on top of it.

   Rather than allow an empty stack, we always have the dummy target at
   the bottom stratum, so we can call the function vectors without
   checking them.  */

int
push_target (struct target_ops *t)
{
  struct target_ops **cur;

  /* Check magic number.  If wrong, it probably means someone changed
     the struct definition, but not all the places that initialize one.  */
  if (t->to_magic != OPS_MAGIC)
    {
      fprintf_unfiltered (gdb_stderr,
			  "Magic number of %s target struct wrong\n",
			  t->to_shortname);
      internal_error (__FILE__, __LINE__, _("failed internal consistency check"));
    }

  /* Find the proper stratum to install this target in.  */
  for (cur = &target_stack; (*cur) != NULL; cur = &(*cur)->beneath)
    {
      if ((int) (t->to_stratum) >= (int) (*cur)->to_stratum)
	break;
    }

  /* If there's already targets at this stratum, remove them.  */
  /* FIXME: cagney/2003-10-15: I think this should be popping all
     targets to CUR, and not just those at this stratum level.  */
  while ((*cur) != NULL && t->to_stratum == (*cur)->to_stratum)
    {
      /* There's already something at this stratum level.  Close it,
         and un-hook it from the stack.  */
      struct target_ops *tmp = (*cur);
      (*cur) = (*cur)->beneath;
      tmp->beneath = NULL;
      target_close (tmp, 0);
    }

  /* We have removed all targets in our stratum, now add the new one.  */
  t->beneath = (*cur);
  (*cur) = t;

  update_current_target ();

  /* Not on top?  */
  return (t != target_stack);
}

/* Remove a target_ops vector from the stack, wherever it may be.
   Return how many times it was removed (0 or 1).  */

int
unpush_target (struct target_ops *t)
{
  struct target_ops **cur;
  struct target_ops *tmp;

  if (t->to_stratum == dummy_stratum)
    internal_error (__FILE__, __LINE__,
		    "Attempt to unpush the dummy target");

  /* Look for the specified target.  Note that we assume that a target
     can only occur once in the target stack. */

  for (cur = &target_stack; (*cur) != NULL; cur = &(*cur)->beneath)
    {
      if ((*cur) == t)
	break;
    }

  if ((*cur) == NULL)
    return 0;			/* Didn't find target_ops, quit now */

  /* NOTE: cagney/2003-12-06: In '94 the close call was made
     unconditional by moving it to before the above check that the
     target was in the target stack (something about "Change the way
     pushing and popping of targets work to support target overlays
     and inheritance").  This doesn't make much sense - only open
     targets should be closed.  */
  target_close (t, 0);

  /* Unchain the target */
  tmp = (*cur);
  (*cur) = (*cur)->beneath;
  tmp->beneath = NULL;

  update_current_target ();

  return 1;
}

void
pop_target (void)
{
  target_close (target_stack, 0);	/* Let it clean up */
  if (unpush_target (target_stack) == 1)
    return;

  fprintf_unfiltered (gdb_stderr,
		      "pop_target couldn't find target %s\n",
		      current_target.to_shortname);
  internal_error (__FILE__, __LINE__, _("failed internal consistency check"));
}

void
pop_all_targets_above (enum strata above_stratum, int quitting)
{
  while ((int) (current_target.to_stratum) > (int) above_stratum)
    {
      target_close (target_stack, quitting);
      if (!unpush_target (target_stack))
	{
	  fprintf_unfiltered (gdb_stderr,
			      "pop_all_targets couldn't find target %s\n",
			      target_stack->to_shortname);
	  internal_error (__FILE__, __LINE__,
			  _("failed internal consistency check"));
	  break;
	}
    }
}

void
pop_all_targets (int quitting)
{
  pop_all_targets_above (dummy_stratum, quitting);
}

/* Using the objfile specified in OBJFILE, find the address for the
   current thread's thread-local storage with offset OFFSET.  */
CORE_ADDR
target_translate_tls_address (struct objfile *objfile, CORE_ADDR offset)
{
  volatile CORE_ADDR addr = 0;
  struct target_ops *target;

  for (target = current_target.beneath;
       target != NULL;
       target = target->beneath)
    {
      if (target->to_get_thread_local_address != NULL)
	break;
    }

  if (target != NULL
      && gdbarch_fetch_tls_load_module_address_p (target_gdbarch))
    {
      ptid_t ptid = inferior_ptid;
      volatile struct gdb_exception ex;

      TRY_CATCH (ex, RETURN_MASK_ALL)
	{
	  CORE_ADDR lm_addr;
	  
	  /* Fetch the load module address for this objfile.  */
	  lm_addr = gdbarch_fetch_tls_load_module_address (target_gdbarch,
	                                                   objfile);
	  /* If it's 0, throw the appropriate exception.  */
	  if (lm_addr == 0)
	    throw_error (TLS_LOAD_MODULE_NOT_FOUND_ERROR,
			 _("TLS load module not found"));

	  addr = target->to_get_thread_local_address (target, ptid, lm_addr, offset);
	}
      /* If an error occurred, print TLS related messages here.  Otherwise,
         throw the error to some higher catcher.  */
      if (ex.reason < 0)
	{
	  int objfile_is_library = (objfile->flags & OBJF_SHARED);

	  switch (ex.error)
	    {
	    case TLS_NO_LIBRARY_SUPPORT_ERROR:
	      error (_("Cannot find thread-local variables in this thread library."));
	      break;
	    case TLS_LOAD_MODULE_NOT_FOUND_ERROR:
	      if (objfile_is_library)
		error (_("Cannot find shared library `%s' in dynamic"
		         " linker's load module list"), objfile->name);
	      else
		error (_("Cannot find executable file `%s' in dynamic"
		         " linker's load module list"), objfile->name);
	      break;
	    case TLS_NOT_ALLOCATED_YET_ERROR:
	      if (objfile_is_library)
		error (_("The inferior has not yet allocated storage for"
		         " thread-local variables in\n"
		         "the shared library `%s'\n"
		         "for %s"),
		       objfile->name, target_pid_to_str (ptid));
	      else
		error (_("The inferior has not yet allocated storage for"
		         " thread-local variables in\n"
		         "the executable `%s'\n"
		         "for %s"),
		       objfile->name, target_pid_to_str (ptid));
	      break;
	    case TLS_GENERIC_ERROR:
	      if (objfile_is_library)
		error (_("Cannot find thread-local storage for %s, "
		         "shared library %s:\n%s"),
		       target_pid_to_str (ptid),
		       objfile->name, ex.message);
	      else
		error (_("Cannot find thread-local storage for %s, "
		         "executable file %s:\n%s"),
		       target_pid_to_str (ptid),
		       objfile->name, ex.message);
	      break;
	    default:
	      throw_exception (ex);
	      break;
	    }
	}
    }
  /* It wouldn't be wrong here to try a gdbarch method, too; finding
     TLS is an ABI-specific thing.  But we don't do that yet.  */
  else
    error (_("Cannot find thread-local variables on this target"));

  return addr;
}

#undef	MIN
#define MIN(A, B) (((A) <= (B)) ? (A) : (B))

/* target_read_string -- read a null terminated string, up to LEN bytes,
   from MEMADDR in target.  Set *ERRNOP to the errno code, or 0 if successful.
   Set *STRING to a pointer to malloc'd memory containing the data; the caller
   is responsible for freeing it.  Return the number of bytes successfully
   read.  */

int
target_read_string (CORE_ADDR memaddr, char **string, int len, int *errnop)
{
  int tlen, origlen, offset, i;
  gdb_byte buf[4];
  int errcode = 0;
  char *buffer;
  int buffer_allocated;
  char *bufptr;
  unsigned int nbytes_read = 0;

  gdb_assert (string);

  /* Small for testing.  */
  buffer_allocated = 4;
  buffer = xmalloc (buffer_allocated);
  bufptr = buffer;

  origlen = len;

  while (len > 0)
    {
      tlen = MIN (len, 4 - (memaddr & 3));
      offset = memaddr & 3;

      errcode = target_read_memory (memaddr & ~3, buf, sizeof buf);
      if (errcode != 0)
	{
	  /* The transfer request might have crossed the boundary to an
	     unallocated region of memory. Retry the transfer, requesting
	     a single byte.  */
	  tlen = 1;
	  offset = 0;
	  errcode = target_read_memory (memaddr, buf, 1);
	  if (errcode != 0)
	    goto done;
	}

      if (bufptr - buffer + tlen > buffer_allocated)
	{
	  unsigned int bytes;
	  bytes = bufptr - buffer;
	  buffer_allocated *= 2;
	  buffer = xrealloc (buffer, buffer_allocated);
	  bufptr = buffer + bytes;
	}

      for (i = 0; i < tlen; i++)
	{
	  *bufptr++ = buf[i + offset];
	  if (buf[i + offset] == '\000')
	    {
	      nbytes_read += i + 1;
	      goto done;
	    }
	}

      memaddr += tlen;
      len -= tlen;
      nbytes_read += tlen;
    }
done:
  *string = buffer;
  if (errnop != NULL)
    *errnop = errcode;
  return nbytes_read;
}

struct target_section_table *
target_get_section_table (struct target_ops *target)
{
  struct target_ops *t;

  if (targetdebug)
    fprintf_unfiltered (gdb_stdlog, "target_get_section_table ()\n");

  for (t = target; t != NULL; t = t->beneath)
    if (t->to_get_section_table != NULL)
      return (*t->to_get_section_table) (t);

  return NULL;
}

/* Find a section containing ADDR.  */

struct target_section *
target_section_by_addr (struct target_ops *target, CORE_ADDR addr)
{
  struct target_section_table *table = target_get_section_table (target);
  struct target_section *secp;

  if (table == NULL)
    return NULL;

  for (secp = table->sections; secp < table->sections_end; secp++)
    {
      if (addr >= secp->addr && addr < secp->endaddr)
	return secp;
    }
  return NULL;
}

/* Perform a partial memory transfer.  The arguments and return
   value are just as for target_xfer_partial.  */

static LONGEST
memory_xfer_partial (struct target_ops *ops, enum target_object object,
		     void *readbuf, const void *writebuf, ULONGEST memaddr,
		     LONGEST len)
{
  LONGEST res;
  int reg_len;
  struct mem_region *region;
  struct inferior *inf;

  /* Zero length requests are ok and require no work.  */
  if (len == 0)
    return 0;

  /* For accesses to unmapped overlay sections, read directly from
     files.  Must do this first, as MEMADDR may need adjustment.  */
  if (readbuf != NULL && overlay_debugging)
    {
      struct obj_section *section = find_pc_overlay (memaddr);
      if (pc_in_unmapped_range (memaddr, section))
	{
	  struct target_section_table *table
	    = target_get_section_table (ops);
	  const char *section_name = section->the_bfd_section->name;
	  memaddr = overlay_mapped_address (memaddr, section);
	  return section_table_xfer_memory_partial (readbuf, writebuf,
						    memaddr, len,
						    table->sections,
						    table->sections_end,
						    section_name);
	}
    }

  /* Try the executable files, if "trust-readonly-sections" is set.  */
  if (readbuf != NULL && trust_readonly)
    {
      struct target_section *secp;
      struct target_section_table *table;

      secp = target_section_by_addr (ops, memaddr);
      if (secp != NULL
	  && (bfd_get_section_flags (secp->bfd, secp->the_bfd_section)
	      & SEC_READONLY))
	{
	  table = target_get_section_table (ops);
	  return section_table_xfer_memory_partial (readbuf, writebuf,
						    memaddr, len,
						    table->sections,
						    table->sections_end,
						    NULL);
	}
    }

  /* Try GDB's internal data cache.  */
  region = lookup_mem_region (memaddr);
  /* region->hi == 0 means there's no upper bound.  */
  if (memaddr + len < region->hi || region->hi == 0)
    reg_len = len;
  else
    reg_len = region->hi - memaddr;

  switch (region->attrib.mode)
    {
    case MEM_RO:
      if (writebuf != NULL)
	return -1;
      break;

    case MEM_WO:
      if (readbuf != NULL)
	return -1;
      break;

    case MEM_FLASH:
      /* We only support writing to flash during "load" for now.  */
      if (writebuf != NULL)
	error (_("Writing to flash memory forbidden in this context"));
      break;

    case MEM_NONE:
      return -1;
    }

  inf = find_inferior_pid (ptid_get_pid (inferior_ptid));

  if (inf != NULL
      && (region->attrib.cache
	  || (stack_cache_enabled_p && object == TARGET_OBJECT_STACK_MEMORY)))
    {
      if (readbuf != NULL)
	res = dcache_xfer_memory (ops, target_dcache, memaddr, readbuf,
				  reg_len, 0);
      else
	/* FIXME drow/2006-08-09: If we're going to preserve const
	   correctness dcache_xfer_memory should take readbuf and
	   writebuf.  */
	res = dcache_xfer_memory (ops, target_dcache, memaddr,
				  (void *) writebuf,
				  reg_len, 1);
      if (res <= 0)
	return -1;
      else
	{
	  if (readbuf && !show_memory_breakpoints)
	    breakpoint_restore_shadows (readbuf, memaddr, reg_len);
	  return res;
	}
    }

  /* If none of those methods found the memory we wanted, fall back
     to a target partial transfer.  Normally a single call to
     to_xfer_partial is enough; if it doesn't recognize an object
     it will call the to_xfer_partial of the next target down.
     But for memory this won't do.  Memory is the only target
     object which can be read from more than one valid target.
     A core file, for instance, could have some of memory but
     delegate other bits to the target below it.  So, we must
     manually try all targets.  */

  do
    {
      res = ops->to_xfer_partial (ops, TARGET_OBJECT_MEMORY, NULL,
				  readbuf, writebuf, memaddr, reg_len);
      if (res > 0)
	break;

      /* We want to continue past core files to executables, but not
	 past a running target's memory.  */
      if (ops->to_has_all_memory (ops))
	break;

      ops = ops->beneath;
    }
  while (ops != NULL);

  if (readbuf && !show_memory_breakpoints)
    breakpoint_restore_shadows (readbuf, memaddr, reg_len);

  /* Make sure the cache gets updated no matter what - if we are writing
     to the stack.  Even if this write is not tagged as such, we still need
     to update the cache.  */

  if (res > 0
      && inf != NULL
      && writebuf != NULL
      && !region->attrib.cache
      && stack_cache_enabled_p
      && object != TARGET_OBJECT_STACK_MEMORY)
    {
      dcache_update (target_dcache, memaddr, (void *) writebuf, reg_len);
    }

  /* If we still haven't got anything, return the last error.  We
     give up.  */
  return res;
}

static void
restore_show_memory_breakpoints (void *arg)
{
  show_memory_breakpoints = (uintptr_t) arg;
}

struct cleanup *
make_show_memory_breakpoints_cleanup (int show)
{
  int current = show_memory_breakpoints;
  show_memory_breakpoints = show;

  return make_cleanup (restore_show_memory_breakpoints,
		       (void *) (uintptr_t) current);
}

static LONGEST
target_xfer_partial (struct target_ops *ops,
		     enum target_object object, const char *annex,
		     void *readbuf, const void *writebuf,
		     ULONGEST offset, LONGEST len)
{
  LONGEST retval;

  gdb_assert (ops->to_xfer_partial != NULL);

  /* If this is a memory transfer, let the memory-specific code
     have a look at it instead.  Memory transfers are more
     complicated.  */
  if (object == TARGET_OBJECT_MEMORY || object == TARGET_OBJECT_STACK_MEMORY)
    retval = memory_xfer_partial (ops, object, readbuf,
				  writebuf, offset, len);
  else
    {
      enum target_object raw_object = object;

      /* If this is a raw memory transfer, request the normal
	 memory object from other layers.  */
      if (raw_object == TARGET_OBJECT_RAW_MEMORY)
	raw_object = TARGET_OBJECT_MEMORY;

      retval = ops->to_xfer_partial (ops, raw_object, annex, readbuf,
				     writebuf, offset, len);
    }

  if (targetdebug)
    {
      const unsigned char *myaddr = NULL;

      fprintf_unfiltered (gdb_stdlog,
			  "%s:target_xfer_partial (%d, %s, %s, %s, %s, %s) = %s",
			  ops->to_shortname,
			  (int) object,
			  (annex ? annex : "(null)"),
			  host_address_to_string (readbuf),
			  host_address_to_string (writebuf),
			  core_addr_to_string_nz (offset),
			  plongest (len), plongest (retval));

      if (readbuf)
	myaddr = readbuf;
      if (writebuf)
	myaddr = writebuf;
      if (retval > 0 && myaddr != NULL)
	{
	  int i;

	  fputs_unfiltered (", bytes =", gdb_stdlog);
	  for (i = 0; i < retval; i++)
	    {
	      if ((((intptr_t) &(myaddr[i])) & 0xf) == 0)
		{
		  if (targetdebug < 2 && i > 0)
		    {
		      fprintf_unfiltered (gdb_stdlog, " ...");
		      break;
		    }
		  fprintf_unfiltered (gdb_stdlog, "\n");
		}

	      fprintf_unfiltered (gdb_stdlog, " %02x", myaddr[i] & 0xff);
	    }
	}

      fputc_unfiltered ('\n', gdb_stdlog);
    }
  return retval;
}

/* Read LEN bytes of target memory at address MEMADDR, placing the results in
   GDB's memory at MYADDR.  Returns either 0 for success or an errno value
   if any error occurs.

   If an error occurs, no guarantee is made about the contents of the data at
   MYADDR.  In particular, the caller should not depend upon partial reads
   filling the buffer with good data.  There is no way for the caller to know
   how much good data might have been transfered anyway.  Callers that can
   deal with partial reads should call target_read (which will retry until
   it makes no progress, and then return how much was transferred). */

int
target_read_memory (CORE_ADDR memaddr, gdb_byte *myaddr, int len)
{
  /* Dispatch to the topmost target, not the flattened current_target.
     Memory accesses check target->to_has_(all_)memory, and the
     flattened target doesn't inherit those.  */
  if (target_read (current_target.beneath, TARGET_OBJECT_MEMORY, NULL,
		   myaddr, memaddr, len) == len)
    return 0;
  else
    return EIO;
}

/* Like target_read_memory, but specify explicitly that this is a read from
   the target's stack.  This may trigger different cache behavior.  */

int
target_read_stack (CORE_ADDR memaddr, gdb_byte *myaddr, int len)
{
  /* Dispatch to the topmost target, not the flattened current_target.
     Memory accesses check target->to_has_(all_)memory, and the
     flattened target doesn't inherit those.  */

  if (target_read (current_target.beneath, TARGET_OBJECT_STACK_MEMORY, NULL,
		   myaddr, memaddr, len) == len)
    return 0;
  else
    return EIO;
}

int
target_write_memory (CORE_ADDR memaddr, const gdb_byte *myaddr, int len)
{
  /* Dispatch to the topmost target, not the flattened current_target.
     Memory accesses check target->to_has_(all_)memory, and the
     flattened target doesn't inherit those.  */
  if (target_write (current_target.beneath, TARGET_OBJECT_MEMORY, NULL,
		    myaddr, memaddr, len) == len)
    return 0;
  else
    return EIO;
}

/* Fetch the target's memory map.  */

VEC(mem_region_s) *
target_memory_map (void)
{
  VEC(mem_region_s) *result;
  struct mem_region *last_one, *this_one;
  int ix;
  struct target_ops *t;

  if (targetdebug)
    fprintf_unfiltered (gdb_stdlog, "target_memory_map ()\n");

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_memory_map != NULL)
      break;

  if (t == NULL)
    return NULL;

  result = t->to_memory_map (t);
  if (result == NULL)
    return NULL;

  qsort (VEC_address (mem_region_s, result),
	 VEC_length (mem_region_s, result),
	 sizeof (struct mem_region), mem_region_cmp);

  /* Check that regions do not overlap.  Simultaneously assign
     a numbering for the "mem" commands to use to refer to
     each region.  */
  last_one = NULL;
  for (ix = 0; VEC_iterate (mem_region_s, result, ix, this_one); ix++)
    {
      this_one->number = ix;

      if (last_one && last_one->hi > this_one->lo)
	{
	  warning (_("Overlapping regions in memory map: ignoring"));
	  VEC_free (mem_region_s, result);
	  return NULL;
	}
      last_one = this_one;
    }

  return result;
}

void
target_flash_erase (ULONGEST address, LONGEST length)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_flash_erase != NULL)
	{
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_flash_erase (%s, %s)\n",
                                hex_string (address), phex (length, 0));
	  t->to_flash_erase (t, address, length);
	  return;
	}

  tcomplain ();
}

void
target_flash_done (void)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_flash_done != NULL)
	{
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_flash_done\n");
	  t->to_flash_done (t);
	  return;
	}

  tcomplain ();
}

static void
show_trust_readonly (struct ui_file *file, int from_tty,
		     struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, _("\
Mode for reading from readonly sections is %s.\n"),
		    value);
}

/* More generic transfers.  */

static LONGEST
default_xfer_partial (struct target_ops *ops, enum target_object object,
		      const char *annex, gdb_byte *readbuf,
		      const gdb_byte *writebuf, ULONGEST offset, LONGEST len)
{
  if (object == TARGET_OBJECT_MEMORY
      && ops->deprecated_xfer_memory != NULL)
    /* If available, fall back to the target's
       "deprecated_xfer_memory" method.  */
    {
      int xfered = -1;
      errno = 0;
      if (writebuf != NULL)
	{
	  void *buffer = xmalloc (len);
	  struct cleanup *cleanup = make_cleanup (xfree, buffer);
	  memcpy (buffer, writebuf, len);
	  xfered = ops->deprecated_xfer_memory (offset, buffer, len,
						1/*write*/, NULL, ops);
	  do_cleanups (cleanup);
	}
      if (readbuf != NULL)
	xfered = ops->deprecated_xfer_memory (offset, readbuf, len, 
					      0/*read*/, NULL, ops);
      if (xfered > 0)
	return xfered;
      else if (xfered == 0 && errno == 0)
	/* "deprecated_xfer_memory" uses 0, cross checked against
           ERRNO as one indication of an error.  */
	return 0;
      else
	return -1;
    }
  else if (ops->beneath != NULL)
    return ops->beneath->to_xfer_partial (ops->beneath, object, annex,
					  readbuf, writebuf, offset, len);
  else
    return -1;
}

/* The xfer_partial handler for the topmost target.  Unlike the default,
   it does not need to handle memory specially; it just passes all
   requests down the stack.  */

static LONGEST
current_xfer_partial (struct target_ops *ops, enum target_object object,
		      const char *annex, gdb_byte *readbuf,
		      const gdb_byte *writebuf, ULONGEST offset, LONGEST len)
{
  if (ops->beneath != NULL)
    return ops->beneath->to_xfer_partial (ops->beneath, object, annex,
					  readbuf, writebuf, offset, len);
  else
    return -1;
}

/* Target vector read/write partial wrapper functions.

   NOTE: cagney/2003-10-21: I wonder if having "to_xfer_partial
   (inbuf, outbuf)", instead of separate read/write methods, make life
   easier.  */

static LONGEST
target_read_partial (struct target_ops *ops,
		     enum target_object object,
		     const char *annex, gdb_byte *buf,
		     ULONGEST offset, LONGEST len)
{
  return target_xfer_partial (ops, object, annex, buf, NULL, offset, len);
}

static LONGEST
target_write_partial (struct target_ops *ops,
		      enum target_object object,
		      const char *annex, const gdb_byte *buf,
		      ULONGEST offset, LONGEST len)
{
  return target_xfer_partial (ops, object, annex, NULL, buf, offset, len);
}

/* Wrappers to perform the full transfer.  */
LONGEST
target_read (struct target_ops *ops,
	     enum target_object object,
	     const char *annex, gdb_byte *buf,
	     ULONGEST offset, LONGEST len)
{
  LONGEST xfered = 0;
  while (xfered < len)
    {
      LONGEST xfer = target_read_partial (ops, object, annex,
					  (gdb_byte *) buf + xfered,
					  offset + xfered, len - xfered);
      /* Call an observer, notifying them of the xfer progress?  */
      if (xfer == 0)
	return xfered;
      if (xfer < 0)
	return -1;
      xfered += xfer;
      QUIT;
    }
  return len;
}

LONGEST
target_read_until_error (struct target_ops *ops,
			 enum target_object object,
			 const char *annex, gdb_byte *buf,
			 ULONGEST offset, LONGEST len)
{
  LONGEST xfered = 0;
  while (xfered < len)
    {
      LONGEST xfer = target_read_partial (ops, object, annex,
					  (gdb_byte *) buf + xfered,
					  offset + xfered, len - xfered);
      /* Call an observer, notifying them of the xfer progress?  */
      if (xfer == 0)
	return xfered;
      if (xfer < 0)
	{
	  /* We've got an error.  Try to read in smaller blocks.  */
	  ULONGEST start = offset + xfered;
	  ULONGEST remaining = len - xfered;
	  ULONGEST half;

	  /* If an attempt was made to read a random memory address,
	     it's likely that the very first byte is not accessible.
	     Try reading the first byte, to avoid doing log N tries
	     below.  */
	  xfer = target_read_partial (ops, object, annex, 
				      (gdb_byte *) buf + xfered, start, 1);
	  if (xfer <= 0)
	    return xfered;
	  start += 1;
	  remaining -= 1;
	  half = remaining/2;
	  
	  while (half > 0)
	    {
	      xfer = target_read_partial (ops, object, annex,
					  (gdb_byte *) buf + xfered,
					  start, half);
	      if (xfer == 0)
		return xfered;
	      if (xfer < 0)
		{
		  remaining = half;		  
		}
	      else
		{
		  /* We have successfully read the first half.  So, the
		     error must be in the second half.  Adjust start and
		     remaining to point at the second half.  */
		  xfered += xfer;
		  start += xfer;
		  remaining -= xfer;
		}
	      half = remaining/2;
	    }

	  return xfered;
	}
      xfered += xfer;
      QUIT;
    }
  return len;
}


/* An alternative to target_write with progress callbacks.  */

LONGEST
target_write_with_progress (struct target_ops *ops,
			    enum target_object object,
			    const char *annex, const gdb_byte *buf,
			    ULONGEST offset, LONGEST len,
			    void (*progress) (ULONGEST, void *), void *baton)
{
  LONGEST xfered = 0;

  /* Give the progress callback a chance to set up.  */
  if (progress)
    (*progress) (0, baton);

  while (xfered < len)
    {
      LONGEST xfer = target_write_partial (ops, object, annex,
					   (gdb_byte *) buf + xfered,
					   offset + xfered, len - xfered);

      if (xfer == 0)
	return xfered;
      if (xfer < 0)
	return -1;

      if (progress)
	(*progress) (xfer, baton);

      xfered += xfer;
      QUIT;
    }
  return len;
}

LONGEST
target_write (struct target_ops *ops,
	      enum target_object object,
	      const char *annex, const gdb_byte *buf,
	      ULONGEST offset, LONGEST len)
{
  return target_write_with_progress (ops, object, annex, buf, offset, len,
				     NULL, NULL);
}

/* Read OBJECT/ANNEX using OPS.  Store the result in *BUF_P and return
   the size of the transferred data.  PADDING additional bytes are
   available in *BUF_P.  This is a helper function for
   target_read_alloc; see the declaration of that function for more
   information.  */

static LONGEST
target_read_alloc_1 (struct target_ops *ops, enum target_object object,
		     const char *annex, gdb_byte **buf_p, int padding)
{
  size_t buf_alloc, buf_pos;
  gdb_byte *buf;
  LONGEST n;

  /* This function does not have a length parameter; it reads the
     entire OBJECT).  Also, it doesn't support objects fetched partly
     from one target and partly from another (in a different stratum,
     e.g. a core file and an executable).  Both reasons make it
     unsuitable for reading memory.  */
  gdb_assert (object != TARGET_OBJECT_MEMORY);

  /* Start by reading up to 4K at a time.  The target will throttle
     this number down if necessary.  */
  buf_alloc = 4096;
  buf = xmalloc (buf_alloc);
  buf_pos = 0;
  while (1)
    {
      n = target_read_partial (ops, object, annex, &buf[buf_pos],
			       buf_pos, buf_alloc - buf_pos - padding);
      if (n < 0)
	{
	  /* An error occurred.  */
	  xfree (buf);
	  return -1;
	}
      else if (n == 0)
	{
	  /* Read all there was.  */
	  if (buf_pos == 0)
	    xfree (buf);
	  else
	    *buf_p = buf;
	  return buf_pos;
	}

      buf_pos += n;

      /* If the buffer is filling up, expand it.  */
      if (buf_alloc < buf_pos * 2)
	{
	  buf_alloc *= 2;
	  buf = xrealloc (buf, buf_alloc);
	}

      QUIT;
    }
}

/* Read OBJECT/ANNEX using OPS.  Store the result in *BUF_P and return
   the size of the transferred data.  See the declaration in "target.h"
   function for more information about the return value.  */

LONGEST
target_read_alloc (struct target_ops *ops, enum target_object object,
		   const char *annex, gdb_byte **buf_p)
{
  return target_read_alloc_1 (ops, object, annex, buf_p, 0);
}

/* Read OBJECT/ANNEX using OPS.  The result is NUL-terminated and
   returned as a string, allocated using xmalloc.  If an error occurs
   or the transfer is unsupported, NULL is returned.  Empty objects
   are returned as allocated but empty strings.  A warning is issued
   if the result contains any embedded NUL bytes.  */

char *
target_read_stralloc (struct target_ops *ops, enum target_object object,
		      const char *annex)
{
  gdb_byte *buffer;
  LONGEST transferred;

  transferred = target_read_alloc_1 (ops, object, annex, &buffer, 1);

  if (transferred < 0)
    return NULL;

  if (transferred == 0)
    return xstrdup ("");

  buffer[transferred] = 0;
  if (strlen (buffer) < transferred)
    warning (_("target object %d, annex %s, "
	       "contained unexpected null characters"),
	     (int) object, annex ? annex : "(none)");

  return (char *) buffer;
}

/* Memory transfer methods.  */

void
get_target_memory (struct target_ops *ops, CORE_ADDR addr, gdb_byte *buf,
		   LONGEST len)
{
  /* This method is used to read from an alternate, non-current
     target.  This read must bypass the overlay support (as symbols
     don't match this target), and GDB's internal cache (wrong cache
     for this target).  */
  if (target_read (ops, TARGET_OBJECT_RAW_MEMORY, NULL, buf, addr, len)
      != len)
    memory_error (EIO, addr);
}

ULONGEST
get_target_memory_unsigned (struct target_ops *ops,
			    CORE_ADDR addr, int len, enum bfd_endian byte_order)
{
  gdb_byte buf[sizeof (ULONGEST)];

  gdb_assert (len <= sizeof (buf));
  get_target_memory (ops, addr, buf, len);
  return extract_unsigned_integer (buf, len, byte_order);
}

static void
target_info (char *args, int from_tty)
{
  struct target_ops *t;
  int has_all_mem = 0;

  if (symfile_objfile != NULL)
    printf_unfiltered (_("Symbols from \"%s\".\n"), symfile_objfile->name);

  for (t = target_stack; t != NULL; t = t->beneath)
    {
      if (!(*t->to_has_memory) (t))
	continue;

      if ((int) (t->to_stratum) <= (int) dummy_stratum)
	continue;
      if (has_all_mem)
	printf_unfiltered (_("\tWhile running this, GDB does not access memory from...\n"));
      printf_unfiltered ("%s:\n", t->to_longname);
      (t->to_files_info) (t);
      has_all_mem = (*t->to_has_all_memory) (t);
    }
}

/* This function is called before any new inferior is created, e.g.
   by running a program, attaching, or connecting to a target.
   It cleans up any state from previous invocations which might
   change between runs.  This is a subset of what target_preopen
   resets (things which might change between targets).  */

void
target_pre_inferior (int from_tty)
{
  /* Clear out solib state. Otherwise the solib state of the previous
     inferior might have survived and is entirely wrong for the new
     target.  This has been observed on GNU/Linux using glibc 2.3. How
     to reproduce:

     bash$ ./foo&
     [1] 4711
     bash$ ./foo&
     [1] 4712
     bash$ gdb ./foo
     [...]
     (gdb) attach 4711
     (gdb) detach
     (gdb) attach 4712
     Cannot access memory at address 0xdeadbeef
  */

  /* In some OSs, the shared library list is the same/global/shared
     across inferiors.  If code is shared between processes, so are
     memory regions and features.  */
  if (!gdbarch_has_global_solist (target_gdbarch))
    {
      no_shared_libraries (NULL, from_tty);

      invalidate_target_mem_regions ();

      target_clear_description ();
    }
}

/* Callback for iterate_over_inferiors.  Gets rid of the given
   inferior.  */

static int
dispose_inferior (struct inferior *inf, void *args)
{
  struct thread_info *thread;

  thread = any_thread_of_process (inf->pid);
  if (thread)
    {
      switch_to_thread (thread->ptid);

      /* Core inferiors actually should be detached, not killed.  */
      if (target_has_execution)
	target_kill ();
      else
	target_detach (NULL, 0);
    }

  return 0;
}

/* This is to be called by the open routine before it does
   anything.  */

void
target_preopen (int from_tty)
{
  dont_repeat ();

  if (have_inferiors ())
    {
      if (!from_tty
	  || !have_live_inferiors ()
	  || query (_("A program is being debugged already.  Kill it? ")))
	iterate_over_inferiors (dispose_inferior, NULL);
      else
	error (_("Program not killed."));
    }

  /* Calling target_kill may remove the target from the stack.  But if
     it doesn't (which seems like a win for UDI), remove it now.  */
  /* Leave the exec target, though.  The user may be switching from a
     live process to a core of the same program.  */
  pop_all_targets_above (file_stratum, 0);

  target_pre_inferior (from_tty);
}

/* Detach a target after doing deferred register stores.  */

void
target_detach (char *args, int from_tty)
{
  struct target_ops* t;
  
  if (gdbarch_has_global_breakpoints (target_gdbarch))
    /* Don't remove global breakpoints here.  They're removed on
       disconnection from the target.  */
    ;
  else
    /* If we're in breakpoints-always-inserted mode, have to remove
       them before detaching.  */
    remove_breakpoints ();

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_detach != NULL)
	{
	  t->to_detach (t, args, from_tty);
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_detach (%s, %d)\n",
				args, from_tty);
	  return;
	}
    }

  internal_error (__FILE__, __LINE__, "could not find a target to detach");
}

void
target_disconnect (char *args, int from_tty)
{
  struct target_ops *t;

  /* If we're in breakpoints-always-inserted mode or if breakpoints
     are global across processes, we have to remove them before
     disconnecting.  */
  remove_breakpoints ();

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_disconnect != NULL)
	{
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_disconnect (%s, %d)\n",
				args, from_tty);
	  t->to_disconnect (t, args, from_tty);
	  return;
	}

  tcomplain ();
}

ptid_t
target_wait (ptid_t ptid, struct target_waitstatus *status, int options)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_wait != NULL)
	{
	  ptid_t retval = (*t->to_wait) (t, ptid, status, options);

	  if (targetdebug)
	    {
	      char *status_string;

	      status_string = target_waitstatus_to_string (status);
	      fprintf_unfiltered (gdb_stdlog,
				  "target_wait (%d, status) = %d,   %s\n",
				  PIDGET (ptid), PIDGET (retval),
				  status_string);
	      xfree (status_string);
	    }

	  return retval;
	}
    }

  noprocess ();
}

char *
target_pid_to_str (ptid_t ptid)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_pid_to_str != NULL)
	return (*t->to_pid_to_str) (t, ptid);
    }

  return normal_pid_to_str (ptid);
}

void
target_resume (ptid_t ptid, int step, enum target_signal signal)
{
  struct target_ops *t;

  target_dcache_invalidate ();

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_resume != NULL)
	{
	  t->to_resume (t, ptid, step, signal);
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_resume (%d, %s, %s)\n",
				PIDGET (ptid),
				step ? "step" : "continue",
				target_signal_to_name (signal));

	  set_executing (ptid, 1);
	  set_running (ptid, 1);
	  clear_inline_frame_state (ptid);
	  return;
	}
    }

  noprocess ();
}
/* Look through the list of possible targets for a target that can
   follow forks.  */

int
target_follow_fork (int follow_child)
{
  struct target_ops *t;

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_follow_fork != NULL)
	{
	  int retval = t->to_follow_fork (t, follow_child);
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_follow_fork (%d) = %d\n",
				follow_child, retval);
	  return retval;
	}
    }

  /* Some target returned a fork event, but did not know how to follow it.  */
  internal_error (__FILE__, __LINE__,
		  "could not find a target to follow fork");
}

void
target_mourn_inferior (void)
{
  struct target_ops *t;
  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_mourn_inferior != NULL)	
	{
	  t->to_mourn_inferior (t);
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_mourn_inferior ()\n");

          /* We no longer need to keep handles on any of the object files.
             Make sure to release them to avoid unnecessarily locking any
             of them while we're not actually debugging.  */
          bfd_cache_close_all ();

	  return;
	}
    }

  internal_error (__FILE__, __LINE__,
		  "could not find a target to follow mourn inferiour");
}

/* Look for a target which can describe architectural features, starting
   from TARGET.  If we find one, return its description.  */

const struct target_desc *
target_read_description (struct target_ops *target)
{
  struct target_ops *t;

  for (t = target; t != NULL; t = t->beneath)
    if (t->to_read_description != NULL)
      {
	const struct target_desc *tdesc;

	tdesc = t->to_read_description (t);
	if (tdesc)
	  return tdesc;
      }

  return NULL;
}

/* The default implementation of to_search_memory.
   This implements a basic search of memory, reading target memory and
   performing the search here (as opposed to performing the search in on the
   target side with, for example, gdbserver).  */

int
simple_search_memory (struct target_ops *ops,
		      CORE_ADDR start_addr, ULONGEST search_space_len,
		      const gdb_byte *pattern, ULONGEST pattern_len,
		      CORE_ADDR *found_addrp)
{
  /* NOTE: also defined in find.c testcase.  */
#define SEARCH_CHUNK_SIZE 16000
  const unsigned chunk_size = SEARCH_CHUNK_SIZE;
  /* Buffer to hold memory contents for searching.  */
  gdb_byte *search_buf;
  unsigned search_buf_size;
  struct cleanup *old_cleanups;

  search_buf_size = chunk_size + pattern_len - 1;

  /* No point in trying to allocate a buffer larger than the search space.  */
  if (search_space_len < search_buf_size)
    search_buf_size = search_space_len;

  search_buf = malloc (search_buf_size);
  if (search_buf == NULL)
    error (_("Unable to allocate memory to perform the search."));
  old_cleanups = make_cleanup (free_current_contents, &search_buf);

  /* Prime the search buffer.  */

  if (target_read (ops, TARGET_OBJECT_MEMORY, NULL,
		   search_buf, start_addr, search_buf_size) != search_buf_size)
    {
      warning (_("Unable to access target memory at %s, halting search."),
	       hex_string (start_addr));
      do_cleanups (old_cleanups);
      return -1;
    }

  /* Perform the search.

     The loop is kept simple by allocating [N + pattern-length - 1] bytes.
     When we've scanned N bytes we copy the trailing bytes to the start and
     read in another N bytes.  */

  while (search_space_len >= pattern_len)
    {
      gdb_byte *found_ptr;
      unsigned nr_search_bytes = min (search_space_len, search_buf_size);

      found_ptr = memmem (search_buf, nr_search_bytes,
			  pattern, pattern_len);

      if (found_ptr != NULL)
	{
	  CORE_ADDR found_addr = start_addr + (found_ptr - search_buf);
	  *found_addrp = found_addr;
	  do_cleanups (old_cleanups);
	  return 1;
	}

      /* Not found in this chunk, skip to next chunk.  */

      /* Don't let search_space_len wrap here, it's unsigned.  */
      if (search_space_len >= chunk_size)
	search_space_len -= chunk_size;
      else
	search_space_len = 0;

      if (search_space_len >= pattern_len)
	{
	  unsigned keep_len = search_buf_size - chunk_size;
	  CORE_ADDR read_addr = start_addr + keep_len;
	  int nr_to_read;

	  /* Copy the trailing part of the previous iteration to the front
	     of the buffer for the next iteration.  */
	  gdb_assert (keep_len == pattern_len - 1);
	  memcpy (search_buf, search_buf + chunk_size, keep_len);

	  nr_to_read = min (search_space_len - keep_len, chunk_size);

	  if (target_read (ops, TARGET_OBJECT_MEMORY, NULL,
			   search_buf + keep_len, read_addr,
			   nr_to_read) != nr_to_read)
	    {
	      warning (_("Unable to access target memory at %s, halting search."),
		       hex_string (read_addr));
	      do_cleanups (old_cleanups);
	      return -1;
	    }

	  start_addr += chunk_size;
	}
    }

  /* Not found.  */

  do_cleanups (old_cleanups);
  return 0;
}

/* Search SEARCH_SPACE_LEN bytes beginning at START_ADDR for the
   sequence of bytes in PATTERN with length PATTERN_LEN.

   The result is 1 if found, 0 if not found, and -1 if there was an error
   requiring halting of the search (e.g. memory read error).
   If the pattern is found the address is recorded in FOUND_ADDRP.  */

int
target_search_memory (CORE_ADDR start_addr, ULONGEST search_space_len,
		      const gdb_byte *pattern, ULONGEST pattern_len,
		      CORE_ADDR *found_addrp)
{
  struct target_ops *t;
  int found;

  /* We don't use INHERIT to set current_target.to_search_memory,
     so we have to scan the target stack and handle targetdebug
     ourselves.  */

  if (targetdebug)
    fprintf_unfiltered (gdb_stdlog, "target_search_memory (%s, ...)\n",
			hex_string (start_addr));

  for (t = current_target.beneath; t != NULL; t = t->beneath)
    if (t->to_search_memory != NULL)
      break;

  if (t != NULL)
    {
      found = t->to_search_memory (t, start_addr, search_space_len,
				   pattern, pattern_len, found_addrp);
    }
  else
    {
      /* If a special version of to_search_memory isn't available, use the
	 simple version.  */
      found = simple_search_memory (current_target.beneath,
				    start_addr, search_space_len,
				    pattern, pattern_len, found_addrp);
    }

  if (targetdebug)
    fprintf_unfiltered (gdb_stdlog, "  = %d\n", found);

  return found;
}

/* Look through the currently pushed targets.  If none of them will
   be able to restart the currently running process, issue an error
   message.  */

void
target_require_runnable (void)
{
  struct target_ops *t;

  for (t = target_stack; t != NULL; t = t->beneath)
    {
      /* If this target knows how to create a new program, then
	 assume we will still be able to after killing the current
	 one.  Either killing and mourning will not pop T, or else
	 find_default_run_target will find it again.  */
      if (t->to_create_inferior != NULL)
	return;

      /* Do not worry about thread_stratum targets that can not
	 create inferiors.  Assume they will be pushed again if
	 necessary, and continue to the process_stratum.  */
      if (t->to_stratum == thread_stratum
	  || t->to_stratum == arch_stratum)
	continue;

      error (_("\
The \"%s\" target does not support \"run\".  Try \"help target\" or \"continue\"."),
	     t->to_shortname);
    }

  /* This function is only called if the target is running.  In that
     case there should have been a process_stratum target and it
     should either know how to create inferiors, or not... */
  internal_error (__FILE__, __LINE__, "No targets found");
}

/* Look through the list of possible targets for a target that can
   execute a run or attach command without any other data.  This is
   used to locate the default process stratum.

   If DO_MESG is not NULL, the result is always valid (error() is
   called for errors); else, return NULL on error.  */

static struct target_ops *
find_default_run_target (char *do_mesg)
{
  struct target_ops **t;
  struct target_ops *runable = NULL;
  int count;

  count = 0;

  for (t = target_structs; t < target_structs + target_struct_size;
       ++t)
    {
      if ((*t)->to_can_run && target_can_run (*t))
	{
	  runable = *t;
	  ++count;
	}
    }

  if (count != 1)
    {
      if (do_mesg)
	error (_("Don't know how to %s.  Try \"help target\"."), do_mesg);
      else
	return NULL;
    }

  return runable;
}

void
find_default_attach (struct target_ops *ops, char *args, int from_tty)
{
  struct target_ops *t;

  t = find_default_run_target ("attach");
  (t->to_attach) (t, args, from_tty);
  return;
}

void
find_default_create_inferior (struct target_ops *ops,
			      char *exec_file, char *allargs, char **env,
			      int from_tty)
{
  struct target_ops *t;

  t = find_default_run_target ("run");
  (t->to_create_inferior) (t, exec_file, allargs, env, from_tty);
  return;
}

static int
find_default_can_async_p (void)
{
  struct target_ops *t;

  /* This may be called before the target is pushed on the stack;
     look for the default process stratum.  If there's none, gdb isn't
     configured with a native debugger, and target remote isn't
     connected yet.  */
  t = find_default_run_target (NULL);
  if (t && t->to_can_async_p)
    return (t->to_can_async_p) ();
  return 0;
}

static int
find_default_is_async_p (void)
{
  struct target_ops *t;

  /* This may be called before the target is pushed on the stack;
     look for the default process stratum.  If there's none, gdb isn't
     configured with a native debugger, and target remote isn't
     connected yet.  */
  t = find_default_run_target (NULL);
  if (t && t->to_is_async_p)
    return (t->to_is_async_p) ();
  return 0;
}

static int
find_default_supports_non_stop (void)
{
  struct target_ops *t;

  t = find_default_run_target (NULL);
  if (t && t->to_supports_non_stop)
    return (t->to_supports_non_stop) ();
  return 0;
}

int
target_supports_non_stop (void)
{
  struct target_ops *t;
  for (t = &current_target; t != NULL; t = t->beneath)
    if (t->to_supports_non_stop)
      return t->to_supports_non_stop ();

  return 0;
}


char *
target_get_osdata (const char *type)
{
  char *document;
  struct target_ops *t;

  /* If we're already connected to something that can get us OS
     related data, use it.  Otherwise, try using the native
     target.  */
  if (current_target.to_stratum >= process_stratum)
    t = current_target.beneath;
  else
    t = find_default_run_target ("get OS data");

  if (!t)
    return NULL;

  return target_read_stralloc (t, TARGET_OBJECT_OSDATA, type);
}

static int
default_region_ok_for_hw_watchpoint (CORE_ADDR addr, int len)
{
  return (len <= gdbarch_ptr_bit (target_gdbarch) / TARGET_CHAR_BIT);
}

static int
default_watchpoint_addr_within_range (struct target_ops *target,
				      CORE_ADDR addr,
				      CORE_ADDR start, int length)
{
  return addr >= start && addr < start + length;
}

static struct gdbarch *
default_thread_architecture (struct target_ops *ops, ptid_t ptid)
{
  return target_gdbarch;
}

static int
return_zero (void)
{
  return 0;
}

static int
return_one (void)
{
  return 1;
}

static int
return_minus_one (void)
{
  return -1;
}

/* Find a single runnable target in the stack and return it.  If for
   some reason there is more than one, return NULL.  */

struct target_ops *
find_run_target (void)
{
  struct target_ops **t;
  struct target_ops *runable = NULL;
  int count;

  count = 0;

  for (t = target_structs; t < target_structs + target_struct_size; ++t)
    {
      if ((*t)->to_can_run && target_can_run (*t))
	{
	  runable = *t;
	  ++count;
	}
    }

  return (count == 1 ? runable : NULL);
}

/* Find a single core_stratum target in the list of targets and return it.
   If for some reason there is more than one, return NULL.  */

struct target_ops *
find_core_target (void)
{
  struct target_ops **t;
  struct target_ops *runable = NULL;
  int count;

  count = 0;

  for (t = target_structs; t < target_structs + target_struct_size;
       ++t)
    {
      if ((*t)->to_stratum == core_stratum)
	{
	  runable = *t;
	  ++count;
	}
    }

  return (count == 1 ? runable : NULL);
}

/*
 * Find the next target down the stack from the specified target.
 */

struct target_ops *
find_target_beneath (struct target_ops *t)
{
  return t->beneath;
}


/* The inferior process has died.  Long live the inferior!  */

void
generic_mourn_inferior (void)
{
  ptid_t ptid;

  ptid = inferior_ptid;
  inferior_ptid = null_ptid;

  if (!ptid_equal (ptid, null_ptid))
    {
      int pid = ptid_get_pid (ptid);
      delete_inferior (pid);
    }

  breakpoint_init_inferior (inf_exited);
  registers_changed ();

  reopen_exec_file ();
  reinit_frame_cache ();

  if (deprecated_detach_hook)
    deprecated_detach_hook ();
}

/* Helper function for child_wait and the derivatives of child_wait.
   HOSTSTATUS is the waitstatus from wait() or the equivalent; store our
   translation of that in OURSTATUS.  */
void
store_waitstatus (struct target_waitstatus *ourstatus, int hoststatus)
{
  if (WIFEXITED (hoststatus))
    {
      ourstatus->kind = TARGET_WAITKIND_EXITED;
      ourstatus->value.integer = WEXITSTATUS (hoststatus);
    }
  else if (!WIFSTOPPED (hoststatus))
    {
      ourstatus->kind = TARGET_WAITKIND_SIGNALLED;
      ourstatus->value.sig = target_signal_from_host (WTERMSIG (hoststatus));
    }
  else
    {
      ourstatus->kind = TARGET_WAITKIND_STOPPED;
      ourstatus->value.sig = target_signal_from_host (WSTOPSIG (hoststatus));
    }
}

/* Convert a normal process ID to a string.  Returns the string in a
   static buffer.  */

char *
normal_pid_to_str (ptid_t ptid)
{
  static char buf[32];

  xsnprintf (buf, sizeof buf, "process %d", ptid_get_pid (ptid));
  return buf;
}

static char *
dummy_pid_to_str (struct target_ops *ops, ptid_t ptid)
{
  return normal_pid_to_str (ptid);
}

/* Error-catcher for target_find_memory_regions */
static int dummy_find_memory_regions (int (*ignore1) (), void *ignore2)
{
  error (_("No target."));
  return 0;
}

/* Error-catcher for target_make_corefile_notes */
static char * dummy_make_corefile_notes (bfd *ignore1, int *ignore2)
{
  error (_("No target."));
  return NULL;
}

/* Set up the handful of non-empty slots needed by the dummy target
   vector.  */

static void
init_dummy_target (void)
{
  dummy_target.to_shortname = "None";
  dummy_target.to_longname = "None";
  dummy_target.to_doc = "";
  dummy_target.to_attach = find_default_attach;
  dummy_target.to_detach = 
    (void (*)(struct target_ops *, char *, int))target_ignore;
  dummy_target.to_create_inferior = find_default_create_inferior;
  dummy_target.to_can_async_p = find_default_can_async_p;
  dummy_target.to_is_async_p = find_default_is_async_p;
  dummy_target.to_supports_non_stop = find_default_supports_non_stop;
  dummy_target.to_pid_to_str = dummy_pid_to_str;
  dummy_target.to_stratum = dummy_stratum;
  dummy_target.to_find_memory_regions = dummy_find_memory_regions;
  dummy_target.to_make_corefile_notes = dummy_make_corefile_notes;
  dummy_target.to_xfer_partial = default_xfer_partial;
  dummy_target.to_has_all_memory = (int (*) (struct target_ops *)) return_zero;
  dummy_target.to_has_memory = (int (*) (struct target_ops *)) return_zero;
  dummy_target.to_has_stack = (int (*) (struct target_ops *)) return_zero;
  dummy_target.to_has_registers = (int (*) (struct target_ops *)) return_zero;
  dummy_target.to_has_execution = (int (*) (struct target_ops *)) return_zero;
  dummy_target.to_magic = OPS_MAGIC;
}

static void
debug_to_open (char *args, int from_tty)
{
  debug_target.to_open (args, from_tty);

  fprintf_unfiltered (gdb_stdlog, "target_open (%s, %d)\n", args, from_tty);
}

void
target_close (struct target_ops *targ, int quitting)
{
  if (targ->to_xclose != NULL)
    targ->to_xclose (targ, quitting);
  else if (targ->to_close != NULL)
    targ->to_close (quitting);

  if (targetdebug)
    fprintf_unfiltered (gdb_stdlog, "target_close (%d)\n", quitting);
}

void
target_attach (char *args, int from_tty)
{
  struct target_ops *t;
  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_attach != NULL)	
	{
	  t->to_attach (t, args, from_tty);
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_attach (%s, %d)\n",
				args, from_tty);
	  return;
	}
    }

  internal_error (__FILE__, __LINE__,
		  "could not find a target to attach");
}

int
target_thread_alive (ptid_t ptid)
{
  struct target_ops *t;
  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_thread_alive != NULL)
	{
	  int retval;

	  retval = t->to_thread_alive (t, ptid);
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_thread_alive (%d) = %d\n",
				PIDGET (ptid), retval);

	  return retval;
	}
    }

  return 0;
}

void
target_find_new_threads (void)
{
  struct target_ops *t;
  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_find_new_threads != NULL)
	{
	  t->to_find_new_threads (t);
	  if (targetdebug)
	    fprintf_unfiltered (gdb_stdlog, "target_find_new_threads ()\n");

	  return;
	}
    }
}

static void
debug_to_post_attach (int pid)
{
  debug_target.to_post_attach (pid);

  fprintf_unfiltered (gdb_stdlog, "target_post_attach (%d)\n", pid);
}

/* Return a pretty printed form of target_waitstatus.
   Space for the result is malloc'd, caller must free.  */

char *
target_waitstatus_to_string (const struct target_waitstatus *ws)
{
  const char *kind_str = "status->kind = ";

  switch (ws->kind)
    {
    case TARGET_WAITKIND_EXITED:
      return xstrprintf ("%sexited, status = %d",
			 kind_str, ws->value.integer);
    case TARGET_WAITKIND_STOPPED:
      return xstrprintf ("%sstopped, signal = %s",
			 kind_str, target_signal_to_name (ws->value.sig));
    case TARGET_WAITKIND_SIGNALLED:
      return xstrprintf ("%ssignalled, signal = %s",
			 kind_str, target_signal_to_name (ws->value.sig));
    case TARGET_WAITKIND_LOADED:
      return xstrprintf ("%sloaded", kind_str);
    case TARGET_WAITKIND_FORKED:
      return xstrprintf ("%sforked", kind_str);
    case TARGET_WAITKIND_VFORKED:
      return xstrprintf ("%svforked", kind_str);
    case TARGET_WAITKIND_EXECD:
      return xstrprintf ("%sexecd", kind_str);
    case TARGET_WAITKIND_SYSCALL_ENTRY:
      return xstrprintf ("%ssyscall-entry", kind_str);
    case TARGET_WAITKIND_SYSCALL_RETURN:
      return xstrprintf ("%ssyscall-return", kind_str);
    case TARGET_WAITKIND_SPURIOUS:
      return xstrprintf ("%sspurious", kind_str);
    case TARGET_WAITKIND_IGNORE:
      return xstrprintf ("%signore", kind_str);
    case TARGET_WAITKIND_NO_HISTORY:
      return xstrprintf ("%sno-history", kind_str);
    default:
      return xstrprintf ("%sunknown???", kind_str);
    }
}

static void
debug_print_register (const char * func,
		      struct regcache *regcache, int regno)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  fprintf_unfiltered (gdb_stdlog, "%s ", func);
  if (regno >= 0 && regno < gdbarch_num_regs (gdbarch)
      && gdbarch_register_name (gdbarch, regno) != NULL
      && gdbarch_register_name (gdbarch, regno)[0] != '\0')
    fprintf_unfiltered (gdb_stdlog, "(%s)",
			gdbarch_register_name (gdbarch, regno));
  else
    fprintf_unfiltered (gdb_stdlog, "(%d)", regno);
  if (regno >= 0 && regno < gdbarch_num_regs (gdbarch))
    {
      enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
      int i, size = register_size (gdbarch, regno);
      unsigned char buf[MAX_REGISTER_SIZE];
      regcache_raw_collect (regcache, regno, buf);
      fprintf_unfiltered (gdb_stdlog, " = ");
      for (i = 0; i < size; i++)
	{
	  fprintf_unfiltered (gdb_stdlog, "%02x", buf[i]);
	}
      if (size <= sizeof (LONGEST))
	{
	  ULONGEST val = extract_unsigned_integer (buf, size, byte_order);
	  fprintf_unfiltered (gdb_stdlog, " %s %s",
			      core_addr_to_string_nz (val), plongest (val));
	}
    }
  fprintf_unfiltered (gdb_stdlog, "\n");
}

void
target_fetch_registers (struct regcache *regcache, int regno)
{
  struct target_ops *t;
  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_fetch_registers != NULL)
	{
	  t->to_fetch_registers (t, regcache, regno);
	  if (targetdebug)
	    debug_print_register ("target_fetch_registers", regcache, regno);
	  return;
	}
    }
}

void
target_store_registers (struct regcache *regcache, int regno)
{

  struct target_ops *t;
  for (t = current_target.beneath; t != NULL; t = t->beneath)
    {
      if (t->to_store_registers != NULL)
	{
	  t->to_store_registers (t, regcache, regno);
	  if (targetdebug)
	    {
	      debug_print_register ("target_store_registers", regcache, regno);
	    }
	  return;
	}
    }

  noprocess ();
}

static void
debug_to_prepare_to_store (struct regcache *regcache)
{
  debug_target.to_prepare_to_store (regcache);

  fprintf_unfiltered (gdb_stdlog, "target_prepare_to_store ()\n");
}

static int
deprecated_debug_xfer_memory (CORE_ADDR memaddr, bfd_byte *myaddr, int len,
			      int write, struct mem_attrib *attrib,
			      struct target_ops *target)
{
  int retval;

  retval = debug_target.deprecated_xfer_memory (memaddr, myaddr, len, write,
						attrib, target);

  fprintf_unfiltered (gdb_stdlog,
		      "target_xfer_memory (%s, xxx, %d, %s, xxx) = %d",
		      paddress (target_gdbarch, memaddr), len,
		      write ? "write" : "read", retval);

  if (retval > 0)
    {
      int i;

      fputs_unfiltered (", bytes =", gdb_stdlog);
      for (i = 0; i < retval; i++)
	{
	  if ((((intptr_t) &(myaddr[i])) & 0xf) == 0)
	    {
	      if (targetdebug < 2 && i > 0)
		{
		  fprintf_unfiltered (gdb_stdlog, " ...");
		  break;
		}
	      fprintf_unfiltered (gdb_stdlog, "\n");
	    }

	  fprintf_unfiltered (gdb_stdlog, " %02x", myaddr[i] & 0xff);
	}
    }

  fputc_unfiltered ('\n', gdb_stdlog);

  return retval;
}

static void
debug_to_files_info (struct target_ops *target)
{
  debug_target.to_files_info (target);

  fprintf_unfiltered (gdb_stdlog, "target_files_info (xxx)\n");
}

static int
debug_to_insert_breakpoint (struct gdbarch *gdbarch,
			    struct bp_target_info *bp_tgt)
{
  int retval;

  retval = debug_target.to_insert_breakpoint (gdbarch, bp_tgt);

  fprintf_unfiltered (gdb_stdlog,
		      "target_insert_breakpoint (0x%lx, xxx) = %ld\n",
		      (unsigned long) bp_tgt->placed_address,
		      (unsigned long) retval);
  return retval;
}

static int
debug_to_remove_breakpoint (struct gdbarch *gdbarch,
			    struct bp_target_info *bp_tgt)
{
  int retval;

  retval = debug_target.to_remove_breakpoint (gdbarch, bp_tgt);

  fprintf_unfiltered (gdb_stdlog,
		      "target_remove_breakpoint (0x%lx, xxx) = %ld\n",
		      (unsigned long) bp_tgt->placed_address,
		      (unsigned long) retval);
  return retval;
}

static int
debug_to_can_use_hw_breakpoint (int type, int cnt, int from_tty)
{
  int retval;

  retval = debug_target.to_can_use_hw_breakpoint (type, cnt, from_tty);

  fprintf_unfiltered (gdb_stdlog,
		      "target_can_use_hw_breakpoint (%ld, %ld, %ld) = %ld\n",
		      (unsigned long) type,
		      (unsigned long) cnt,
		      (unsigned long) from_tty,
		      (unsigned long) retval);
  return retval;
}

static int
debug_to_region_ok_for_hw_watchpoint (CORE_ADDR addr, int len)
{
  CORE_ADDR retval;

  retval = debug_target.to_region_ok_for_hw_watchpoint (addr, len);

  fprintf_unfiltered (gdb_stdlog,
		      "target_region_ok_for_hw_watchpoint (%ld, %ld) = 0x%lx\n",
		      (unsigned long) addr,
		      (unsigned long) len,
		      (unsigned long) retval);
  return retval;
}

static int
debug_to_stopped_by_watchpoint (void)
{
  int retval;

  retval = debug_target.to_stopped_by_watchpoint ();

  fprintf_unfiltered (gdb_stdlog,
		      "target_stopped_by_watchpoint () = %ld\n",
		      (unsigned long) retval);
  return retval;
}

static int
debug_to_stopped_data_address (struct target_ops *target, CORE_ADDR *addr)
{
  int retval;

  retval = debug_target.to_stopped_data_address (target, addr);

  fprintf_unfiltered (gdb_stdlog,
		      "target_stopped_data_address ([0x%lx]) = %ld\n",
		      (unsigned long)*addr,
		      (unsigned long)retval);
  return retval;
}

static int
debug_to_watchpoint_addr_within_range (struct target_ops *target,
				       CORE_ADDR addr,
				       CORE_ADDR start, int length)
{
  int retval;

  retval = debug_target.to_watchpoint_addr_within_range (target, addr,
							 start, length);

  fprintf_filtered (gdb_stdlog,
		    "target_watchpoint_addr_within_range (0x%lx, 0x%lx, %d) = %d\n",
		    (unsigned long) addr, (unsigned long) start, length,
		    retval);
  return retval;
}

static int
debug_to_insert_hw_breakpoint (struct gdbarch *gdbarch,
			       struct bp_target_info *bp_tgt)
{
  int retval;

  retval = debug_target.to_insert_hw_breakpoint (gdbarch, bp_tgt);

  fprintf_unfiltered (gdb_stdlog,
		      "target_insert_hw_breakpoint (0x%lx, xxx) = %ld\n",
		      (unsigned long) bp_tgt->placed_address,
		      (unsigned long) retval);
  return retval;
}

static int
debug_to_remove_hw_breakpoint (struct gdbarch *gdbarch,
			       struct bp_target_info *bp_tgt)
{
  int retval;

  retval = debug_target.to_remove_hw_breakpoint (gdbarch, bp_tgt);

  fprintf_unfiltered (gdb_stdlog,
		      "target_remove_hw_breakpoint (0x%lx, xxx) = %ld\n",
		      (unsigned long) bp_tgt->placed_address,
		      (unsigned long) retval);
  return retval;
}

static int
debug_to_insert_watchpoint (CORE_ADDR addr, int len, int type)
{
  int retval;

  retval = debug_target.to_insert_watchpoint (addr, len, type);

  fprintf_unfiltered (gdb_stdlog,
		      "target_insert_watchpoint (0x%lx, %d, %d) = %ld\n",
		      (unsigned long) addr, len, type, (unsigned long) retval);
  return retval;
}

static int
debug_to_remove_watchpoint (CORE_ADDR addr, int len, int type)
{
  int retval;

  retval = debug_target.to_remove_watchpoint (addr, len, type);

  fprintf_unfiltered (gdb_stdlog,
		      "target_remove_watchpoint (0x%lx, %d, %d) = %ld\n",
		      (unsigned long) addr, len, type, (unsigned long) retval);
  return retval;
}

static void
debug_to_terminal_init (void)
{
  debug_target.to_terminal_init ();

  fprintf_unfiltered (gdb_stdlog, "target_terminal_init ()\n");
}

static void
debug_to_terminal_inferior (void)
{
  debug_target.to_terminal_inferior ();

  fprintf_unfiltered (gdb_stdlog, "target_terminal_inferior ()\n");
}

static void
debug_to_terminal_ours_for_output (void)
{
  debug_target.to_terminal_ours_for_output ();

  fprintf_unfiltered (gdb_stdlog, "target_terminal_ours_for_output ()\n");
}

static void
debug_to_terminal_ours (void)
{
  debug_target.to_terminal_ours ();

  fprintf_unfiltered (gdb_stdlog, "target_terminal_ours ()\n");
}

static void
debug_to_terminal_save_ours (void)
{
  debug_target.to_terminal_save_ours ();

  fprintf_unfiltered (gdb_stdlog, "target_terminal_save_ours ()\n");
}

static void
debug_to_terminal_info (char *arg, int from_tty)
{
  debug_target.to_terminal_info (arg, from_tty);

  fprintf_unfiltered (gdb_stdlog, "target_terminal_info (%s, %d)\n", arg,
		      from_tty);
}

static void
debug_to_load (char *args, int from_tty)
{
  debug_target.to_load (args, from_tty);

  fprintf_unfiltered (gdb_stdlog, "target_load (%s, %d)\n", args, from_tty);
}

static int
debug_to_lookup_symbol (char *name, CORE_ADDR *addrp)
{
  int retval;

  retval = debug_target.to_lookup_symbol (name, addrp);

  fprintf_unfiltered (gdb_stdlog, "target_lookup_symbol (%s, xxx)\n", name);

  return retval;
}

static void
debug_to_post_startup_inferior (ptid_t ptid)
{
  debug_target.to_post_startup_inferior (ptid);

  fprintf_unfiltered (gdb_stdlog, "target_post_startup_inferior (%d)\n",
		      PIDGET (ptid));
}

static void
debug_to_acknowledge_created_inferior (int pid)
{
  debug_target.to_acknowledge_created_inferior (pid);

  fprintf_unfiltered (gdb_stdlog, "target_acknowledge_created_inferior (%d)\n",
		      pid);
}

static void
debug_to_insert_fork_catchpoint (int pid)
{
  debug_target.to_insert_fork_catchpoint (pid);

  fprintf_unfiltered (gdb_stdlog, "target_insert_fork_catchpoint (%d)\n",
		      pid);
}

static int
debug_to_remove_fork_catchpoint (int pid)
{
  int retval;

  retval = debug_target.to_remove_fork_catchpoint (pid);

  fprintf_unfiltered (gdb_stdlog, "target_remove_fork_catchpoint (%d) = %d\n",
		      pid, retval);

  return retval;
}

static void
debug_to_insert_vfork_catchpoint (int pid)
{
  debug_target.to_insert_vfork_catchpoint (pid);

  fprintf_unfiltered (gdb_stdlog, "target_insert_vfork_catchpoint (%d)\n",
		      pid);
}

static int
debug_to_remove_vfork_catchpoint (int pid)
{
  int retval;

  retval = debug_target.to_remove_vfork_catchpoint (pid);

  fprintf_unfiltered (gdb_stdlog, "target_remove_vfork_catchpoint (%d) = %d\n",
		      pid, retval);

  return retval;
}

static void
debug_to_insert_exec_catchpoint (int pid)
{
  debug_target.to_insert_exec_catchpoint (pid);

  fprintf_unfiltered (gdb_stdlog, "target_insert_exec_catchpoint (%d)\n",
		      pid);
}

static int
debug_to_remove_exec_catchpoint (int pid)
{
  int retval;

  retval = debug_target.to_remove_exec_catchpoint (pid);

  fprintf_unfiltered (gdb_stdlog, "target_remove_exec_catchpoint (%d) = %d\n",
		      pid, retval);

  return retval;
}

static int
debug_to_has_exited (int pid, int wait_status, int *exit_status)
{
  int has_exited;

  has_exited = debug_target.to_has_exited (pid, wait_status, exit_status);

  fprintf_unfiltered (gdb_stdlog, "target_has_exited (%d, %d, %d) = %d\n",
		      pid, wait_status, *exit_status, has_exited);

  return has_exited;
}

static int
debug_to_can_run (void)
{
  int retval;

  retval = debug_target.to_can_run ();

  fprintf_unfiltered (gdb_stdlog, "target_can_run () = %d\n", retval);

  return retval;
}

static void
debug_to_notice_signals (ptid_t ptid)
{
  debug_target.to_notice_signals (ptid);

  fprintf_unfiltered (gdb_stdlog, "target_notice_signals (%d)\n",
                      PIDGET (ptid));
}

static struct gdbarch *
debug_to_thread_architecture (struct target_ops *ops, ptid_t ptid)
{
  struct gdbarch *retval;

  retval = debug_target.to_thread_architecture (ops, ptid);

  fprintf_unfiltered (gdb_stdlog, "target_thread_architecture (%s) = %p [%s]\n",
		      target_pid_to_str (ptid), retval,
		      gdbarch_bfd_arch_info (retval)->printable_name);
  return retval;
}

static void
debug_to_stop (ptid_t ptid)
{
  debug_target.to_stop (ptid);

  fprintf_unfiltered (gdb_stdlog, "target_stop (%s)\n",
		      target_pid_to_str (ptid));
}

static void
debug_to_rcmd (char *command,
	       struct ui_file *outbuf)
{
  debug_target.to_rcmd (command, outbuf);
  fprintf_unfiltered (gdb_stdlog, "target_rcmd (%s, ...)\n", command);
}

static char *
debug_to_pid_to_exec_file (int pid)
{
  char *exec_file;

  exec_file = debug_target.to_pid_to_exec_file (pid);

  fprintf_unfiltered (gdb_stdlog, "target_pid_to_exec_file (%d) = %s\n",
		      pid, exec_file);

  return exec_file;
}

static void
setup_target_debug (void)
{
  memcpy (&debug_target, &current_target, sizeof debug_target);

  current_target.to_open = debug_to_open;
  current_target.to_post_attach = debug_to_post_attach;
  current_target.to_prepare_to_store = debug_to_prepare_to_store;
  current_target.deprecated_xfer_memory = deprecated_debug_xfer_memory;
  current_target.to_files_info = debug_to_files_info;
  current_target.to_insert_breakpoint = debug_to_insert_breakpoint;
  current_target.to_remove_breakpoint = debug_to_remove_breakpoint;
  current_target.to_can_use_hw_breakpoint = debug_to_can_use_hw_breakpoint;
  current_target.to_insert_hw_breakpoint = debug_to_insert_hw_breakpoint;
  current_target.to_remove_hw_breakpoint = debug_to_remove_hw_breakpoint;
  current_target.to_insert_watchpoint = debug_to_insert_watchpoint;
  current_target.to_remove_watchpoint = debug_to_remove_watchpoint;
  current_target.to_stopped_by_watchpoint = debug_to_stopped_by_watchpoint;
  current_target.to_stopped_data_address = debug_to_stopped_data_address;
  current_target.to_watchpoint_addr_within_range = debug_to_watchpoint_addr_within_range;
  current_target.to_region_ok_for_hw_watchpoint = debug_to_region_ok_for_hw_watchpoint;
  current_target.to_terminal_init = debug_to_terminal_init;
  current_target.to_terminal_inferior = debug_to_terminal_inferior;
  current_target.to_terminal_ours_for_output = debug_to_terminal_ours_for_output;
  current_target.to_terminal_ours = debug_to_terminal_ours;
  current_target.to_terminal_save_ours = debug_to_terminal_save_ours;
  current_target.to_terminal_info = debug_to_terminal_info;
  current_target.to_load = debug_to_load;
  current_target.to_lookup_symbol = debug_to_lookup_symbol;
  current_target.to_post_startup_inferior = debug_to_post_startup_inferior;
  current_target.to_acknowledge_created_inferior = debug_to_acknowledge_created_inferior;
  current_target.to_insert_fork_catchpoint = debug_to_insert_fork_catchpoint;
  current_target.to_remove_fork_catchpoint = debug_to_remove_fork_catchpoint;
  current_target.to_insert_vfork_catchpoint = debug_to_insert_vfork_catchpoint;
  current_target.to_remove_vfork_catchpoint = debug_to_remove_vfork_catchpoint;
  current_target.to_insert_exec_catchpoint = debug_to_insert_exec_catchpoint;
  current_target.to_remove_exec_catchpoint = debug_to_remove_exec_catchpoint;
  current_target.to_has_exited = debug_to_has_exited;
  current_target.to_can_run = debug_to_can_run;
  current_target.to_notice_signals = debug_to_notice_signals;
  current_target.to_stop = debug_to_stop;
  current_target.to_rcmd = debug_to_rcmd;
  current_target.to_pid_to_exec_file = debug_to_pid_to_exec_file;
  current_target.to_thread_architecture = debug_to_thread_architecture;
}


static char targ_desc[] =
"Names of targets and files being debugged.\n\
Shows the entire stack of targets currently in use (including the exec-file,\n\
core-file, and process, if any), as well as the symbol file name.";

static void
do_monitor_command (char *cmd,
		 int from_tty)
{
  if ((current_target.to_rcmd
       == (void (*) (char *, struct ui_file *)) tcomplain)
      || (current_target.to_rcmd == debug_to_rcmd
	  && (debug_target.to_rcmd
	      == (void (*) (char *, struct ui_file *)) tcomplain)))
    error (_("\"monitor\" command not supported by this target."));
  target_rcmd (cmd, gdb_stdtarg);
}

/* Print the name of each layers of our target stack.  */

static void
maintenance_print_target_stack (char *cmd, int from_tty)
{
  struct target_ops *t;

  printf_filtered (_("The current target stack is:\n"));

  for (t = target_stack; t != NULL; t = t->beneath)
    {
      printf_filtered ("  - %s (%s)\n", t->to_shortname, t->to_longname);
    }
}

/* Controls if async mode is permitted.  */
int target_async_permitted = 0;

/* The set command writes to this variable.  If the inferior is
   executing, linux_nat_async_permitted is *not* updated.  */
static int target_async_permitted_1 = 0;

static void
set_maintenance_target_async_permitted (char *args, int from_tty,
					struct cmd_list_element *c)
{
  if (have_live_inferiors ())
    {
      target_async_permitted_1 = target_async_permitted;
      error (_("Cannot change this setting while the inferior is running."));
    }

  target_async_permitted = target_async_permitted_1;
}

static void
show_maintenance_target_async_permitted (struct ui_file *file, int from_tty,
					 struct cmd_list_element *c,
					 const char *value)
{
  fprintf_filtered (file, _("\
Controlling the inferior in asynchronous mode is %s.\n"), value);
}

void
initialize_targets (void)
{
  init_dummy_target ();
  push_target (&dummy_target);

  add_info ("target", target_info, targ_desc);
  add_info ("files", target_info, targ_desc);

  add_setshow_zinteger_cmd ("target", class_maintenance, &targetdebug, _("\
Set target debugging."), _("\
Show target debugging."), _("\
When non-zero, target debugging is enabled.  Higher numbers are more\n\
verbose.  Changes do not take effect until the next \"run\" or \"target\"\n\
command."),
			    NULL,
			    show_targetdebug,
			    &setdebuglist, &showdebuglist);

  add_setshow_boolean_cmd ("trust-readonly-sections", class_support,
			   &trust_readonly, _("\
Set mode for reading from readonly sections."), _("\
Show mode for reading from readonly sections."), _("\
When this mode is on, memory reads from readonly sections (such as .text)\n\
will be read from the object file instead of from the target.  This will\n\
result in significant performance improvement for remote targets."),
			   NULL,
			   show_trust_readonly,
			   &setlist, &showlist);

  add_com ("monitor", class_obscure, do_monitor_command,
	   _("Send a command to the remote monitor (remote targets only)."));

  add_cmd ("target-stack", class_maintenance, maintenance_print_target_stack,
           _("Print the name of each layer of the internal target stack."),
           &maintenanceprintlist);

  add_setshow_boolean_cmd ("target-async", no_class,
			   &target_async_permitted_1, _("\
Set whether gdb controls the inferior in asynchronous mode."), _("\
Show whether gdb controls the inferior in asynchronous mode."), _("\
Tells gdb whether to control the inferior in asynchronous mode."),
			   set_maintenance_target_async_permitted,
			   show_maintenance_target_async_permitted,
			   &setlist,
			   &showlist);

  add_setshow_boolean_cmd ("stack-cache", class_support,
			   &stack_cache_enabled_p_1, _("\
Set cache use for stack access."), _("\
Show cache use for stack access."), _("\
When on, use the data cache for all stack access, regardless of any\n\
configured memory regions.  This improves remote performance significantly.\n\
By default, caching for stack access is on."),
			   set_stack_cache_enabled_p,
			   show_stack_cache_enabled_p,
			   &setlist, &showlist);

  target_dcache = dcache_init ();
}
