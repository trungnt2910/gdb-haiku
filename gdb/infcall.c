/* Perform an inferior function call, for GDB, the GNU debugger.

   Copyright (C) 1986-2019 Free Software Foundation, Inc.

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
#include "infcall.h"
#include "breakpoint.h"
#include "tracepoint.h"
#include "target.h"
#include "regcache.h"
#include "inferior.h"
#include "infrun.h"
#include "block.h"
#include "gdbcore.h"
#include "language.h"
#include "objfiles.h"
#include "gdbcmd.h"
#include "command.h"
#include "dummy-frame.h"
#include "ada-lang.h"
#include "f-lang.h"
#include "gdbthread.h"
#include "event-top.h"
#include "observable.h"
#include "top.h"
#include "interps.h"
#include "thread-fsm.h"
#include <algorithm>
#include "common/scope-exit.h"

/* If we can't find a function's name from its address,
   we print this instead.  */
#define RAW_FUNCTION_ADDRESS_FORMAT "at 0x%s"
#define RAW_FUNCTION_ADDRESS_SIZE (sizeof (RAW_FUNCTION_ADDRESS_FORMAT) \
                                   + 2 * sizeof (CORE_ADDR))

/* NOTE: cagney/2003-04-16: What's the future of this code?

   GDB needs an asynchronous expression evaluator, that means an
   asynchronous inferior function call implementation, and that in
   turn means restructuring the code so that it is event driven.  */

/* How you should pass arguments to a function depends on whether it
   was defined in K&R style or prototype style.  If you define a
   function using the K&R syntax that takes a `float' argument, then
   callers must pass that argument as a `double'.  If you define the
   function using the prototype syntax, then you must pass the
   argument as a `float', with no promotion.

   Unfortunately, on certain older platforms, the debug info doesn't
   indicate reliably how each function was defined.  A function type's
   TYPE_PROTOTYPED flag may be clear, even if the function was defined
   in prototype style.  When calling a function whose TYPE_PROTOTYPED
   flag is clear, GDB consults this flag to decide what to do.

   For modern targets, it is proper to assume that, if the prototype
   flag is clear, that can be trusted: `float' arguments should be
   promoted to `double'.  For some older targets, if the prototype
   flag is clear, that doesn't tell us anything.  The default is to
   trust the debug information; the user can override this behavior
   with "set coerce-float-to-double 0".  */

static int coerce_float_to_double_p = 1;
static void
show_coerce_float_to_double_p (struct ui_file *file, int from_tty,
			       struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file,
		    _("Coercion of floats to doubles "
		      "when calling functions is %s.\n"),
		    value);
}

/* This boolean tells what gdb should do if a signal is received while
   in a function called from gdb (call dummy).  If set, gdb unwinds
   the stack and restore the context to what as it was before the
   call.

   The default is to stop in the frame where the signal was received.  */

static int unwind_on_signal_p = 0;
static void
show_unwind_on_signal_p (struct ui_file *file, int from_tty,
			 struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file,
		    _("Unwinding of stack if a signal is "
		      "received while in a call dummy is %s.\n"),
		    value);
}

/* This boolean tells what gdb should do if a std::terminate call is
   made while in a function called from gdb (call dummy).
   As the confines of a single dummy stack prohibit out-of-frame
   handlers from handling a raised exception, and as out-of-frame
   handlers are common in C++, this can lead to no handler being found
   by the unwinder, and a std::terminate call.  This is a false positive.
   If set, gdb unwinds the stack and restores the context to what it
   was before the call.

   The default is to unwind the frame if a std::terminate call is
   made.  */

static int unwind_on_terminating_exception_p = 1;

static void
show_unwind_on_terminating_exception_p (struct ui_file *file, int from_tty,
					struct cmd_list_element *c,
					const char *value)

{
  fprintf_filtered (file,
		    _("Unwind stack if a C++ exception is "
		      "unhandled while in a call dummy is %s.\n"),
		    value);
}

/* Perform the standard coercions that are specified
   for arguments to be passed to C, Ada or Fortran functions.

   If PARAM_TYPE is non-NULL, it is the expected parameter type.
   IS_PROTOTYPED is non-zero if the function declaration is prototyped.
   SP is the stack pointer were additional data can be pushed (updating
   its value as needed).  */

static struct value *
value_arg_coerce (struct gdbarch *gdbarch, struct value *arg,
		  struct type *param_type, int is_prototyped, CORE_ADDR *sp)
{
  const struct builtin_type *builtin = builtin_type (gdbarch);
  struct type *arg_type = check_typedef (value_type (arg));
  struct type *type
    = param_type ? check_typedef (param_type) : arg_type;

  /* Perform any Ada- and Fortran-specific coercion first.  */
  if (current_language->la_language == language_ada)
    arg = ada_convert_actual (arg, type);
  else if (current_language->la_language == language_fortran)
    type = fortran_preserve_arg_pointer (arg, type);

  /* Force the value to the target if we will need its address.  At
     this point, we could allocate arguments on the stack instead of
     calling malloc if we knew that their addresses would not be
     saved by the called function.  */
  arg = value_coerce_to_target (arg);

  switch (TYPE_CODE (type))
    {
    case TYPE_CODE_REF:
    case TYPE_CODE_RVALUE_REF:
      {
	struct value *new_value;

	if (TYPE_IS_REFERENCE (arg_type))
	  return value_cast_pointers (type, arg, 0);

	/* Cast the value to the reference's target type, and then
	   convert it back to a reference.  This will issue an error
	   if the value was not previously in memory - in some cases
	   we should clearly be allowing this, but how?  */
	new_value = value_cast (TYPE_TARGET_TYPE (type), arg);
	new_value = value_ref (new_value, TYPE_CODE (type));
	return new_value;
      }
    case TYPE_CODE_INT:
    case TYPE_CODE_CHAR:
    case TYPE_CODE_BOOL:
    case TYPE_CODE_ENUM:
      /* If we don't have a prototype, coerce to integer type if necessary.  */
      if (!is_prototyped)
	{
	  if (TYPE_LENGTH (type) < TYPE_LENGTH (builtin->builtin_int))
	    type = builtin->builtin_int;
	}
      /* Currently all target ABIs require at least the width of an integer
         type for an argument.  We may have to conditionalize the following
         type coercion for future targets.  */
      if (TYPE_LENGTH (type) < TYPE_LENGTH (builtin->builtin_int))
	type = builtin->builtin_int;
      break;
    case TYPE_CODE_FLT:
      if (!is_prototyped && coerce_float_to_double_p)
	{
	  if (TYPE_LENGTH (type) < TYPE_LENGTH (builtin->builtin_double))
	    type = builtin->builtin_double;
	  else if (TYPE_LENGTH (type) > TYPE_LENGTH (builtin->builtin_double))
	    type = builtin->builtin_long_double;
	}
      break;
    case TYPE_CODE_FUNC:
      type = lookup_pointer_type (type);
      break;
    case TYPE_CODE_ARRAY:
      /* Arrays are coerced to pointers to their first element, unless
         they are vectors, in which case we want to leave them alone,
         because they are passed by value.  */
      if (current_language->c_style_arrays)
	if (!TYPE_VECTOR (type))
	  type = lookup_pointer_type (TYPE_TARGET_TYPE (type));
      break;
    case TYPE_CODE_UNDEF:
    case TYPE_CODE_PTR:
    case TYPE_CODE_STRUCT:
    case TYPE_CODE_UNION:
    case TYPE_CODE_VOID:
    case TYPE_CODE_SET:
    case TYPE_CODE_RANGE:
    case TYPE_CODE_STRING:
    case TYPE_CODE_ERROR:
    case TYPE_CODE_MEMBERPTR:
    case TYPE_CODE_METHODPTR:
    case TYPE_CODE_METHOD:
    case TYPE_CODE_COMPLEX:
    default:
      break;
    }

  return value_cast (type, arg);
}

/* See infcall.h.  */

CORE_ADDR
find_function_addr (struct value *function,
		    struct type **retval_type,
		    struct type **function_type)
{
  struct type *ftype = check_typedef (value_type (function));
  struct gdbarch *gdbarch = get_type_arch (ftype);
  struct type *value_type = NULL;
  /* Initialize it just to avoid a GCC false warning.  */
  CORE_ADDR funaddr = 0;

  /* If it's a member function, just look at the function
     part of it.  */

  /* Determine address to call.  */
  if (TYPE_CODE (ftype) == TYPE_CODE_FUNC
      || TYPE_CODE (ftype) == TYPE_CODE_METHOD)
    funaddr = value_address (function);
  else if (TYPE_CODE (ftype) == TYPE_CODE_PTR)
    {
      funaddr = value_as_address (function);
      ftype = check_typedef (TYPE_TARGET_TYPE (ftype));
      if (TYPE_CODE (ftype) == TYPE_CODE_FUNC
	  || TYPE_CODE (ftype) == TYPE_CODE_METHOD)
	funaddr = gdbarch_convert_from_func_ptr_addr (gdbarch, funaddr,
						      current_top_target ());
    }
  if (TYPE_CODE (ftype) == TYPE_CODE_FUNC
      || TYPE_CODE (ftype) == TYPE_CODE_METHOD)
    {
      if (TYPE_GNU_IFUNC (ftype))
	{
	  CORE_ADDR resolver_addr = funaddr;

	  /* Resolve the ifunc.  Note this may call the resolver
	     function in the inferior.  */
	  funaddr = gnu_ifunc_resolve_addr (gdbarch, resolver_addr);

	  /* Skip querying the function symbol if no RETVAL_TYPE or
	     FUNCTION_TYPE have been asked for.  */
	  if (retval_type != NULL || function_type != NULL)
	    {
	      type *target_ftype = find_function_type (funaddr);
	      /* If we don't have debug info for the target function,
		 see if we can instead extract the target function's
		 type from the type that the resolver returns.  */
	      if (target_ftype == NULL)
		target_ftype = find_gnu_ifunc_target_type (resolver_addr);
	      if (target_ftype != NULL)
		{
		  value_type = TYPE_TARGET_TYPE (check_typedef (target_ftype));
		  ftype = target_ftype;
		}
	    }
	}
      else
	value_type = TYPE_TARGET_TYPE (ftype);
    }
  else if (TYPE_CODE (ftype) == TYPE_CODE_INT)
    {
      /* Handle the case of functions lacking debugging info.
         Their values are characters since their addresses are char.  */
      if (TYPE_LENGTH (ftype) == 1)
	funaddr = value_as_address (value_addr (function));
      else
	{
	  /* Handle function descriptors lacking debug info.  */
	  int found_descriptor = 0;

	  funaddr = 0;	/* pacify "gcc -Werror" */
	  if (VALUE_LVAL (function) == lval_memory)
	    {
	      CORE_ADDR nfunaddr;

	      funaddr = value_as_address (value_addr (function));
	      nfunaddr = funaddr;
	      funaddr
		= gdbarch_convert_from_func_ptr_addr (gdbarch, funaddr,
						      current_top_target ());
	      if (funaddr != nfunaddr)
		found_descriptor = 1;
	    }
	  if (!found_descriptor)
	    /* Handle integer used as address of a function.  */
	    funaddr = (CORE_ADDR) value_as_long (function);
	}
    }
  else
    error (_("Invalid data type for function to be called."));

  if (retval_type != NULL)
    *retval_type = value_type;
  if (function_type != NULL)
    *function_type = ftype;
  return funaddr + gdbarch_deprecated_function_start_offset (gdbarch);
}

/* For CALL_DUMMY_ON_STACK, push a breakpoint sequence that the called
   function returns to.  */

static CORE_ADDR
push_dummy_code (struct gdbarch *gdbarch,
		 CORE_ADDR sp, CORE_ADDR funaddr,
		 gdb::array_view<value *> args,
		 struct type *value_type,
		 CORE_ADDR *real_pc, CORE_ADDR *bp_addr,
		 struct regcache *regcache)
{
  gdb_assert (gdbarch_push_dummy_code_p (gdbarch));

  return gdbarch_push_dummy_code (gdbarch, sp, funaddr,
				  args.data (), args.size (),
				  value_type, real_pc, bp_addr,
				  regcache);
}

/* See infcall.h.  */

void
error_call_unknown_return_type (const char *func_name)
{
  if (func_name != NULL)
    error (_("'%s' has unknown return type; "
	     "cast the call to its declared return type"),
	   func_name);
  else
    error (_("function has unknown return type; "
	     "cast the call to its declared return type"));
}

/* Fetch the name of the function at FUNADDR.
   This is used in printing an error message for call_function_by_hand.
   BUF is used to print FUNADDR in hex if the function name cannot be
   determined.  It must be large enough to hold formatted result of
   RAW_FUNCTION_ADDRESS_FORMAT.  */

static const char *
get_function_name (CORE_ADDR funaddr, char *buf, int buf_size)
{
  {
    struct symbol *symbol = find_pc_function (funaddr);

    if (symbol)
      return SYMBOL_PRINT_NAME (symbol);
  }

  {
    /* Try the minimal symbols.  */
    struct bound_minimal_symbol msymbol = lookup_minimal_symbol_by_pc (funaddr);

    if (msymbol.minsym)
      return MSYMBOL_PRINT_NAME (msymbol.minsym);
  }

  {
    std::string tmp = string_printf (_(RAW_FUNCTION_ADDRESS_FORMAT),
				     hex_string (funaddr));

    gdb_assert (tmp.length () + 1 <= buf_size);
    return strcpy (buf, tmp.c_str ());
  }
}

/* All the meta data necessary to extract the call's return value.  */

struct call_return_meta_info
{
  /* The caller frame's architecture.  */
  struct gdbarch *gdbarch;

  /* The called function.  */
  struct value *function;

  /* The return value's type.  */
  struct type *value_type;

  /* Are we returning a value using a structure return or a normal
     value return?  */
  int struct_return_p;

  /* If using a structure return, this is the structure's address.  */
  CORE_ADDR struct_addr;
};

/* Extract the called function's return value.  */

static struct value *
get_call_return_value (struct call_return_meta_info *ri)
{
  struct value *retval = NULL;
  thread_info *thr = inferior_thread ();
  bool stack_temporaries = thread_stack_temporaries_enabled_p (thr);

  if (TYPE_CODE (ri->value_type) == TYPE_CODE_VOID)
    retval = allocate_value (ri->value_type);
  else if (ri->struct_return_p)
    {
      if (stack_temporaries)
	{
	  retval = value_from_contents_and_address (ri->value_type, NULL,
						    ri->struct_addr);
	  push_thread_stack_temporary (thr, retval);
	}
      else
	{
	  retval = allocate_value (ri->value_type);
	  read_value_memory (retval, 0, 1, ri->struct_addr,
			     value_contents_raw (retval),
			     TYPE_LENGTH (ri->value_type));
	}
    }
  else
    {
      retval = allocate_value (ri->value_type);
      gdbarch_return_value (ri->gdbarch, ri->function, ri->value_type,
			    get_current_regcache (),
			    value_contents_raw (retval), NULL);
      if (stack_temporaries && class_or_union_p (ri->value_type))
	{
	  /* Values of class type returned in registers are copied onto
	     the stack and their lval_type set to lval_memory.  This is
	     required because further evaluation of the expression
	     could potentially invoke methods on the return value
	     requiring GDB to evaluate the "this" pointer.  To evaluate
	     the this pointer, GDB needs the memory address of the
	     value.  */
	  value_force_lval (retval, ri->struct_addr);
	  push_thread_stack_temporary (thr, retval);
	}
    }

  gdb_assert (retval != NULL);
  return retval;
}

/* Data for the FSM that manages an infcall.  It's main job is to
   record the called function's return value.  */

struct call_thread_fsm : public thread_fsm
{
  /* All the info necessary to be able to extract the return
     value.  */
  struct call_return_meta_info return_meta_info;

  /* The called function's return value.  This is extracted from the
     target before the dummy frame is popped.  */
  struct value *return_value = nullptr;

  /* The top level that started the infcall (and is synchronously
     waiting for it to end).  */
  struct ui *waiting_ui;

  call_thread_fsm (struct ui *waiting_ui, struct interp *cmd_interp,
		   struct gdbarch *gdbarch, struct value *function,
		   struct type *value_type,
		   int struct_return_p, CORE_ADDR struct_addr);

  bool should_stop (struct thread_info *thread) override;

  bool should_notify_stop () override;
};

/* Allocate a new call_thread_fsm object.  */

call_thread_fsm::call_thread_fsm (struct ui *waiting_ui,
				  struct interp *cmd_interp,
				  struct gdbarch *gdbarch,
				  struct value *function,
				  struct type *value_type,
				  int struct_return_p, CORE_ADDR struct_addr)
  : thread_fsm (cmd_interp),
    waiting_ui (waiting_ui)
{
  return_meta_info.gdbarch = gdbarch;
  return_meta_info.function = function;
  return_meta_info.value_type = value_type;
  return_meta_info.struct_return_p = struct_return_p;
  return_meta_info.struct_addr = struct_addr;
}

/* Implementation of should_stop method for infcalls.  */

bool
call_thread_fsm::should_stop (struct thread_info *thread)
{
  if (stop_stack_dummy == STOP_STACK_DUMMY)
    {
      /* Done.  */
      set_finished ();

      /* Stash the return value before the dummy frame is popped and
	 registers are restored to what they were before the
	 call..  */
      return_value = get_call_return_value (&return_meta_info);

      /* Break out of wait_sync_command_done.  */
      scoped_restore save_ui = make_scoped_restore (&current_ui, waiting_ui);
      target_terminal::ours ();
      waiting_ui->prompt_state = PROMPT_NEEDED;
    }

  return true;
}

/* Implementation of should_notify_stop method for infcalls.  */

bool
call_thread_fsm::should_notify_stop ()
{
  if (finished_p ())
    {
      /* Infcall succeeded.  Be silent and proceed with evaluating the
	 expression.  */
      return false;
    }

  /* Something wrong happened.  E.g., an unexpected breakpoint
     triggered, or a signal was intercepted.  Notify the stop.  */
  return true;
}

/* Subroutine of call_function_by_hand to simplify it.
   Start up the inferior and wait for it to stop.
   Return the exception if there's an error, or an exception with
   reason >= 0 if there's no error.

   This is done inside a TRY_CATCH so the caller needn't worry about
   thrown errors.  The caller should rethrow if there's an error.  */

static struct gdb_exception
run_inferior_call (struct call_thread_fsm *sm,
		   struct thread_info *call_thread, CORE_ADDR real_pc)
{
  struct gdb_exception caught_error = exception_none;
  int saved_in_infcall = call_thread->control.in_infcall;
  ptid_t call_thread_ptid = call_thread->ptid;
  enum prompt_state saved_prompt_state = current_ui->prompt_state;
  int was_running = call_thread->state == THREAD_RUNNING;
  int saved_ui_async = current_ui->async;

  /* Infcalls run synchronously, in the foreground.  */
  current_ui->prompt_state = PROMPT_BLOCKED;
  /* So that we don't print the prompt prematurely in
     fetch_inferior_event.  */
  current_ui->async = 0;

  delete_file_handler (current_ui->input_fd);

  call_thread->control.in_infcall = 1;

  clear_proceed_status (0);

  /* Associate the FSM with the thread after clear_proceed_status
     (otherwise it'd clear this FSM), and before anything throws, so
     we don't leak it (and any resources it manages).  */
  call_thread->thread_fsm = sm;

  disable_watchpoints_before_interactive_call_start ();

  /* We want to print return value, please...  */
  call_thread->control.proceed_to_finish = 1;

  TRY
    {
      proceed (real_pc, GDB_SIGNAL_0);

      /* Inferior function calls are always synchronous, even if the
	 target supports asynchronous execution.  */
      wait_sync_command_done ();
    }
  CATCH (e, RETURN_MASK_ALL)
    {
      caught_error = e;
    }
  END_CATCH

  /* If GDB has the prompt blocked before, then ensure that it remains
     so.  normal_stop calls async_enable_stdin, so reset the prompt
     state again here.  In other cases, stdin will be re-enabled by
     inferior_event_handler, when an exception is thrown.  */
  current_ui->prompt_state = saved_prompt_state;
  if (current_ui->prompt_state == PROMPT_BLOCKED)
    delete_file_handler (current_ui->input_fd);
  else
    ui_register_input_event_handler (current_ui);
  current_ui->async = saved_ui_async;

  /* If the infcall does NOT succeed, normal_stop will have already
     finished the thread states.  However, on success, normal_stop
     defers here, so that we can set back the thread states to what
     they were before the call.  Note that we must also finish the
     state of new threads that might have spawned while the call was
     running.  The main cases to handle are:

     - "(gdb) print foo ()", or any other command that evaluates an
     expression at the prompt.  (The thread was marked stopped before.)

     - "(gdb) break foo if return_false()" or similar cases where we
     do an infcall while handling an event (while the thread is still
     marked running).  In this example, whether the condition
     evaluates true and thus we'll present a user-visible stop is
     decided elsewhere.  */
  if (!was_running
      && call_thread_ptid == inferior_ptid
      && stop_stack_dummy == STOP_STACK_DUMMY)
    finish_thread_state (user_visible_resume_ptid (0));

  enable_watchpoints_after_interactive_call_stop ();

  /* Call breakpoint_auto_delete on the current contents of the bpstat
     of inferior call thread.
     If all error()s out of proceed ended up calling normal_stop
     (and perhaps they should; it already does in the special case
     of error out of resume()), then we wouldn't need this.  */
  if (caught_error.reason < 0)
    {
      if (call_thread->state != THREAD_EXITED)
	breakpoint_auto_delete (call_thread->control.stop_bpstat);
    }

  call_thread->control.in_infcall = saved_in_infcall;

  return caught_error;
}

/* See infcall.h.  */

struct value *
call_function_by_hand (struct value *function,
		       type *default_return_type,
		       gdb::array_view<value *> args)
{
  return call_function_by_hand_dummy (function, default_return_type,
				      args, NULL, NULL);
}

/* All this stuff with a dummy frame may seem unnecessarily complicated
   (why not just save registers in GDB?).  The purpose of pushing a dummy
   frame which looks just like a real frame is so that if you call a
   function and then hit a breakpoint (get a signal, etc), "backtrace"
   will look right.  Whether the backtrace needs to actually show the
   stack at the time the inferior function was called is debatable, but
   it certainly needs to not display garbage.  So if you are contemplating
   making dummy frames be different from normal frames, consider that.  */

/* Perform a function call in the inferior.
   ARGS is a vector of values of arguments (NARGS of them).
   FUNCTION is a value, the function to be called.
   Returns a value representing what the function returned.
   May fail to return, if a breakpoint or signal is hit
   during the execution of the function.

   ARGS is modified to contain coerced values.  */

struct value *
call_function_by_hand_dummy (struct value *function,
			     type *default_return_type,
			     gdb::array_view<value *> args,
			     dummy_frame_dtor_ftype *dummy_dtor,
			     void *dummy_dtor_data)
{
  CORE_ADDR sp;
  struct type *target_values_type;
  function_call_return_method return_method = return_method_normal;
  CORE_ADDR struct_addr = 0;
  CORE_ADDR real_pc;
  CORE_ADDR bp_addr;
  struct frame_id dummy_id;
  struct frame_info *frame;
  struct gdbarch *gdbarch;
  ptid_t call_thread_ptid;
  struct gdb_exception e;
  char name_buf[RAW_FUNCTION_ADDRESS_SIZE];

  if (!target_has_execution)
    noprocess ();

  if (get_traceframe_number () >= 0)
    error (_("May not call functions while looking at trace frames."));

  if (execution_direction == EXEC_REVERSE)
    error (_("Cannot call functions in reverse mode."));

  /* We're going to run the target, and inspect the thread's state
     afterwards.  Hold a strong reference so that the pointer remains
     valid even if the thread exits.  */
  thread_info_ref call_thread
    = thread_info_ref::new_reference (inferior_thread ());

  bool stack_temporaries = thread_stack_temporaries_enabled_p (call_thread.get ());

  frame = get_current_frame ();
  gdbarch = get_frame_arch (frame);

  if (!gdbarch_push_dummy_call_p (gdbarch))
    error (_("This target does not support function calls."));

  /* A holder for the inferior status.
     This is only needed while we're preparing the inferior function call.  */
  infcall_control_state_up inf_status (save_infcall_control_state ());

  /* Save the caller's registers and other state associated with the
     inferior itself so that they can be restored once the
     callee returns.  To allow nested calls the registers are (further
     down) pushed onto a dummy frame stack.  This unique pointer
     is released once the regcache has been pushed).  */
  infcall_suspend_state_up caller_state (save_infcall_suspend_state ());

  /* Ensure that the initial SP is correctly aligned.  */
  {
    CORE_ADDR old_sp = get_frame_sp (frame);

    if (gdbarch_frame_align_p (gdbarch))
      {
	sp = gdbarch_frame_align (gdbarch, old_sp);
	/* NOTE: cagney/2003-08-13: Skip the "red zone".  For some
	   ABIs, a function can use memory beyond the inner most stack
	   address.  AMD64 called that region the "red zone".  Skip at
	   least the "red zone" size before allocating any space on
	   the stack.  */
	if (gdbarch_inner_than (gdbarch, 1, 2))
	  sp -= gdbarch_frame_red_zone_size (gdbarch);
	else
	  sp += gdbarch_frame_red_zone_size (gdbarch);
	/* Still aligned?  */
	gdb_assert (sp == gdbarch_frame_align (gdbarch, sp));
	/* NOTE: cagney/2002-09-18:
	   
	   On a RISC architecture, a void parameterless generic dummy
	   frame (i.e., no parameters, no result) typically does not
	   need to push anything the stack and hence can leave SP and
	   FP.  Similarly, a frameless (possibly leaf) function does
	   not push anything on the stack and, hence, that too can
	   leave FP and SP unchanged.  As a consequence, a sequence of
	   void parameterless generic dummy frame calls to frameless
	   functions will create a sequence of effectively identical
	   frames (SP, FP and TOS and PC the same).  This, not
	   suprisingly, results in what appears to be a stack in an
	   infinite loop --- when GDB tries to find a generic dummy
	   frame on the internal dummy frame stack, it will always
	   find the first one.

	   To avoid this problem, the code below always grows the
	   stack.  That way, two dummy frames can never be identical.
	   It does burn a few bytes of stack but that is a small price
	   to pay :-).  */
	if (sp == old_sp)
	  {
	    if (gdbarch_inner_than (gdbarch, 1, 2))
	      /* Stack grows down.  */
	      sp = gdbarch_frame_align (gdbarch, old_sp - 1);
	    else
	      /* Stack grows up.  */
	      sp = gdbarch_frame_align (gdbarch, old_sp + 1);
	  }
	/* SP may have underflown address zero here from OLD_SP.  Memory access
	   functions will probably fail in such case but that is a target's
	   problem.  */
      }
    else
      /* FIXME: cagney/2002-09-18: Hey, you loose!

	 Who knows how badly aligned the SP is!

	 If the generic dummy frame ends up empty (because nothing is
	 pushed) GDB won't be able to correctly perform back traces.
	 If a target is having trouble with backtraces, first thing to
	 do is add FRAME_ALIGN() to the architecture vector.  If that
	 fails, try dummy_id().

         If the ABI specifies a "Red Zone" (see the doco) the code
         below will quietly trash it.  */
      sp = old_sp;

    /* Skip over the stack temporaries that might have been generated during
       the evaluation of an expression.  */
    if (stack_temporaries)
      {
	struct value *lastval;

	lastval = get_last_thread_stack_temporary (call_thread.get ());
        if (lastval != NULL)
	  {
	    CORE_ADDR lastval_addr = value_address (lastval);

	    if (gdbarch_inner_than (gdbarch, 1, 2))
	      {
		gdb_assert (sp >= lastval_addr);
		sp = lastval_addr;
	      }
	    else
	      {
		gdb_assert (sp <= lastval_addr);
		sp = lastval_addr + TYPE_LENGTH (value_type (lastval));
	      }

	    if (gdbarch_frame_align_p (gdbarch))
	      sp = gdbarch_frame_align (gdbarch, sp);
	  }
      }
  }

  type *ftype;
  type *values_type;
  CORE_ADDR funaddr = find_function_addr (function, &values_type, &ftype);

  if (values_type == NULL)
    values_type = default_return_type;
  if (values_type == NULL)
    {
      const char *name = get_function_name (funaddr,
					    name_buf, sizeof (name_buf));
      error (_("'%s' has unknown return type; "
	       "cast the call to its declared return type"),
	     name);
    }

  values_type = check_typedef (values_type);

  /* Are we returning a value using a structure return?  */

  if (gdbarch_return_in_first_hidden_param_p (gdbarch, values_type))
    {
      return_method = return_method_hidden_param;

      /* Tell the target specific argument pushing routine not to
	 expect a value.  */
      target_values_type = builtin_type (gdbarch)->builtin_void;
    }
  else
    {
      if (using_struct_return (gdbarch, function, values_type))
	return_method = return_method_struct;
      target_values_type = values_type;
    }

  gdb::observers::inferior_call_pre.notify (inferior_ptid, funaddr);

  /* Determine the location of the breakpoint (and possibly other
     stuff) that the called function will return to.  The SPARC, for a
     function returning a structure or union, needs to make space for
     not just the breakpoint but also an extra word containing the
     size (?) of the structure being passed.  */

  switch (gdbarch_call_dummy_location (gdbarch))
    {
    case ON_STACK:
      {
	const gdb_byte *bp_bytes;
	CORE_ADDR bp_addr_as_address;
	int bp_size;

	/* Be careful BP_ADDR is in inferior PC encoding while
	   BP_ADDR_AS_ADDRESS is a plain memory address.  */

	sp = push_dummy_code (gdbarch, sp, funaddr, args,
			      target_values_type, &real_pc, &bp_addr,
			      get_current_regcache ());

	/* Write a legitimate instruction at the point where the infcall
	   breakpoint is going to be inserted.  While this instruction
	   is never going to be executed, a user investigating the
	   memory from GDB would see this instruction instead of random
	   uninitialized bytes.  We chose the breakpoint instruction
	   as it may look as the most logical one to the user and also
	   valgrind 3.7.0 needs it for proper vgdb inferior calls.

	   If software breakpoints are unsupported for this target we
	   leave the user visible memory content uninitialized.  */

	bp_addr_as_address = bp_addr;
	bp_bytes = gdbarch_breakpoint_from_pc (gdbarch, &bp_addr_as_address,
					       &bp_size);
	if (bp_bytes != NULL)
	  write_memory (bp_addr_as_address, bp_bytes, bp_size);
      }
      break;
    case AT_ENTRY_POINT:
      {
	CORE_ADDR dummy_addr;

	real_pc = funaddr;
	dummy_addr = entry_point_address ();

	/* A call dummy always consists of just a single breakpoint, so
	   its address is the same as the address of the dummy.

	   The actual breakpoint is inserted separatly so there is no need to
	   write that out.  */
	bp_addr = dummy_addr;
	break;
      }
    default:
      internal_error (__FILE__, __LINE__, _("bad switch"));
    }

  if (args.size () < TYPE_NFIELDS (ftype))
    error (_("Too few arguments in function call."));

  for (int i = args.size () - 1; i >= 0; i--)
    {
      int prototyped;
      struct type *param_type;

      /* FIXME drow/2002-05-31: Should just always mark methods as
	 prototyped.  Can we respect TYPE_VARARGS?  Probably not.  */
      if (TYPE_CODE (ftype) == TYPE_CODE_METHOD)
	prototyped = 1;
      if (TYPE_TARGET_TYPE (ftype) == NULL && TYPE_NFIELDS (ftype) == 0
	  && default_return_type != NULL)
	{
	  /* Calling a no-debug function with the return type
	     explicitly cast.  Assume the function is prototyped,
	     with a prototype matching the types of the arguments.
	     E.g., with:
	     float mult (float v1, float v2) { return v1 * v2; }
	     This:
	     (gdb) p (float) mult (2.0f, 3.0f)
	     Is a simpler alternative to:
	     (gdb) p ((float (*) (float, float)) mult) (2.0f, 3.0f)
	  */
	  prototyped = 1;
	}
      else if (i < TYPE_NFIELDS (ftype))
	prototyped = TYPE_PROTOTYPED (ftype);
      else
	prototyped = 0;

      if (i < TYPE_NFIELDS (ftype))
	param_type = TYPE_FIELD_TYPE (ftype, i);
      else
	param_type = NULL;

      args[i] = value_arg_coerce (gdbarch, args[i],
				  param_type, prototyped, &sp);

      if (param_type != NULL && language_pass_by_reference (param_type))
	args[i] = value_addr (args[i]);
    }

  /* Reserve space for the return structure to be written on the
     stack, if necessary.  Make certain that the value is correctly
     aligned.

     While evaluating expressions, we reserve space on the stack for
     return values of class type even if the language ABI and the target
     ABI do not require that the return value be passed as a hidden first
     argument.  This is because we want to store the return value as an
     on-stack temporary while the expression is being evaluated.  This
     enables us to have chained function calls in expressions.

     Keeping the return values as on-stack temporaries while the expression
     is being evaluated is OK because the thread is stopped until the
     expression is completely evaluated.  */

  if (return_method != return_method_normal
      || (stack_temporaries && class_or_union_p (values_type)))
    {
      if (gdbarch_inner_than (gdbarch, 1, 2))
	{
	  /* Stack grows downward.  Align STRUCT_ADDR and SP after
             making space for the return value.  */
	  sp -= TYPE_LENGTH (values_type);
	  if (gdbarch_frame_align_p (gdbarch))
	    sp = gdbarch_frame_align (gdbarch, sp);
	  struct_addr = sp;
	}
      else
	{
	  /* Stack grows upward.  Align the frame, allocate space, and
             then again, re-align the frame???  */
	  if (gdbarch_frame_align_p (gdbarch))
	    sp = gdbarch_frame_align (gdbarch, sp);
	  struct_addr = sp;
	  sp += TYPE_LENGTH (values_type);
	  if (gdbarch_frame_align_p (gdbarch))
	    sp = gdbarch_frame_align (gdbarch, sp);
	}
    }

  std::vector<struct value *> new_args;
  if (return_method == return_method_hidden_param)
    {
      /* Add the new argument to the front of the argument list.  */
      new_args.reserve (args.size ());
      new_args.push_back
	(value_from_pointer (lookup_pointer_type (values_type), struct_addr));
      new_args.insert (new_args.end (), args.begin (), args.end ());
      args = new_args;
    }

  /* Create the dummy stack frame.  Pass in the call dummy address as,
     presumably, the ABI code knows where, in the call dummy, the
     return address should be pointed.  */
  sp = gdbarch_push_dummy_call (gdbarch, function, get_current_regcache (),
				bp_addr, args.size (), args.data (),
				sp, return_method, struct_addr);

  /* Set up a frame ID for the dummy frame so we can pass it to
     set_momentary_breakpoint.  We need to give the breakpoint a frame
     ID so that the breakpoint code can correctly re-identify the
     dummy breakpoint.  */
  /* Sanity.  The exact same SP value is returned by PUSH_DUMMY_CALL,
     saved as the dummy-frame TOS, and used by dummy_id to form
     the frame ID's stack address.  */
  dummy_id = frame_id_build (sp, bp_addr);

  /* Create a momentary breakpoint at the return address of the
     inferior.  That way it breaks when it returns.  */

  {
    symtab_and_line sal;
    sal.pspace = current_program_space;
    sal.pc = bp_addr;
    sal.section = find_pc_overlay (sal.pc);

    /* Sanity.  The exact same SP value is returned by
       PUSH_DUMMY_CALL, saved as the dummy-frame TOS, and used by
       dummy_id to form the frame ID's stack address.  */
    breakpoint *bpt
      = set_momentary_breakpoint (gdbarch, sal,
				  dummy_id, bp_call_dummy).release ();

    /* set_momentary_breakpoint invalidates FRAME.  */
    frame = NULL;

    bpt->disposition = disp_del;
    gdb_assert (bpt->related_breakpoint == bpt);

    breakpoint *longjmp_b = set_longjmp_breakpoint_for_call_dummy ();
    if (longjmp_b)
      {
	/* Link BPT into the chain of LONGJMP_B.  */
	bpt->related_breakpoint = longjmp_b;
	while (longjmp_b->related_breakpoint != bpt->related_breakpoint)
	  longjmp_b = longjmp_b->related_breakpoint;
	longjmp_b->related_breakpoint = bpt;
      }
  }

  /* Create a breakpoint in std::terminate.
     If a C++ exception is raised in the dummy-frame, and the
     exception handler is (normally, and expected to be) out-of-frame,
     the default C++ handler will (wrongly) be called in an inferior
     function call.  This is wrong, as an exception can be  normally
     and legally handled out-of-frame.  The confines of the dummy frame
     prevent the unwinder from finding the correct handler (or any
     handler, unless it is in-frame).  The default handler calls
     std::terminate.  This will kill the inferior.  Assert that
     terminate should never be called in an inferior function
     call.  Place a momentary breakpoint in the std::terminate function
     and if triggered in the call, rewind.  */
  if (unwind_on_terminating_exception_p)
    set_std_terminate_breakpoint ();

  /* Everything's ready, push all the info needed to restore the
     caller (and identify the dummy-frame) onto the dummy-frame
     stack.  */
  dummy_frame_push (caller_state.release (), &dummy_id, call_thread.get ());
  if (dummy_dtor != NULL)
    register_dummy_frame_dtor (dummy_id, call_thread.get (),
			       dummy_dtor, dummy_dtor_data);

  /* Register a clean-up for unwind_on_terminating_exception_breakpoint.  */
  SCOPE_EXIT { delete_std_terminate_breakpoint (); };

  /* - SNIP - SNIP - SNIP - SNIP - SNIP - SNIP - SNIP - SNIP - SNIP -
     If you're looking to implement asynchronous dummy-frames, then
     just below is the place to chop this function in two..  */

  {
    struct thread_fsm *saved_sm;
    struct call_thread_fsm *sm;

    /* Save the current FSM.  We'll override it.  */
    saved_sm = call_thread->thread_fsm;
    call_thread->thread_fsm = NULL;

    /* Save this thread's ptid, we need it later but the thread
       may have exited.  */
    call_thread_ptid = call_thread->ptid;

    /* Run the inferior until it stops.  */

    /* Create the FSM used to manage the infcall.  It tells infrun to
       not report the stop to the user, and captures the return value
       before the dummy frame is popped.  run_inferior_call registers
       it with the thread ASAP.  */
    sm = new call_thread_fsm (current_ui, command_interp (),
			      gdbarch, function,
			      values_type,
			      return_method != return_method_normal,
			      struct_addr);

    e = run_inferior_call (sm, call_thread.get (), real_pc);

    gdb::observers::inferior_call_post.notify (call_thread_ptid, funaddr);

    if (call_thread->state != THREAD_EXITED)
      {
	/* The FSM should still be the same.  */
	gdb_assert (call_thread->thread_fsm == sm);

	if (call_thread->thread_fsm->finished_p ())
	  {
	    struct value *retval;

	    /* The inferior call is successful.  Pop the dummy frame,
	       which runs its destructors and restores the inferior's
	       suspend state, and restore the inferior control
	       state.  */
	    dummy_frame_pop (dummy_id, call_thread.get ());
	    restore_infcall_control_state (inf_status.release ());

	    /* Get the return value.  */
	    retval = sm->return_value;

	    /* Clean up / destroy the call FSM, and restore the
	       original one.  */
	    call_thread->thread_fsm->clean_up (call_thread.get ());
	    delete call_thread->thread_fsm;
	    call_thread->thread_fsm = saved_sm;

	    maybe_remove_breakpoints ();

	    gdb_assert (retval != NULL);
	    return retval;
	  }

	/* Didn't complete.  Clean up / destroy the call FSM, and restore the
	   previous state machine, and handle the error.  */
	call_thread->thread_fsm->clean_up (call_thread.get ());
	delete call_thread->thread_fsm;
	call_thread->thread_fsm = saved_sm;
      }
  }

  /* Rethrow an error if we got one trying to run the inferior.  */

  if (e.reason < 0)
    {
      const char *name = get_function_name (funaddr,
                                            name_buf, sizeof (name_buf));

      discard_infcall_control_state (inf_status.release ());

      /* We could discard the dummy frame here if the program exited,
         but it will get garbage collected the next time the program is
         run anyway.  */

      switch (e.reason)
	{
	case RETURN_ERROR:
	  throw_error (e.error, _("%s\n\
An error occurred while in a function called from GDB.\n\
Evaluation of the expression containing the function\n\
(%s) will be abandoned.\n\
When the function is done executing, GDB will silently stop."),
		       e.what (), name);
	case RETURN_QUIT:
	default:
	  throw_exception (e);
	}
    }

  /* If the program has exited, or we stopped at a different thread,
     exit and inform the user.  */

  if (! target_has_execution)
    {
      const char *name = get_function_name (funaddr,
					    name_buf, sizeof (name_buf));

      /* If we try to restore the inferior status,
	 we'll crash as the inferior is no longer running.  */
      discard_infcall_control_state (inf_status.release ());

      /* We could discard the dummy frame here given that the program exited,
         but it will get garbage collected the next time the program is
         run anyway.  */

      error (_("The program being debugged exited while in a function "
	       "called from GDB.\n"
	       "Evaluation of the expression containing the function\n"
	       "(%s) will be abandoned."),
	     name);
    }

  if (call_thread_ptid != inferior_ptid)
    {
      const char *name = get_function_name (funaddr,
					    name_buf, sizeof (name_buf));

      /* We've switched threads.  This can happen if another thread gets a
	 signal or breakpoint while our thread was running.
	 There's no point in restoring the inferior status,
	 we're in a different thread.  */
      discard_infcall_control_state (inf_status.release ());
      /* Keep the dummy frame record, if the user switches back to the
	 thread with the hand-call, we'll need it.  */
      if (stopped_by_random_signal)
	error (_("\
The program received a signal in another thread while\n\
making a function call from GDB.\n\
Evaluation of the expression containing the function\n\
(%s) will be abandoned.\n\
When the function is done executing, GDB will silently stop."),
	       name);
      else
	error (_("\
The program stopped in another thread while making a function call from GDB.\n\
Evaluation of the expression containing the function\n\
(%s) will be abandoned.\n\
When the function is done executing, GDB will silently stop."),
	       name);
    }

    {
      /* Make a copy as NAME may be in an objfile freed by dummy_frame_pop.  */
      std::string name = get_function_name (funaddr, name_buf,
					    sizeof (name_buf));

      if (stopped_by_random_signal)
	{
	  /* We stopped inside the FUNCTION because of a random
	     signal.  Further execution of the FUNCTION is not
	     allowed.  */

	  if (unwind_on_signal_p)
	    {
	      /* The user wants the context restored.  */

	      /* We must get back to the frame we were before the
		 dummy call.  */
	      dummy_frame_pop (dummy_id, call_thread.get ());

	      /* We also need to restore inferior status to that before the
		 dummy call.  */
	      restore_infcall_control_state (inf_status.release ());

	      /* FIXME: Insert a bunch of wrap_here; name can be very
		 long if it's a C++ name with arguments and stuff.  */
	      error (_("\
The program being debugged was signaled while in a function called from GDB.\n\
GDB has restored the context to what it was before the call.\n\
To change this behavior use \"set unwindonsignal off\".\n\
Evaluation of the expression containing the function\n\
(%s) will be abandoned."),
		     name.c_str ());
	    }
	  else
	    {
	      /* The user wants to stay in the frame where we stopped
		 (default).
		 Discard inferior status, we're not at the same point
		 we started at.  */
	      discard_infcall_control_state (inf_status.release ());

	      /* FIXME: Insert a bunch of wrap_here; name can be very
		 long if it's a C++ name with arguments and stuff.  */
	      error (_("\
The program being debugged was signaled while in a function called from GDB.\n\
GDB remains in the frame where the signal was received.\n\
To change this behavior use \"set unwindonsignal on\".\n\
Evaluation of the expression containing the function\n\
(%s) will be abandoned.\n\
When the function is done executing, GDB will silently stop."),
		     name.c_str ());
	    }
	}

      if (stop_stack_dummy == STOP_STD_TERMINATE)
	{
	  /* We must get back to the frame we were before the dummy
	     call.  */
	  dummy_frame_pop (dummy_id, call_thread.get ());

	  /* We also need to restore inferior status to that before
	     the dummy call.  */
	  restore_infcall_control_state (inf_status.release ());

	  error (_("\
The program being debugged entered a std::terminate call, most likely\n\
caused by an unhandled C++ exception.  GDB blocked this call in order\n\
to prevent the program from being terminated, and has restored the\n\
context to its original state before the call.\n\
To change this behaviour use \"set unwind-on-terminating-exception off\".\n\
Evaluation of the expression containing the function (%s)\n\
will be abandoned."),
		 name.c_str ());
	}
      else if (stop_stack_dummy == STOP_NONE)
	{

	  /* We hit a breakpoint inside the FUNCTION.
	     Keep the dummy frame, the user may want to examine its state.
	     Discard inferior status, we're not at the same point
	     we started at.  */
	  discard_infcall_control_state (inf_status.release ());

	  /* The following error message used to say "The expression
	     which contained the function call has been discarded."
	     It is a hard concept to explain in a few words.  Ideally,
	     GDB would be able to resume evaluation of the expression
	     when the function finally is done executing.  Perhaps
	     someday this will be implemented (it would not be easy).  */
	  /* FIXME: Insert a bunch of wrap_here; name can be very long if it's
	     a C++ name with arguments and stuff.  */
	  error (_("\
The program being debugged stopped while in a function called from GDB.\n\
Evaluation of the expression containing the function\n\
(%s) will be abandoned.\n\
When the function is done executing, GDB will silently stop."),
		 name.c_str ());
	}

    }

  /* The above code errors out, so ...  */
  gdb_assert_not_reached ("... should not be here");
}

void
_initialize_infcall (void)
{
  add_setshow_boolean_cmd ("coerce-float-to-double", class_obscure,
			   &coerce_float_to_double_p, _("\
Set coercion of floats to doubles when calling functions."), _("\
Show coercion of floats to doubles when calling functions"), _("\
Variables of type float should generally be converted to doubles before\n\
calling an unprototyped function, and left alone when calling a prototyped\n\
function.  However, some older debug info formats do not provide enough\n\
information to determine that a function is prototyped.  If this flag is\n\
set, GDB will perform the conversion for a function it considers\n\
unprototyped.\n\
The default is to perform the conversion.\n"),
			   NULL,
			   show_coerce_float_to_double_p,
			   &setlist, &showlist);

  add_setshow_boolean_cmd ("unwindonsignal", no_class,
			   &unwind_on_signal_p, _("\
Set unwinding of stack if a signal is received while in a call dummy."), _("\
Show unwinding of stack if a signal is received while in a call dummy."), _("\
The unwindonsignal lets the user determine what gdb should do if a signal\n\
is received while in a function called from gdb (call dummy).  If set, gdb\n\
unwinds the stack and restore the context to what as it was before the call.\n\
The default is to stop in the frame where the signal was received."),
			   NULL,
			   show_unwind_on_signal_p,
			   &setlist, &showlist);

  add_setshow_boolean_cmd ("unwind-on-terminating-exception", no_class,
			   &unwind_on_terminating_exception_p, _("\
Set unwinding of stack if std::terminate is called while in call dummy."), _("\
Show unwinding of stack if std::terminate() is called while in a call dummy."),
			   _("\
The unwind on terminating exception flag lets the user determine\n\
what gdb should do if a std::terminate() call is made from the\n\
default exception handler.  If set, gdb unwinds the stack and restores\n\
the context to what it was before the call.  If unset, gdb allows the\n\
std::terminate call to proceed.\n\
The default is to unwind the frame."),
			   NULL,
			   show_unwind_on_terminating_exception_p,
			   &setlist, &showlist);

}
