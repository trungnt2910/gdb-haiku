/* Exception (throw catch) mechanism, for GDB, the GNU debugger.

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

#ifndef COMMON_COMMON_EXCEPTIONS_H
#define COMMON_COMMON_EXCEPTIONS_H

#include <setjmp.h>
#include <new>
#include <memory>

/* Reasons for calling throw_exceptions().  NOTE: all reason values
   must be different from zero.  enum value 0 is reserved for internal
   use as the return value from an initial setjmp().  */

enum return_reason
  {
    /* User interrupt.  */
    RETURN_QUIT = -2,
    /* Any other error.  */
    RETURN_ERROR
  };

#define RETURN_MASK(reason)	(1 << (int)(-reason))

typedef enum
{
  RETURN_MASK_QUIT = RETURN_MASK (RETURN_QUIT),
  RETURN_MASK_ERROR = RETURN_MASK (RETURN_ERROR),
  RETURN_MASK_ALL = (RETURN_MASK_QUIT | RETURN_MASK_ERROR)
} return_mask;

/* Describe all exceptions.  */

enum errors {
  GDB_NO_ERROR,

  /* Any generic error, the corresponding text is in
     exception.message.  */
  GENERIC_ERROR,

  /* Something requested was not found.  */
  NOT_FOUND_ERROR,

  /* Thread library lacks support necessary for finding thread local
     storage.  */
  TLS_NO_LIBRARY_SUPPORT_ERROR,

  /* Load module not found while attempting to find thread local storage.  */
  TLS_LOAD_MODULE_NOT_FOUND_ERROR,

  /* Thread local storage has not been allocated yet.  */
  TLS_NOT_ALLOCATED_YET_ERROR,

  /* Something else went wrong while attempting to find thread local
     storage.  The ``struct gdb_exception'' message field provides
     more detail.  */
  TLS_GENERIC_ERROR,

  /* Problem parsing an XML document.  */
  XML_PARSE_ERROR,

  /* Error accessing memory.  */
  MEMORY_ERROR,

  /* Value not available.  E.g., a register was not collected in a
     traceframe.  */
  NOT_AVAILABLE_ERROR,

  /* Value was optimized out.  Note: if the value was a register, this
     means the register was not saved in the frame.  */
  OPTIMIZED_OUT_ERROR,

  /* DW_OP_entry_value resolving failed.  */
  NO_ENTRY_VALUE_ERROR,

  /* Target throwing an error has been closed.  Current command should be
     aborted as the inferior state is no longer valid.  */
  TARGET_CLOSE_ERROR,

  /* An undefined command was executed.  */
  UNDEFINED_COMMAND_ERROR,

  /* Requested feature, method, mechanism, etc. is not supported.  */
  NOT_SUPPORTED_ERROR,

  /* The number of candidates generated during line completion has
     reached the user's specified limit.  This isn't an error, this exception
     is used to halt searching for more completions, but for consistency
     "_ERROR" is appended to the name.  */
  MAX_COMPLETIONS_REACHED_ERROR,

  /* Add more errors here.  */
  NR_ERRORS
};

struct gdb_exception
{
  gdb_exception ()
    : reason ((enum return_reason) 0),
      error (GDB_NO_ERROR)
  {
  }

  gdb_exception (enum return_reason r, enum errors e)
    : reason (r),
      error (e)
  {
  }

  /* The copy constructor exists so that we can mark it "noexcept",
     which is a good practice for any sort of exception object.  */
  gdb_exception (const gdb_exception &other) noexcept
    : reason (other.reason),
      error (other.error),
      message (other.message)
  {
  }

  /* The assignment operator exists so that we can mark it "noexcept",
     which is a good practice for any sort of exception object.  */
  gdb_exception &operator= (const gdb_exception &other) noexcept
  {
    reason = other.reason;
    error = other.error;
    message = other.message;
    return *this;
  }

  /* Return the contents of the exception message, as a C string.  The
     string remains owned by the exception object.  */
  const char *what () const noexcept
  {
    return message->c_str ();
  }

  enum return_reason reason;
  enum errors error;
  std::shared_ptr<std::string> message;
};

/* Functions to drive the sjlj-based exceptions state machine.  Though
   declared here by necessity, these functions should be considered
   internal to the exceptions subsystem and not used other than via
   the TRY/CATCH (or TRY_SJLJ/CATCH_SJLJ) macros defined below.  */

extern jmp_buf *exceptions_state_mc_init (void);
extern int exceptions_state_mc_action_iter (void);
extern int exceptions_state_mc_action_iter_1 (void);
extern int exceptions_state_mc_catch (struct gdb_exception *, int);

/* For the C++ try/catch-based TRY/CATCH mechanism.  */

extern void exception_rethrow (void) ATTRIBUTE_NORETURN;

/* Macro to wrap up standard try/catch behavior.

   The double loop lets us correctly handle code "break"ing out of the
   try catch block.  (It works as the "break" only exits the inner
   "while" loop, the outer for loop detects this handling it
   correctly.)  Of course "return" and "goto" are not so lucky.

   For instance:

   *INDENT-OFF*

   TRY
     {
     }
   CATCH (e, RETURN_MASK_ERROR)
     {
       switch (e.reason)
         {
           case RETURN_ERROR: ...
         }
     }
   END_CATCH

  Note that the SJLJ version of the macros are actually named
  TRY_SJLJ/CATCH_SJLJ in order to make it possible to call them even
  when TRY/CATCH are mapped to C++ try/catch.  The SJLJ variants are
  needed in some cases where gdb exceptions need to cross third-party
  library code compiled without exceptions support (e.g.,
  readline).  */

#define TRY_SJLJ \
     { \
       jmp_buf *buf = \
	 exceptions_state_mc_init (); \
       setjmp (*buf); \
     } \
     while (exceptions_state_mc_action_iter ()) \
       while (exceptions_state_mc_action_iter_1 ())

#define CATCH_SJLJ(EXCEPTION, MASK)				\
  {							\
    struct gdb_exception EXCEPTION;				\
    if (exceptions_state_mc_catch (&(EXCEPTION), MASK))

#define END_CATCH_SJLJ				\
  }

/* We still need to wrap TRY/CATCH in C++ so that cleanups and C++
   exceptions can coexist.

   The TRY blocked is wrapped in a do/while(0) so that break/continue
   within the block works the same as in C.

   END_CATCH makes sure that even if the CATCH block doesn't want to
   catch the exception, we stop at every frame in the unwind chain to
   run its cleanups, which may e.g., have pointers to stack variables
   that are going to be destroyed.

   There's an outer scope around the whole TRY/END_CATCH in order to
   cause a compilation error if you forget to add the END_CATCH at the
   end a TRY/CATCH construct.  */

#define TRY								\
  {									\
    try									\
      {									\
	do								\
	  {

#define CATCH(EXCEPTION, MASK)						\
	  } while (0);							\
	}								\
    catch (struct gdb_exception ## _ ## MASK &EXCEPTION)

#define END_CATCH				\
    catch (...)					\
      {						\
	exception_rethrow ();			\
      }						\
  }

/* The exception types client code may catch.  They're just shims
   around gdb_exception that add nothing but type info.  Which is used
   is selected depending on the MASK argument passed to CATCH.  */

struct gdb_exception_RETURN_MASK_ALL : public gdb_exception
{
  explicit gdb_exception_RETURN_MASK_ALL (const gdb_exception &ex) noexcept
    : gdb_exception (ex)
  {
  }
};

struct gdb_exception_RETURN_MASK_ERROR : public gdb_exception_RETURN_MASK_ALL
{
  explicit gdb_exception_RETURN_MASK_ERROR (const gdb_exception &ex) noexcept
    : gdb_exception_RETURN_MASK_ALL (ex)
  {
  }
};

struct gdb_exception_RETURN_MASK_QUIT : public gdb_exception_RETURN_MASK_ALL
{
  explicit gdb_exception_RETURN_MASK_QUIT (const gdb_exception &ex) noexcept
    : gdb_exception_RETURN_MASK_ALL (ex)
  {
  }
};

/* An exception type that inherits from both std::bad_alloc and a gdb
   exception.  This is necessary because operator new can only throw
   std::bad_alloc, and OTOH, we want exceptions thrown due to memory
   allocation error to be caught by all the CATCH/RETURN_MASK_ALL
   spread around the codebase.  */

struct gdb_quit_bad_alloc
  : public gdb_exception_RETURN_MASK_QUIT,
    public std::bad_alloc
{
  explicit gdb_quit_bad_alloc (const gdb_exception &ex) noexcept
    : gdb_exception_RETURN_MASK_QUIT (ex),
      std::bad_alloc ()
  {
  }
};

/* *INDENT-ON* */

/* Throw an exception (as described by "struct gdb_exception"),
   landing in the inner most containing exception handler established
   using TRY/CATCH.  */
extern void throw_exception (struct gdb_exception exception)
     ATTRIBUTE_NORETURN;

/* Throw an exception by executing a LONG JUMP to the inner most
   containing exception handler established using TRY_SJLJ.  Necessary
   in some cases where we need to throw GDB exceptions across
   third-party library code (e.g., readline).  */
extern void throw_exception_sjlj (struct gdb_exception exception)
     ATTRIBUTE_NORETURN;

/* Convenience wrappers around throw_exception that throw GDB
   errors.  */
extern void throw_verror (enum errors, const char *fmt, va_list ap)
     ATTRIBUTE_NORETURN ATTRIBUTE_PRINTF (2, 0);
extern void throw_vquit (const char *fmt, va_list ap)
     ATTRIBUTE_NORETURN ATTRIBUTE_PRINTF (1, 0);
extern void throw_error (enum errors error, const char *fmt, ...)
     ATTRIBUTE_NORETURN ATTRIBUTE_PRINTF (2, 3);
extern void throw_quit (const char *fmt, ...)
     ATTRIBUTE_NORETURN ATTRIBUTE_PRINTF (1, 2);

/* A pre-defined non-exception.  */
extern const struct gdb_exception exception_none;

#endif /* COMMON_COMMON_EXCEPTIONS_H */
