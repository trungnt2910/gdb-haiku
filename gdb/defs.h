/* Basic, host-specific, and target-specific definitions for GDB.
   Copyright (C) 1986, 89, 91, 92, 93, 94, 95, 96, 1998
   Free Software Foundation, Inc.

This file is part of GDB.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef DEFS_H
#define DEFS_H

#include "config.h"		/* Generated by configure */
#include <stdio.h>
#include <errno.h>		/* System call error return status */
#include <limits.h>

#ifdef HAVE_STDDEF_H
#  include <stddef.h>
#else
#  include <sys/types.h>   /* for size_t */
#endif

/* Just in case they're not defined in stdio.h. */

#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_CUR
#define SEEK_CUR 1
#endif

/* First include ansidecl.h so we can use the various macro definitions
   here and in all subsequent file inclusions.  */

#include "ansidecl.h"

#ifdef ANSI_PROTOTYPES
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "libiberty.h"

/* libiberty.h can't declare this one, but evidently we can.  */
extern char *strsignal PARAMS ((int));

#include "progress.h"

#ifdef USE_MMALLOC
#include "mmalloc.h"
#endif

/* For BFD64 and bfd_vma.  */
#include "bfd.h"

/* An address in the program being debugged.  Host byte order.  Rather
   than duplicate all the logic in BFD which figures out what type
   this is (long, long long, etc.) and whether it needs to be 64
   bits (the host/target interactions are subtle), we just use
   bfd_vma.  */

typedef bfd_vma CORE_ADDR;

extern int core_addr_lessthan PARAMS ((CORE_ADDR lhs, CORE_ADDR rhs));
extern int core_addr_greaterthan PARAMS ((CORE_ADDR lhs, CORE_ADDR rhs));


#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif

/* Gdb does *lots* of string compares.  Use macros to speed them up by
   avoiding function calls if the first characters are not the same. */

#define STRCMP(a,b) (*(a) == *(b) ? strcmp ((a), (b)) : (int)*(a) - (int)*(b))
#define STREQ(a,b) (*(a) == *(b) ? !strcmp ((a), (b)) : 0)
#define STREQN(a,b,c) (*(a) == *(b) ? !strncmp ((a), (b), (c)) : 0)

/* The character GNU C++ uses to build identifiers that must be unique from
   the program's identifiers (such as $this and $$vptr).  */
#define CPLUS_MARKER '$'	/* May be overridden to '.' for SysV */

/* Check if a character is one of the commonly used C++ marker characters.  */
extern int is_cplus_marker PARAMS ((int));

/* use tui interface if non-zero */
extern int tui_version;

#if defined(TUI)
/* all invocations of TUIDO should have two sets of parens */
#define TUIDO(x)	tuiDo x
#else
#define TUIDO(x)
#endif

/* enable xdb commands if set */
extern int xdb_commands;

/* enable dbx commands if set */
extern int dbx_commands;

extern int quit_flag;
extern int immediate_quit;
extern int sevenbit_strings;

extern void quit PARAMS ((void));

#ifdef QUIT
/* do twice to force compiler warning */
#define QUIT_FIXME "FIXME"
#define QUIT_FIXME "ignoring redefinition of QUIT"
#else
#define QUIT { \
  if (quit_flag) quit (); \
  if (interactive_hook) interactive_hook (); \
  PROGRESS (1); \
}
#endif

/* Command classes are top-level categories into which commands are broken
   down for "help" purposes.  
   Notes on classes: class_alias is for alias commands which are not
   abbreviations of the original command.  class-pseudo is for commands
   which are not really commands nor help topics ("stop").  */

enum command_class
{
  /* Special args to help_list */
  all_classes = -2, all_commands = -1,
  /* Classes of commands */
  no_class = -1, class_run = 0, class_vars, class_stack,
  class_files, class_support, class_info, class_breakpoint, class_trace,
  class_alias, class_obscure, class_user, class_maintenance,
  class_pseudo, class_tui, class_xdb
};

/* Languages represented in the symbol table and elsewhere.
   This should probably be in language.h, but since enum's can't
   be forward declared to satisfy opaque references before their
   actual definition, needs to be here. */

enum language 
{
   language_unknown, 		/* Language not known */
   language_auto,		/* Placeholder for automatic setting */
   language_c, 			/* C */
   language_cplus, 		/* C++ */
   language_java,		/* Java */
   language_chill,		/* Chill */
   language_fortran,		/* Fortran */
   language_m2,			/* Modula-2 */
   language_asm,		/* Assembly language */
   language_scm			/* Scheme / Guile */
};

enum precision_type
{
  single_precision,
  double_precision,
  unspecified_precision
};
   
/* the cleanup list records things that have to be undone
   if an error happens (descriptors to be closed, memory to be freed, etc.)
   Each link in the chain records a function to call and an
   argument to give it.

   Use make_cleanup to add an element to the cleanup chain.
   Use do_cleanups to do all cleanup actions back to a given
   point in the chain.  Use discard_cleanups to remove cleanups
   from the chain back to a given point, not doing them.  */

struct cleanup
{
  struct cleanup *next;
  void (*function) PARAMS ((PTR));
  PTR arg;
};


/* The ability to declare that a function never returns is useful, but
   not really required to compile GDB successfully, so the NORETURN and
   ATTR_NORETURN macros normally expand into nothing.  */

/* If compiling with older versions of GCC, a function may be declared
   "volatile" to indicate that it does not return.  */

#ifndef NORETURN
# if defined(__GNUC__) \
     && (__GNUC__ == 1 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7))
#  define NORETURN volatile
# else
#  define NORETURN /* nothing */
# endif
#endif

/* GCC 2.5 and later versions define a function attribute "noreturn",
   which is the preferred way to declare that a function never returns.
   However GCC 2.7 appears to be the first version in which this fully
   works everywhere we use it. */

#ifndef ATTR_NORETURN
# if defined(__GNUC__) && __GNUC__ >= 2 && __GNUC_MINOR__ >= 7
#  define ATTR_NORETURN __attribute__ ((noreturn))
# else
#  define ATTR_NORETURN /* nothing */
# endif
#endif

#ifndef ATTR_FORMAT
# if defined(__GNUC__) && __GNUC__ >= 2 && __GNUC_MINOR__ >= 4 && defined (__ANSI_PROTOTYPES)
#  define ATTR_FORMAT(type, x, y) __attribute__ ((format(type, x, y)))
# else
#  define ATTR_FORMAT(type, x, y) /* nothing */
# endif
#endif

/* Needed for various prototypes */

#ifdef __STDC__
struct symtab;
struct breakpoint;
#endif

/* From blockframe.c */

extern int inside_entry_func PARAMS ((CORE_ADDR));

extern int inside_entry_file PARAMS ((CORE_ADDR addr));

extern int inside_main_func PARAMS ((CORE_ADDR pc));

/* From ch-lang.c, for the moment. (FIXME) */

extern char *chill_demangle PARAMS ((const char *));

/* From utils.c */

extern void initialize_utils PARAMS ((void));

extern void notice_quit PARAMS ((void));

extern int strcmp_iw PARAMS ((const char *, const char *));

extern int subset_compare PARAMS ((char *, char *));

extern char *safe_strerror PARAMS ((int));

extern char *safe_strsignal PARAMS ((int));

extern void init_malloc PARAMS ((void *));

extern void request_quit PARAMS ((int));

extern void do_cleanups PARAMS ((struct cleanup *));
extern void do_final_cleanups PARAMS ((struct cleanup *));
extern void do_my_cleanups PARAMS ((struct cleanup **, struct cleanup *));
extern void do_run_cleanups PARAMS ((struct cleanup *));

extern void discard_cleanups PARAMS ((struct cleanup *));
extern void discard_final_cleanups PARAMS ((struct cleanup *));
extern void discard_my_cleanups PARAMS ((struct cleanup **, struct cleanup *));

typedef void (*make_cleanup_func) PARAMS ((void *));

extern struct cleanup *make_cleanup PARAMS ((make_cleanup_func, void *));

extern struct cleanup *make_cleanup_freeargv PARAMS ((char **));

extern struct cleanup *make_final_cleanup PARAMS ((make_cleanup_func, void *));

extern struct cleanup *make_my_cleanup PARAMS ((struct cleanup **, 
                                                make_cleanup_func, void *));

extern struct cleanup *make_run_cleanup PARAMS ((make_cleanup_func, void *));

extern struct cleanup *save_cleanups PARAMS ((void));
extern struct cleanup *save_final_cleanups PARAMS ((void));
extern struct cleanup *save_my_cleanups PARAMS ((struct cleanup **));

extern void restore_cleanups PARAMS ((struct cleanup *));
extern void restore_final_cleanups PARAMS ((struct cleanup *));
extern void restore_my_cleanups PARAMS ((struct cleanup **, struct cleanup *));

extern void free_current_contents PARAMS ((char **));

extern void null_cleanup PARAMS ((PTR));

extern int myread PARAMS ((int, char *, int));

extern int query PARAMS((char *, ...))
     ATTR_FORMAT(printf, 1, 2);

#if !defined (USE_MMALLOC)
extern PTR mmalloc PARAMS ((PTR, size_t));
extern PTR mrealloc PARAMS ((PTR, PTR, size_t));
extern void mfree PARAMS ((PTR, PTR));
#endif

extern void init_page_info PARAMS ((void));

/* From demangle.c */

extern void set_demangling_style PARAMS ((char *));

/* From tm.h */

struct type;
typedef int (use_struct_convention_fn) PARAMS ((int gcc_p, struct type *value_type));
extern use_struct_convention_fn generic_use_struct_convention;

typedef unsigned char *(breakpoint_from_pc_fn) PARAMS ((CORE_ADDR *pcptr, int *lenptr));



/* Annotation stuff.  */

extern int annotation_level; /* in stack.c */

extern void begin_line PARAMS ((void));

extern void wrap_here PARAMS ((char *));

extern void reinitialize_more_filter PARAMS ((void));

/* new */
enum streamtype
{
  afile,
  astring
};

/* new */
typedef struct tui_stream
{
  enum streamtype ts_streamtype;
  FILE *ts_filestream;
  char *ts_strbuf;
  int ts_buflen;
} GDB_FILE;

extern GDB_FILE *gdb_stdout;
extern GDB_FILE *gdb_stderr;

#if 0
typedef FILE GDB_FILE;
#define gdb_stdout stdout
#define gdb_stderr stderr
#endif

#if defined(TUI)
#include "tui.h"
#include "tuiCommand.h"
#include "tuiData.h"
#include "tuiIO.h"
#include "tuiLayout.h"
#include "tuiWin.h"
#endif

extern void gdb_fclose PARAMS ((GDB_FILE **));

extern void gdb_flush PARAMS ((GDB_FILE *));

extern GDB_FILE *gdb_fopen PARAMS ((char * name, char * mode));

extern void fputs_filtered PARAMS ((const char *, GDB_FILE *));

extern void fputs_unfiltered PARAMS ((const char *, GDB_FILE *));

extern int fputc_filtered PARAMS ((int c, GDB_FILE *));

extern int fputc_unfiltered PARAMS ((int c, GDB_FILE *));

extern int putchar_unfiltered PARAMS ((int c));

extern void puts_filtered PARAMS ((const char *));

extern void puts_unfiltered PARAMS ((const char *));

extern void puts_debug PARAMS ((char *prefix, char *string, char *suffix));

extern void vprintf_filtered PARAMS ((const char *, va_list))
     ATTR_FORMAT(printf, 1, 0);

extern void vfprintf_filtered PARAMS ((GDB_FILE *, const char *, va_list))
     ATTR_FORMAT(printf, 2, 0);

extern void fprintf_filtered PARAMS ((GDB_FILE *, const char *, ...))
     ATTR_FORMAT(printf, 2, 3);

extern void fprintfi_filtered PARAMS ((int, GDB_FILE *, const char *, ...))
     ATTR_FORMAT(printf, 3, 4);

extern void printf_filtered PARAMS ((const char *, ...))
     ATTR_FORMAT(printf, 1, 2);

extern void printfi_filtered PARAMS ((int, const char *, ...))
     ATTR_FORMAT(printf, 2, 3);

extern void vprintf_unfiltered PARAMS ((const char *, va_list))
     ATTR_FORMAT(printf, 1, 0);

extern void vfprintf_unfiltered PARAMS ((GDB_FILE *, const char *, va_list))
     ATTR_FORMAT(printf, 2, 0);

extern void fprintf_unfiltered PARAMS ((GDB_FILE *, const char *, ...))
     ATTR_FORMAT(printf, 2, 3);

extern void printf_unfiltered PARAMS ((const char *, ...))
     ATTR_FORMAT(printf, 1, 2);

extern int gdb_file_isatty PARAMS ((GDB_FILE *));

extern GDB_FILE *gdb_file_init_astring PARAMS ((int));

extern void gdb_file_deallocate PARAMS ((GDB_FILE **));

extern char *gdb_file_get_strbuf PARAMS ((GDB_FILE *));

extern void gdb_file_adjust_strbuf PARAMS ((int, GDB_FILE *));

extern void print_spaces PARAMS ((int, GDB_FILE *));

extern void print_spaces_filtered PARAMS ((int, GDB_FILE *));

extern char *n_spaces PARAMS ((int));

extern void gdb_printchar PARAMS ((int, GDB_FILE *, int));

extern void gdb_print_address PARAMS ((void *, GDB_FILE *));

typedef bfd_vma t_addr;
typedef bfd_vma t_reg;
extern char* paddr PARAMS ((t_addr addr));

extern char* preg PARAMS ((t_reg reg));

extern char* paddr_nz PARAMS ((t_addr addr));

extern char* preg_nz PARAMS ((t_reg reg));

extern void fprintf_symbol_filtered PARAMS ((GDB_FILE *, char *,
					     enum language, int));

extern NORETURN void perror_with_name PARAMS ((char *)) ATTR_NORETURN;

extern void print_sys_errmsg PARAMS ((char *, int));

/* From regex.c or libc.  BSD 4.4 declares this with the argument type as
   "const char *" in unistd.h, so we can't declare the argument
   as "char *".  */

extern char *re_comp PARAMS ((const char *));

/* From symfile.c */

extern void symbol_file_command PARAMS ((char *, int));

/* From top.c */

extern char *skip_quoted PARAMS ((char *));

extern char *gdb_readline PARAMS ((char *));

extern char *command_line_input PARAMS ((char *, int, char *));

extern void print_prompt PARAMS ((void));

extern int input_from_terminal_p PARAMS ((void));

extern int info_verbose;

/* From printcmd.c */

extern void set_next_address PARAMS ((CORE_ADDR));

extern void print_address_symbolic PARAMS ((CORE_ADDR, GDB_FILE *, int,
					    char *));

extern void print_address_numeric PARAMS ((CORE_ADDR, int, GDB_FILE *));

extern void print_address PARAMS ((CORE_ADDR, GDB_FILE *));

/* From source.c */

extern int openp PARAMS ((char *, int, char *, int, int, char **));

extern int source_full_path_of PARAMS ((char *, char **));

extern void mod_path PARAMS ((char *, char **));

extern void directory_command PARAMS ((char *, int));

extern void init_source_path PARAMS ((void));

extern char *symtab_to_filename PARAMS ((struct symtab *));

/* From findvar.c */

extern int read_relative_register_raw_bytes PARAMS ((int, char *));

#if __STDC__
enum lval_type;
struct frame_info;
#endif
void default_get_saved_register PARAMS ((char *raw_buffer, int *optimized,
					 CORE_ADDR *addrp,
					 struct frame_info *frame, int regnum,
					 enum lval_type *lval));

/* From readline (but not in any readline .h files).  */

extern char *tilde_expand PARAMS ((char *));

/* Control types for commands */

enum misc_command_type
{
  ok_command,
  end_command,
  else_command,
  nop_command
};

enum command_control_type
{
  simple_control,
  break_control,
  continue_control,
  while_control,
  if_control,
  invalid_control
};

/* Structure for saved commands lines
   (for breakpoints, defined commands, etc).  */

struct command_line
{
  struct command_line *next;
  char *line;
  enum command_control_type control_type;
  int body_count;
  struct command_line **body_list;
};

extern struct command_line *read_command_lines PARAMS ((char *, int));

extern void free_command_lines PARAMS ((struct command_line **));

/* String containing the current directory (what getwd would return).  */

extern char *current_directory;

/* Default radixes for input and output.  Only some values supported.  */
extern unsigned input_radix;
extern unsigned output_radix;

/* Possibilities for prettyprint parameters to routines which print
   things.  Like enum language, this should be in value.h, but needs
   to be here for the same reason.  FIXME:  If we can eliminate this
   as an arg to LA_VAL_PRINT, then we can probably move it back to
   value.h. */

enum val_prettyprint
{
  Val_no_prettyprint = 0,
  Val_prettyprint,
  /* Use the default setting which the user has specified.  */
  Val_pretty_default
};


/* Host machine definition.  This will be a symlink to one of the
   xm-*.h files, built by the `configure' script.  */

#include "xm.h"

/* Native machine support.  This will be a symlink to one of the
   nm-*.h files, built by the `configure' script.  */

#include "nm.h"

/* Target machine definition.  This will be a symlink to one of the
   tm-*.h files, built by the `configure' script.  */

#include "tm.h"

/* If the xm.h file did not define the mode string used to open the
   files, assume that binary files are opened the same way as text
   files */
#ifndef FOPEN_RB
#include "fopen-same.h"
#endif

/* Microsoft C can't deal with const pointers */

#ifdef _MSC_VER
#define CONST_PTR
#else
#define CONST_PTR const
#endif

/*
 * Allow things in gdb to be declared "volatile".  If compiling ANSI, it
 * just works.  If compiling with gcc but non-ansi, redefine to __volatile__.
 * If non-ansi, non-gcc, then eliminate "volatile" entirely, making those
 * objects be read-write rather than read-only.
 */

#ifndef volatile
#ifndef __STDC__
# ifdef __GNUC__
#  define volatile __volatile__
# else
#  define volatile /*nothing*/
# endif /* GNUC */
#endif /* STDC */
#endif /* volatile */

/* Defaults for system-wide constants (if not defined by xm.h, we fake it).
   FIXME: Assumes 2's complement arithmetic */

#if !defined (UINT_MAX)
#define	UINT_MAX ((unsigned int)(~0))		/* 0xFFFFFFFF for 32-bits */
#endif

#if !defined (INT_MAX)
#define	INT_MAX ((int)(UINT_MAX >> 1))		/* 0x7FFFFFFF for 32-bits */
#endif

#if !defined (INT_MIN)
#define INT_MIN ((int)((int) ~0 ^ INT_MAX))	/* 0x80000000 for 32-bits */
#endif

#if !defined (ULONG_MAX)
#define	ULONG_MAX ((unsigned long)(~0L))	/* 0xFFFFFFFF for 32-bits */
#endif

#if !defined (LONG_MAX)
#define	LONG_MAX ((long)(ULONG_MAX >> 1))	/* 0x7FFFFFFF for 32-bits */
#endif

#ifndef LONGEST

#ifdef BFD64

/* This is to make sure that LONGEST is at least as big as CORE_ADDR.  */

#define LONGEST BFD_HOST_64_BIT
#define ULONGEST BFD_HOST_U_64_BIT

#else /* No BFD64 */

#  ifdef CC_HAS_LONG_LONG
#    define LONGEST long long
#    define ULONGEST unsigned long long
#  else
/* BFD_HOST_64_BIT is defined for some hosts that don't have long long
   (e.g. i386-windows) so try it.  */
#    ifdef BFD_HOST_64_BIT
#      define LONGEST BFD_HOST_64_BIT
#      define ULONGEST BFD_HOST_U_64_BIT
#    else
#      define LONGEST long
#      define ULONGEST unsigned long
#    endif
#  endif

#endif /* No BFD64 */

#endif /* ! LONGEST */

/* Convert a LONGEST to an int.  This is used in contexts (e.g. number of
   arguments to a function, number in a value history, register number, etc.)
   where the value must not be larger than can fit in an int.  */

extern int longest_to_int PARAMS ((LONGEST));

/* Assorted functions we can declare, now that const and volatile are 
   defined.  */

extern char *savestring PARAMS ((const char *, int));

extern char *msavestring PARAMS ((void *, const char *, int));

extern char *strsave PARAMS ((const char *));

extern char *mstrsave PARAMS ((void *, const char *));

#ifdef _MSC_VER /* FIXME; was long, but this causes compile errors in msvc if already defined */
extern PTR xmmalloc PARAMS ((PTR, size_t));

extern PTR xmrealloc PARAMS ((PTR, PTR, size_t));
#else
extern PTR xmmalloc PARAMS ((PTR, long));

extern PTR xmrealloc PARAMS ((PTR, PTR, long));
#endif

extern int parse_escape PARAMS ((char **));

/* compat - handle old targets that just define REGISTER_NAMES */
#ifndef REGISTER_NAME
extern char *gdb_register_names[];
#define REGISTER_NAME(i) gdb_register_names[i]
#endif

/* Message to be printed before the error message, when an error occurs.  */

extern char *error_pre_print;

/* Message to be printed before the error message, when an error occurs.  */

extern char *quit_pre_print;

/* Message to be printed before the warning message, when a warning occurs.  */

extern char *warning_pre_print;

extern NORETURN void error PARAMS((const char *, ...)) ATTR_NORETURN;

extern void error_begin PARAMS ((void));

extern NORETURN void fatal PARAMS((char *, ...)) ATTR_NORETURN;

extern NORETURN void nomem PARAMS ((long)) ATTR_NORETURN;

/* Reasons for calling return_to_top_level.  */
enum return_reason {
  /* User interrupt.  */
  RETURN_QUIT,

  /* Any other error.  */
  RETURN_ERROR
};

#define RETURN_MASK_QUIT (1 << (int)RETURN_QUIT)
#define RETURN_MASK_ERROR (1 << (int)RETURN_ERROR)
#define RETURN_MASK_ALL (RETURN_MASK_QUIT | RETURN_MASK_ERROR)
typedef int return_mask;

extern NORETURN void
return_to_top_level PARAMS ((enum return_reason)) ATTR_NORETURN;

typedef int (catch_errors_ftype) PARAMS ((PTR));
extern int catch_errors PARAMS ((catch_errors_ftype *, PTR, char *, return_mask));

extern void warning_begin PARAMS ((void));

extern void warning PARAMS ((const char *, ...))
     ATTR_FORMAT(printf, 1, 2);

/* Global functions from other, non-gdb GNU thingies.
   Libiberty thingies are no longer declared here.  We include libiberty.h
   above, instead.  */

#ifndef GETENV_PROVIDED
extern char *getenv PARAMS ((const char *));
#endif

/* From other system libraries */

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#ifdef HAVE_STDLIB_H
#if defined(_MSC_VER) && !defined(__cplusplus)
/* msvc defines these in stdlib.h for c code */
#undef min
#undef max
#endif
#include <stdlib.h>
#endif
#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif


/* We take the address of fclose later, but some stdio's forget
   to declare this.  We can't always declare it since there's
   no way to declare the parameters without upsetting some compiler
   somewhere. */

#ifndef FCLOSE_PROVIDED
extern int fclose PARAMS ((FILE *));
#endif

#ifndef atof
extern double atof PARAMS ((const char *));	/* X3.159-1989  4.10.1.1 */
#endif

#ifndef MALLOC_INCOMPATIBLE

#ifdef NEED_DECLARATION_MALLOC
extern PTR malloc ();
#endif

#ifdef NEED_DECLARATION_REALLOC
extern PTR realloc ();
#endif

#ifdef NEED_DECLARATION_FREE
extern void free ();
#endif

#endif /* MALLOC_INCOMPATIBLE */

/* Various possibilities for alloca.  */
#ifndef alloca
# ifdef __GNUC__
#  define alloca __builtin_alloca
# else /* Not GNU C */
#  ifdef HAVE_ALLOCA_H
#   include <alloca.h>
#  else
#   ifdef _AIX
 #pragma alloca
#   else

/* We need to be careful not to declare this in a way which conflicts with
   bison.  Bison never declares it as char *, but under various circumstances
   (like __hpux) we need to use void *.  */
#    if defined (__STDC__) || defined (__hpux)
   extern void *alloca ();
#    else /* Don't use void *.  */
   extern char *alloca ();
#    endif /* Don't use void *.  */
#   endif /* Not _AIX */
#  endif /* Not HAVE_ALLOCA_H */
# endif /* Not GNU C */
#endif /* alloca not defined */

/* HOST_BYTE_ORDER must be defined to one of these.  */

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif

#if !defined (BIG_ENDIAN)
#define BIG_ENDIAN 4321
#endif

#if !defined (LITTLE_ENDIAN)
#define LITTLE_ENDIAN 1234
#endif

/* Dynamic target-system-dependent parameters for GDB. */
#include "gdbarch.h"

/* Static target-system-dependent parameters for GDB. */

/* Number of bits in a char or unsigned char for the target machine.
   Just like CHAR_BIT in <limits.h> but describes the target machine.  */
#if !defined (TARGET_CHAR_BIT)
#define TARGET_CHAR_BIT 8
#endif

/* Number of bits in a short or unsigned short for the target machine. */
#if !defined (TARGET_SHORT_BIT)
#define TARGET_SHORT_BIT (2 * TARGET_CHAR_BIT)
#endif

/* Number of bits in an int or unsigned int for the target machine. */
#if !defined (TARGET_INT_BIT)
#define TARGET_INT_BIT (4 * TARGET_CHAR_BIT)
#endif

/* Number of bits in a long or unsigned long for the target machine. */
#if !defined (TARGET_LONG_BIT)
#define TARGET_LONG_BIT (4 * TARGET_CHAR_BIT)
#endif

/* Number of bits in a long long or unsigned long long for the target machine. */
#if !defined (TARGET_LONG_LONG_BIT)
#define TARGET_LONG_LONG_BIT (2 * TARGET_LONG_BIT)
#endif

/* Number of bits in a float for the target machine. */
#if !defined (TARGET_FLOAT_BIT)
#define TARGET_FLOAT_BIT (4 * TARGET_CHAR_BIT)
#endif

/* Number of bits in a double for the target machine. */
#if !defined (TARGET_DOUBLE_BIT)
#define TARGET_DOUBLE_BIT (8 * TARGET_CHAR_BIT)
#endif

/* Number of bits in a long double for the target machine.  */
#if !defined (TARGET_LONG_DOUBLE_BIT)
#define TARGET_LONG_DOUBLE_BIT (2 * TARGET_DOUBLE_BIT)
#endif

/* Number of bits in a pointer for the target machine */
#if !defined (TARGET_PTR_BIT)
#define TARGET_PTR_BIT TARGET_INT_BIT
#endif

/* If we picked up a copy of CHAR_BIT from a configuration file
   (which may get it by including <limits.h>) then use it to set
   the number of bits in a host char.  If not, use the same size
   as the target. */

#if defined (CHAR_BIT)
#define HOST_CHAR_BIT CHAR_BIT
#else
#define HOST_CHAR_BIT TARGET_CHAR_BIT
#endif

/* The bit byte-order has to do just with numbering of bits in
   debugging symbols and such.  Conceptually, it's quite separate
   from byte/word byte order.  */

#if !defined (BITS_BIG_ENDIAN)
#define BITS_BIG_ENDIAN (TARGET_BYTE_ORDER == BIG_ENDIAN)
#endif

/* In findvar.c.  */

extern LONGEST extract_signed_integer PARAMS ((void *, int));

extern ULONGEST extract_unsigned_integer PARAMS ((void *, int));

extern int extract_long_unsigned_integer PARAMS ((void *, int, LONGEST *));

extern CORE_ADDR extract_address PARAMS ((void *, int));

extern void store_signed_integer PARAMS ((PTR, int, LONGEST));

extern void store_unsigned_integer PARAMS ((PTR, int, ULONGEST));

extern void store_address PARAMS ((PTR, int, LONGEST));

/* Setup definitions for host and target floating point formats.  We need to
   consider the format for `float', `double', and `long double' for both target
   and host.  We need to do this so that we know what kind of conversions need
   to be done when converting target numbers to and from the hosts DOUBLEST
   data type.  */

/* This is used to indicate that we don't know the format of the floating point
   number.  Typically, this is useful for native ports, where the actual format
   is irrelevant, since no conversions will be taking place.  */

extern const struct floatformat floatformat_unknown;

#if HOST_BYTE_ORDER == BIG_ENDIAN
#  ifndef HOST_FLOAT_FORMAT
#    define HOST_FLOAT_FORMAT &floatformat_ieee_single_big
#  endif
#  ifndef HOST_DOUBLE_FORMAT
#    define HOST_DOUBLE_FORMAT &floatformat_ieee_double_big
#  endif
#else				/* LITTLE_ENDIAN */
#  ifndef HOST_FLOAT_FORMAT
#    define HOST_FLOAT_FORMAT &floatformat_ieee_single_little
#  endif
#  ifndef HOST_DOUBLE_FORMAT
#    define HOST_DOUBLE_FORMAT &floatformat_ieee_double_little
#  endif
#endif

#ifndef HOST_LONG_DOUBLE_FORMAT
#define HOST_LONG_DOUBLE_FORMAT &floatformat_unknown
#endif

#ifndef TARGET_FLOAT_FORMAT
#define TARGET_FLOAT_FORMAT (TARGET_BYTE_ORDER == BIG_ENDIAN \
			     ? &floatformat_ieee_single_big \
			     : &floatformat_ieee_single_little)
#endif
#ifndef TARGET_DOUBLE_FORMAT
#define TARGET_DOUBLE_FORMAT (TARGET_BYTE_ORDER == BIG_ENDIAN \
			      ? &floatformat_ieee_double_big \
			      : &floatformat_ieee_double_little)
#endif

#ifndef TARGET_LONG_DOUBLE_FORMAT
#  define TARGET_LONG_DOUBLE_FORMAT &floatformat_unknown
#endif

/* Use `long double' if the host compiler supports it.  (Note that this is not
   necessarily any longer than `double'.  On SunOS/gcc, it's the same as
   double.)  This is necessary because GDB internally converts all floating
   point values to the widest type supported by the host.

   There are problems however, when the target `long double' is longer than the
   host's `long double'.  In general, we'll probably reduce the precision of
   any such values and print a warning.  */

#ifdef HAVE_LONG_DOUBLE
typedef long double DOUBLEST;
#else
typedef double DOUBLEST;
#endif

extern void floatformat_to_doublest PARAMS ((const struct floatformat *,
					     char *, DOUBLEST *));
extern void floatformat_from_doublest PARAMS ((const struct floatformat *,
					       DOUBLEST *, char *));
extern DOUBLEST extract_floating PARAMS ((void *, int));

extern void store_floating PARAMS ((void *, int, DOUBLEST));

/* On some machines there are bits in addresses which are not really
   part of the address, but are used by the kernel, the hardware, etc.
   for special purposes.  ADDR_BITS_REMOVE takes out any such bits
   so we get a "real" address such as one would find in a symbol
   table.  This is used only for addresses of instructions, and even then
   I'm not sure it's used in all contexts.  It exists to deal with there
   being a few stray bits in the PC which would mislead us, not as some sort
   of generic thing to handle alignment or segmentation (it's possible it
   should be in TARGET_READ_PC instead). */
#if !defined (ADDR_BITS_REMOVE)
#define ADDR_BITS_REMOVE(addr) (addr)
#endif /* No ADDR_BITS_REMOVE.  */

/* From valops.c */

extern CORE_ADDR push_bytes PARAMS ((CORE_ADDR, char *, int));

extern CORE_ADDR push_word PARAMS ((CORE_ADDR, ULONGEST));

extern int watchdog;

/* Hooks for alternate command interfaces.  */

#ifdef __STDC__
struct target_waitstatus;
struct cmd_list_element;
#endif

extern void (*async_hook) PARAMS ((void));                                                                   
extern void (*init_ui_hook) PARAMS ((char *argv0));
extern void (*command_loop_hook) PARAMS ((void));
extern void (*fputs_unfiltered_hook) PARAMS ((const char *linebuffer,
					      GDB_FILE *stream));
extern void (*print_frame_info_listing_hook) PARAMS ((struct symtab *s,
						      int line, int stopline,
						      int noerror));
extern struct frame_info *parse_frame_specification PARAMS ((char *frame_exp));
extern int  (*query_hook) PARAMS ((const char *, va_list));
extern void (*warning_hook) PARAMS ((const char *, va_list));
extern void (*flush_hook) PARAMS ((GDB_FILE *stream));
extern void (*create_breakpoint_hook) PARAMS ((struct breakpoint *b));
extern void (*delete_breakpoint_hook) PARAMS ((struct breakpoint *bpt));
extern void (*modify_breakpoint_hook) PARAMS ((struct breakpoint *bpt));
extern void (*target_output_hook) PARAMS ((char *));
extern void (*interactive_hook) PARAMS ((void));
extern void (*registers_changed_hook) PARAMS ((void));
extern void (*readline_begin_hook) PARAMS ((char *, ...));
extern char * (*readline_hook) PARAMS ((char *));
extern void (*readline_end_hook) PARAMS ((void));
extern void (*register_changed_hook) PARAMS ((int regno));
extern void (*memory_changed_hook) PARAMS ((CORE_ADDR addr, int len));
extern void (*context_hook) PARAMS ((int));
extern int (*target_wait_hook) PARAMS ((int pid,
					struct target_waitstatus *status));

extern void (*call_command_hook) PARAMS ((struct cmd_list_element *c,
					  char *cmd, int from_tty));

extern NORETURN void (*error_hook) PARAMS ((void)) ATTR_NORETURN;

extern void (*error_begin_hook) PARAMS ((void));


/* Inhibit window interface if non-zero. */

extern int use_windows;

/* Symbolic definitions of filename-related things.  */
/* FIXME, this doesn't work very well if host and executable
   filesystems conventions are different.  */

#ifndef DIRNAME_SEPARATOR
#define DIRNAME_SEPARATOR ':'
#endif

#ifndef SLASH_P
#if defined(__GO32__)||defined(_WIN32)
#define SLASH_P(X) ((X)=='\\')
#else
#define SLASH_P(X) ((X)=='/')
#endif
#endif

#ifndef SLASH_CHAR
#if defined(__GO32__)||defined(_WIN32)
#define SLASH_CHAR '\\'
#else
#define SLASH_CHAR '/'
#endif
#endif

#ifndef SLASH_STRING
#if defined(__GO32__)||defined(_WIN32)
#define SLASH_STRING "\\"
#else
#define SLASH_STRING "/"
#endif
#endif

#ifndef ROOTED_P
#define ROOTED_P(X) (SLASH_P((X)[0]))
#endif

/* On some systems, PIDGET is defined to extract the inferior pid from
   an internal pid that has the thread id and pid in seperate bit
   fields.  If not defined, then just use the entire internal pid as
   the actual pid. */

#ifndef PIDGET
#define PIDGET(pid) (pid)
#endif

/* If under Cygwin, provide backwards compatibility with older
   Cygwin compilers that don't define the current cpp define. */
#ifdef __CYGWIN32__
#ifndef __CYGWIN__
#define __CYGWIN__
#endif
#endif

#endif /* #ifndef DEFS_H */
