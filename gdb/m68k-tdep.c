/* Target dependent code for the Motorola 68000 series.
   Copyright 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1999, 2000, 2001,
   2002, 2003
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
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include "defs.h"
#include "frame.h"
#include "symtab.h"
#include "gdbcore.h"
#include "value.h"
#include "gdb_string.h"
#include "inferior.h"
#include "regcache.h"
#include "arch-utils.h"
#include "osabi.h"

#include "m68k-tdep.h"


#define P_LINKL_FP	0x480e
#define P_LINKW_FP	0x4e56
#define P_PEA_FP	0x4856
#define P_MOVL_SP_FP	0x2c4f
#define P_MOVL		0x207c
#define P_JSR		0x4eb9
#define P_BSR		0x61ff
#define P_LEAL		0x43fb
#define P_MOVML		0x48ef
#define P_FMOVM		0xf237
#define P_TRAP		0x4e40


#define REGISTER_BYTES_FP (16*4 + 8 + 8*12 + 3*4)
#define REGISTER_BYTES_NOFP (16*4 + 8)

#define NUM_FREGS (NUM_REGS-24)

/* Offset from SP to first arg on stack at first instruction of a function */

#define SP_ARG0 (1 * 4)

/* This was determined by experimentation on hp300 BSD 4.3.  Perhaps
   it corresponds to some offset in /usr/include/sys/user.h or
   something like that.  Using some system include file would
   have the advantage of probably being more robust in the face
   of OS upgrades, but the disadvantage of being wrong for
   cross-debugging.  */

#define SIG_PC_FP_OFFSET 530

#define TARGET_M68K


#if !defined (BPT_VECTOR)
#define BPT_VECTOR 0xf
#endif

#if !defined (REMOTE_BPT_VECTOR)
#define REMOTE_BPT_VECTOR 1
#endif


static void m68k_frame_init_saved_regs (struct frame_info *frame_info);


/* gdbarch_breakpoint_from_pc is set to m68k_local_breakpoint_from_pc
   so m68k_remote_breakpoint_from_pc is currently not used.  */

static const unsigned char *
m68k_remote_breakpoint_from_pc (CORE_ADDR *pcptr, int *lenptr)
{
  static unsigned char break_insn[] = {0x4e, (0x40 | REMOTE_BPT_VECTOR)};
  *lenptr = sizeof (break_insn);
  return break_insn;
}

static const unsigned char *
m68k_local_breakpoint_from_pc (CORE_ADDR *pcptr, int *lenptr)
{
  static unsigned char break_insn[] = {0x4e, (0x40 | BPT_VECTOR)};
  *lenptr = sizeof (break_insn);
  return break_insn;
}


static int
m68k_register_bytes_ok (long numbytes)
{
  return ((numbytes == REGISTER_BYTES_FP)
	  || (numbytes == REGISTER_BYTES_NOFP));
}

/* Number of bytes of storage in the actual machine representation
   for register regnum.  On the 68000, all regs are 4 bytes
   except the floating point regs which are 12 bytes.  */

static int
m68k_register_raw_size (int regnum)
{
  return (regnum >= FP0_REGNUM && regnum < FP0_REGNUM + 8 ? 12 : 4);
}

/* Number of bytes of storage in the program's representation
   for register regnum.  On the 68000, all regs are 4 bytes
   except the floating point regs which are 12-byte long doubles.  */

static int
m68k_register_virtual_size (int regnum)
{
  return (regnum >= FP0_REGNUM && regnum < FP0_REGNUM + 8 ? 12 : 4);
}

/* Return the GDB type object for the "standard" data type of data in
   register N.  This should be int for D0-D7, SR, FPCONTROL and
   FPSTATUS, long double for FP0-FP7, and void pointer for all others
   (A0-A7, PC, FPIADDR).  Note, for registers which contain
   addresses return pointer to void, not pointer to char, because we
   don't want to attempt to print the string after printing the
   address.  */

static struct type *
m68k_register_virtual_type (int regnum)
{
  if (regnum >= FP0_REGNUM && regnum <= FP0_REGNUM + 7)
    return builtin_type_m68881_ext;

  if (regnum == M68K_FPI_REGNUM || regnum == PC_REGNUM)
    return builtin_type_void_func_ptr;

  if (regnum == M68K_FPC_REGNUM || regnum == M68K_FPS_REGNUM
      || regnum == PS_REGNUM)
    return builtin_type_int32;

  if (regnum >= M68K_A0_REGNUM && regnum <= M68K_A0_REGNUM + 7)
    return builtin_type_void_data_ptr;

  return builtin_type_int32;
}

/* Function: m68k_register_name
   Returns the name of the standard m68k register regnum. */

static const char *
m68k_register_name (int regnum)
{
  static char *register_names[] = {
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
    "a0", "a1", "a2", "a3", "a4", "a5", "fp", "sp",
    "ps", "pc",
    "fp0", "fp1", "fp2", "fp3", "fp4", "fp5", "fp6", "fp7",
    "fpcontrol", "fpstatus", "fpiaddr", "fpcode", "fpflags"
  };

  if (regnum < 0 ||
      regnum >= sizeof (register_names) / sizeof (register_names[0]))
    internal_error (__FILE__, __LINE__,
		    "m68k_register_name: illegal register number %d", regnum);
  else
    return register_names[regnum];
}

/* Index within `registers' of the first byte of the space for
   register regnum.  */

static int
m68k_register_byte (int regnum)
{
  if (regnum >= M68K_FPC_REGNUM)
    return (((regnum - M68K_FPC_REGNUM) * 4) + 168);
  else if (regnum >= FP0_REGNUM)
    return (((regnum - FP0_REGNUM) * 12) + 72);
  else
    return (regnum * 4);
}

/* Store the address of the place in which to copy the structure the
   subroutine will return.  This is called from call_function. */

static void
m68k_store_struct_return (CORE_ADDR addr, CORE_ADDR sp)
{
  write_register (M68K_A1_REGNUM, addr);
}

/* Extract from an array regbuf containing the (raw) register state
   a function return value of type type, and copy that, in virtual format,
   into valbuf.  This is assuming that floating point values are returned
   as doubles in d0/d1.  */

static void
m68k_deprecated_extract_return_value (struct type *type, char *regbuf,
				      char *valbuf)
{
  int offset = 0;
  int typeLength = TYPE_LENGTH (type);

  if (typeLength < 4)
    offset = 4 - typeLength;

  memcpy (valbuf, regbuf + offset, typeLength);
}

static CORE_ADDR
m68k_deprecated_extract_struct_value_address (char *regbuf)
{
  return (*(CORE_ADDR *) (regbuf));
}

/* Write into appropriate registers a function return value
   of type TYPE, given in virtual format.  Assumes floats are passed
   in d0/d1.  */

static void
m68k_store_return_value (struct type *type, char *valbuf)
{
  deprecated_write_register_bytes (0, valbuf, TYPE_LENGTH (type));
}

/* Describe the pointer in each stack frame to the previous stack frame
   (its caller).  */

/* DEPRECATED_FRAME_CHAIN takes a frame's nominal address and produces
   the frame's chain-pointer.  In the case of the 68000, the frame's
   nominal address is the address of a 4-byte word containing the
   calling frame's address.  */

/* If we are chaining from sigtramp, then manufacture a sigtramp frame
   (which isn't really on the stack.  I'm not sure this is right for anything
   but BSD4.3 on an hp300.  */

static CORE_ADDR
m68k_frame_chain (struct frame_info *thisframe)
{
  if (get_frame_type (thisframe) == SIGTRAMP_FRAME)
    return get_frame_base (thisframe);
  else if (!inside_entry_file (get_frame_pc (thisframe)))
    return read_memory_unsigned_integer (get_frame_base (thisframe), 4);
  else
    return 0;
}

/* A function that tells us whether the function invocation represented
   by fi does not have a frame on the stack associated with it.  If it
   does not, FRAMELESS is set to 1, else 0.  */

static int
m68k_frameless_function_invocation (struct frame_info *fi)
{
  if (get_frame_type (fi) == SIGTRAMP_FRAME)
    return 0;
  else
    return frameless_look_for_prologue (fi);
}

static CORE_ADDR
m68k_frame_saved_pc (struct frame_info *frame)
{
  if (get_frame_type (frame) == SIGTRAMP_FRAME)
    {
      if (get_next_frame (frame))
	return read_memory_unsigned_integer (get_frame_base (get_next_frame (frame))
					     + SIG_PC_FP_OFFSET, 4);
      else
	return read_memory_unsigned_integer (read_register (SP_REGNUM)
					     + SIG_PC_FP_OFFSET - 8, 4);
    }
  else
    return read_memory_unsigned_integer (get_frame_base (frame) + 4, 4);
}


int
delta68_in_sigtramp (CORE_ADDR pc, char *name)
{
  if (name != NULL)
    return strcmp (name, "_sigcode") == 0;
  else
    return 0;
}

CORE_ADDR
delta68_frame_args_address (struct frame_info *frame_info)
{
  /* we assume here that the only frameless functions are the system calls
     or other functions who do not put anything on the stack. */
  if (get_frame_type (frame_info) == SIGTRAMP_FRAME)
    return get_frame_base (frame_info) + 12;
  else if (frameless_look_for_prologue (frame_info))
    {
      /* Check for an interrupted system call */
      if (get_next_frame (frame_info) && (get_frame_type (get_next_frame (frame_info)) == SIGTRAMP_FRAME))
	return get_frame_base (get_next_frame (frame_info)) + 16;
      else
	return get_frame_base (frame_info) + 4;
    }
  else
    return get_frame_base (frame_info);
}

CORE_ADDR
delta68_frame_saved_pc (struct frame_info *frame_info)
{
  return read_memory_unsigned_integer (delta68_frame_args_address (frame_info)
				       + 4, 4);
}

int
delta68_frame_num_args (struct frame_info *fi)
{
  int val;
  CORE_ADDR pc = DEPRECATED_FRAME_SAVED_PC (fi);
  int insn = read_memory_unsigned_integer (pc, 2);
  val = 0;
  if (insn == 0047757 || insn == 0157374)	/* lea W(sp),sp or addaw #W,sp */
    val = read_memory_integer (pc + 2, 2);
  else if ((insn & 0170777) == 0050217	/* addql #N, sp */
	   || (insn & 0170777) == 0050117)	/* addqw */
    {
      val = (insn >> 9) & 7;
      if (val == 0)
	val = 8;
    }
  else if (insn == 0157774)	/* addal #WW, sp */
    val = read_memory_integer (pc + 2, 4);
  val >>= 2;
  return val;
}

/* Insert the specified number of args and function address
   into a call sequence of the above form stored at DUMMYNAME.
   We use the BFD routines to store a big-endian value of known size.  */

static void
m68k_fix_call_dummy (char *dummy, CORE_ADDR pc, CORE_ADDR fun, int nargs,
		     struct value **args, struct type *type, int gcc_p)
{
  bfd_putb32 (fun, (unsigned char *) dummy + DEPRECATED_CALL_DUMMY_START_OFFSET + 2);
  bfd_putb32 (nargs * 4,
	      (unsigned char *) dummy + DEPRECATED_CALL_DUMMY_START_OFFSET + 8);
}


/* Push an empty stack frame, to record the current PC, etc.  */

static void
m68k_push_dummy_frame (void)
{
  register CORE_ADDR sp = read_register (SP_REGNUM);
  register int regnum;
  char raw_buffer[12];

  sp = push_word (sp, read_register (PC_REGNUM));
  sp = push_word (sp, read_register (DEPRECATED_FP_REGNUM));
  write_register (DEPRECATED_FP_REGNUM, sp);

  /* Always save the floating-point registers, whether they exist on
     this target or not.  */
  for (regnum = FP0_REGNUM + 7; regnum >= FP0_REGNUM; regnum--)
    {
      deprecated_read_register_bytes (REGISTER_BYTE (regnum), raw_buffer, 12);
      sp = push_bytes (sp, raw_buffer, 12);
    }

  for (regnum = DEPRECATED_FP_REGNUM - 1; regnum >= 0; regnum--)
    {
      sp = push_word (sp, read_register (regnum));
    }
  sp = push_word (sp, read_register (PS_REGNUM));
  write_register (SP_REGNUM, sp);
}

/* Discard from the stack the innermost frame,
   restoring all saved registers.  */

static void
m68k_pop_frame (void)
{
  register struct frame_info *frame = get_current_frame ();
  register CORE_ADDR fp;
  register int regnum;
  char raw_buffer[12];

  fp = get_frame_base (frame);
  m68k_frame_init_saved_regs (frame);
  for (regnum = FP0_REGNUM + 7; regnum >= FP0_REGNUM; regnum--)
    {
      if (get_frame_saved_regs (frame)[regnum])
	{
	  read_memory (get_frame_saved_regs (frame)[regnum], raw_buffer, 12);
	  deprecated_write_register_bytes (REGISTER_BYTE (regnum), raw_buffer,
					   12);
	}
    }
  for (regnum = DEPRECATED_FP_REGNUM - 1; regnum >= 0; regnum--)
    {
      if (get_frame_saved_regs (frame)[regnum])
	{
	  write_register (regnum,
			  read_memory_integer (get_frame_saved_regs (frame)[regnum], 4));
	}
    }
  if (get_frame_saved_regs (frame)[PS_REGNUM])
    {
      write_register (PS_REGNUM,
		      read_memory_integer (get_frame_saved_regs (frame)[PS_REGNUM], 4));
    }
  write_register (DEPRECATED_FP_REGNUM, read_memory_integer (fp, 4));
  write_register (PC_REGNUM, read_memory_integer (fp + 4, 4));
  write_register (SP_REGNUM, fp + 8);
  flush_cached_frames ();
}


/* Given an ip value corresponding to the start of a function,
   return the ip of the first instruction after the function 
   prologue.  This is the generic m68k support.  Machines which
   require something different can override the SKIP_PROLOGUE
   macro to point elsewhere.

   Some instructions which typically may appear in a function
   prologue include:

   A link instruction, word form:

   link.w       %a6,&0                  4e56  XXXX

   A link instruction, long form:

   link.l  %fp,&F%1             480e  XXXX  XXXX

   A movm instruction to preserve integer regs:

   movm.l  &M%1,(4,%sp)         48ef  XXXX  XXXX

   A fmovm instruction to preserve float regs:

   fmovm   &FPM%1,(FPO%1,%sp)   f237  XXXX  XXXX  XXXX  XXXX

   Some profiling setup code (FIXME, not recognized yet):

   lea.l   (.L3,%pc),%a1                43fb  XXXX  XXXX  XXXX
   bsr     _mcount                      61ff  XXXX  XXXX

 */

static CORE_ADDR
m68k_skip_prologue (CORE_ADDR ip)
{
  register CORE_ADDR limit;
  struct symtab_and_line sal;
  register int op;

  /* Find out if there is a known limit for the extent of the prologue.
     If so, ensure we don't go past it.  If not, assume "infinity". */

  sal = find_pc_line (ip, 0);
  limit = (sal.end) ? sal.end : (CORE_ADDR) ~0;

  while (ip < limit)
    {
      op = read_memory_unsigned_integer (ip, 2);

      if (op == P_LINKW_FP)
	ip += 4;		/* Skip link.w */
      else if (op == P_PEA_FP)
	ip += 2;		/* Skip pea %fp */
      else if (op == P_MOVL_SP_FP)
	ip += 2;		/* Skip move.l %sp, %fp */
      else if (op == P_LINKL_FP)
	ip += 6;		/* Skip link.l */
      else if (op == P_MOVML)
	ip += 6;		/* Skip movm.l */
      else if (op == P_FMOVM)
	ip += 10;		/* Skip fmovm */
      else
	break;			/* Found unknown code, bail out. */
    }
  return (ip);
}

/* Store the addresses of the saved registers of the frame described by 
   FRAME_INFO in its saved_regs field.
   This includes special registers such as pc and fp saved in special
   ways in the stack frame.  sp is even more special:
   the address we return for it IS the sp for the next frame.  */

static void
m68k_frame_init_saved_regs (struct frame_info *frame_info)
{
  register int regnum;
  register int regmask;
  register CORE_ADDR next_addr;
  register CORE_ADDR pc;

  /* First possible address for a pc in a call dummy for this frame.  */
  CORE_ADDR possible_call_dummy_start =
    get_frame_base (frame_info) - 28 - DEPRECATED_FP_REGNUM * 4 - 4 - 8 * 12;

  int nextinsn;

  if (get_frame_saved_regs (frame_info))
    return;

  frame_saved_regs_zalloc (frame_info);

  memset (get_frame_saved_regs (frame_info), 0, SIZEOF_FRAME_SAVED_REGS);

  if (get_frame_pc (frame_info) >= possible_call_dummy_start
      && get_frame_pc (frame_info) <= get_frame_base (frame_info))
    {

      /* It is a call dummy.  We could just stop now, since we know
         what the call dummy saves and where.  But this code proceeds
         to parse the "prologue" which is part of the call dummy.
         This is needlessly complex and confusing.  FIXME.  */

      next_addr = get_frame_base (frame_info);
      pc = possible_call_dummy_start;
    }
  else
    {
      pc = get_frame_func (frame_info);

      nextinsn = read_memory_unsigned_integer (pc, 2);
      if (P_PEA_FP == nextinsn
	  && P_MOVL_SP_FP == read_memory_unsigned_integer (pc + 2, 2))
	{
	  /* pea %fp
	     move.l %sp, %fp */
	  next_addr = get_frame_base (frame_info);
	  pc += 4;
	}
      else if (P_LINKL_FP == nextinsn)
	/* link.l %fp */
	/* Find the address above the saved   
	   regs using the amount of storage from the link instruction.  */
	{
	  next_addr = get_frame_base (frame_info) + read_memory_integer (pc + 2, 4);
	  pc += 6;
	}
      else if (P_LINKW_FP == nextinsn)
	/* link.w %fp */
	/* Find the address above the saved   
	   regs using the amount of storage from the link instruction.  */
	{
	  next_addr = get_frame_base (frame_info) + read_memory_integer (pc + 2, 2);
	  pc += 4;
	}
      else
	goto lose;

      /* If have an addal #-n, sp next, adjust next_addr.  */
      if (read_memory_unsigned_integer (pc, 2) == 0157774)
	next_addr += read_memory_integer (pc += 2, 4), pc += 4;
    }

  for (;;)
    {
      nextinsn = read_memory_unsigned_integer (pc, 2);
      regmask = read_memory_unsigned_integer (pc + 2, 2);
      /* fmovemx to -(sp) */
      if (0xf227 == nextinsn && (regmask & 0xff00) == 0xe000)
	{
	  /* Regmask's low bit is for register fp7, the first pushed */
	  for (regnum = FP0_REGNUM + 8; --regnum >= FP0_REGNUM; regmask >>= 1)
	    if (regmask & 1)
	      get_frame_saved_regs (frame_info)[regnum] = (next_addr -= 12);
	  pc += 4;
	}
      /* fmovemx to (fp + displacement) */
      else if (0171056 == nextinsn && (regmask & 0xff00) == 0xf000)
	{
	  register CORE_ADDR addr;

	  addr = get_frame_base (frame_info) + read_memory_integer (pc + 4, 2);
	  /* Regmask's low bit is for register fp7, the first pushed */
	  for (regnum = FP0_REGNUM + 8; --regnum >= FP0_REGNUM; regmask >>= 1)
	    if (regmask & 1)
	      {
		get_frame_saved_regs (frame_info)[regnum] = addr;
		addr += 12;
	      }
	  pc += 6;
	}
      /* moveml to (sp) */
      else if (0044327 == nextinsn)
	{
	  /* Regmask's low bit is for register 0, the first written */
	  for (regnum = 0; regnum < 16; regnum++, regmask >>= 1)
	    if (regmask & 1)
	      {
		get_frame_saved_regs (frame_info)[regnum] = next_addr;
		next_addr += 4;
	      }
	  pc += 4;
	}
      /* moveml to (fp + displacement) */
      else if (0044356 == nextinsn)
	{
	  register CORE_ADDR addr;

	  addr = get_frame_base (frame_info) + read_memory_integer (pc + 4, 2);
	  /* Regmask's low bit is for register 0, the first written */
	  for (regnum = 0; regnum < 16; regnum++, regmask >>= 1)
	    if (regmask & 1)
	      {
		get_frame_saved_regs (frame_info)[regnum] = addr;
		addr += 4;
	      }
	  pc += 6;
	}
      /* moveml to -(sp) */
      else if (0044347 == nextinsn)
	{
	  /* Regmask's low bit is for register 15, the first pushed */
	  for (regnum = 16; --regnum >= 0; regmask >>= 1)
	    if (regmask & 1)
	      get_frame_saved_regs (frame_info)[regnum] = (next_addr -= 4);
	  pc += 4;
	}
      /* movl r,-(sp) */
      else if (0x2f00 == (0xfff0 & nextinsn))
	{
	  regnum = 0xf & nextinsn;
	  get_frame_saved_regs (frame_info)[regnum] = (next_addr -= 4);
	  pc += 2;
	}
      /* fmovemx to index of sp */
      else if (0xf236 == nextinsn && (regmask & 0xff00) == 0xf000)
	{
	  /* Regmask's low bit is for register fp0, the first written */
	  for (regnum = FP0_REGNUM + 8; --regnum >= FP0_REGNUM; regmask >>= 1)
	    if (regmask & 1)
	      {
		get_frame_saved_regs (frame_info)[regnum] = next_addr;
		next_addr += 12;
	      }
	  pc += 10;
	}
      /* clrw -(sp); movw ccr,-(sp) */
      else if (0x4267 == nextinsn && 0x42e7 == regmask)
	{
	  get_frame_saved_regs (frame_info)[PS_REGNUM] = (next_addr -= 4);
	  pc += 4;
	}
      else
	break;
    }
lose:;
  get_frame_saved_regs (frame_info)[SP_REGNUM] = get_frame_base (frame_info) + 8;
  get_frame_saved_regs (frame_info)[DEPRECATED_FP_REGNUM] = get_frame_base (frame_info);
  get_frame_saved_regs (frame_info)[PC_REGNUM] = get_frame_base (frame_info) + 4;
#ifdef SIG_SP_FP_OFFSET
  /* Adjust saved SP_REGNUM for fake _sigtramp frames.  */
  if ((get_frame_type (frame_info) == SIGTRAMP_FRAME) && frame_info->next)
    frame_info->saved_regs[SP_REGNUM] =
      frame_info->next->frame + SIG_SP_FP_OFFSET;
#endif
}


#ifdef USE_PROC_FS		/* Target dependent support for /proc */

#include <sys/procfs.h>

/* Prototypes for supply_gregset etc. */
#include "gregset.h"

/*  The /proc interface divides the target machine's register set up into
   two different sets, the general register set (gregset) and the floating
   point register set (fpregset).  For each set, there is an ioctl to get
   the current register set and another ioctl to set the current values.

   The actual structure passed through the ioctl interface is, of course,
   naturally machine dependent, and is different for each set of registers.
   For the m68k for example, the general register set is typically defined
   by:

   typedef int gregset_t[18];

   #define      R_D0    0
   ...
   #define      R_PS    17

   and the floating point set by:

   typedef      struct fpregset {
   int  f_pcr;
   int  f_psr;
   int  f_fpiaddr;
   int  f_fpregs[8][3];         (8 regs, 96 bits each)
   } fpregset_t;

   These routines provide the packing and unpacking of gregset_t and
   fpregset_t formatted data.

 */

/* Atari SVR4 has R_SR but not R_PS */

#if !defined (R_PS) && defined (R_SR)
#define R_PS R_SR
#endif

/*  Given a pointer to a general register set in /proc format (gregset_t *),
   unpack the register contents and supply them as gdb's idea of the current
   register values. */

void
supply_gregset (gregset_t *gregsetp)
{
  register int regi;
  register greg_t *regp = (greg_t *) gregsetp;

  for (regi = 0; regi < R_PC; regi++)
    {
      supply_register (regi, (char *) (regp + regi));
    }
  supply_register (PS_REGNUM, (char *) (regp + R_PS));
  supply_register (PC_REGNUM, (char *) (regp + R_PC));
}

void
fill_gregset (gregset_t *gregsetp, int regno)
{
  register int regi;
  register greg_t *regp = (greg_t *) gregsetp;

  for (regi = 0; regi < R_PC; regi++)
    {
      if ((regno == -1) || (regno == regi))
	{
	  *(regp + regi) = *(int *) &deprecated_registers[REGISTER_BYTE (regi)];
	}
    }
  if ((regno == -1) || (regno == PS_REGNUM))
    {
      *(regp + R_PS) = *(int *) &deprecated_registers[REGISTER_BYTE (PS_REGNUM)];
    }
  if ((regno == -1) || (regno == PC_REGNUM))
    {
      *(regp + R_PC) = *(int *) &deprecated_registers[REGISTER_BYTE (PC_REGNUM)];
    }
}

#if defined (FP0_REGNUM)

/*  Given a pointer to a floating point register set in /proc format
   (fpregset_t *), unpack the register contents and supply them as gdb's
   idea of the current floating point register values. */

void
supply_fpregset (fpregset_t *fpregsetp)
{
  register int regi;
  char *from;

  for (regi = FP0_REGNUM; regi < M68K_FPC_REGNUM; regi++)
    {
      from = (char *) &(fpregsetp->f_fpregs[regi - FP0_REGNUM][0]);
      supply_register (regi, from);
    }
  supply_register (M68K_FPC_REGNUM, (char *) &(fpregsetp->f_pcr));
  supply_register (M68K_FPS_REGNUM, (char *) &(fpregsetp->f_psr));
  supply_register (M68K_FPI_REGNUM, (char *) &(fpregsetp->f_fpiaddr));
}

/*  Given a pointer to a floating point register set in /proc format
   (fpregset_t *), update the register specified by REGNO from gdb's idea
   of the current floating point register set.  If REGNO is -1, update
   them all. */

void
fill_fpregset (fpregset_t *fpregsetp, int regno)
{
  int regi;
  char *to;
  char *from;

  for (regi = FP0_REGNUM; regi < M68K_FPC_REGNUM; regi++)
    {
      if ((regno == -1) || (regno == regi))
	{
	  from = (char *) &deprecated_registers[REGISTER_BYTE (regi)];
	  to = (char *) &(fpregsetp->f_fpregs[regi - FP0_REGNUM][0]);
	  memcpy (to, from, REGISTER_RAW_SIZE (regi));
	}
    }
  if ((regno == -1) || (regno == M68K_FPC_REGNUM))
    {
      fpregsetp->f_pcr = *(int *) &deprecated_registers[REGISTER_BYTE (M68K_FPC_REGNUM)];
    }
  if ((regno == -1) || (regno == M68K_FPS_REGNUM))
    {
      fpregsetp->f_psr = *(int *) &deprecated_registers[REGISTER_BYTE (M68K_FPS_REGNUM)];
    }
  if ((regno == -1) || (regno == M68K_FPI_REGNUM))
    {
      fpregsetp->f_fpiaddr = *(int *) &deprecated_registers[REGISTER_BYTE (M68K_FPI_REGNUM)];
    }
}

#endif /* defined (FP0_REGNUM) */

#endif /* USE_PROC_FS */

/* Figure out where the longjmp will land.  Slurp the args out of the stack.
   We expect the first arg to be a pointer to the jmp_buf structure from which
   we extract the pc (JB_PC) that we will land at.  The pc is copied into PC.
   This routine returns true on success. */

int
m68k_get_longjmp_target (CORE_ADDR *pc)
{
  char *buf;
  CORE_ADDR sp, jb_addr;
  struct gdbarch_tdep *tdep = gdbarch_tdep (current_gdbarch);

  if (tdep->jb_pc < 0)
    {
      internal_error (__FILE__, __LINE__,
		      "m68k_get_longjmp_target: not implemented");
      return 0;
    }

  buf = alloca (TARGET_PTR_BIT / TARGET_CHAR_BIT);
  sp = read_register (SP_REGNUM);

  if (target_read_memory (sp + SP_ARG0,	/* Offset of first arg on stack */
			  buf, TARGET_PTR_BIT / TARGET_CHAR_BIT))
    return 0;

  jb_addr = extract_unsigned_integer (buf, TARGET_PTR_BIT / TARGET_CHAR_BIT);

  if (target_read_memory (jb_addr + tdep->jb_pc * tdep->jb_elt_size, buf,
			  TARGET_PTR_BIT / TARGET_CHAR_BIT))
    return 0;

  *pc = extract_unsigned_integer (buf, TARGET_PTR_BIT / TARGET_CHAR_BIT);
  return 1;
}

/* Immediately after a function call, return the saved pc before the frame
   is setup.  For sun3's, we check for the common case of being inside of a
   system call, and if so, we know that Sun pushes the call # on the stack
   prior to doing the trap. */

static CORE_ADDR
m68k_saved_pc_after_call (struct frame_info *frame)
{
#ifdef SYSCALL_TRAP
  int op;

  op = read_memory_unsigned_integer (frame->pc - SYSCALL_TRAP_OFFSET, 2);

  if (op == SYSCALL_TRAP)
    return read_memory_unsigned_integer (read_register (SP_REGNUM) + 4, 4);
  else
#endif /* SYSCALL_TRAP */
    return read_memory_unsigned_integer (read_register (SP_REGNUM), 4);
}

/* Function: m68k_gdbarch_init
   Initializer function for the m68k gdbarch vector.
   Called by gdbarch.  Sets up the gdbarch vector(s) for this target. */

static struct gdbarch *
m68k_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  static LONGEST call_dummy_words[7] = { 0xf227e0ff, 0x48e7fffc, 0x426742e7,
    0x4eb93232, 0x3232dffc, 0x69696969,
    (0x4e404e71 | (BPT_VECTOR << 16))
  };
  struct gdbarch_tdep *tdep = NULL;
  struct gdbarch *gdbarch;

  /* find a candidate among the list of pre-declared architectures. */
  arches = gdbarch_list_lookup_by_info (arches, &info);
  if (arches != NULL)
    return (arches->gdbarch);

  tdep = xmalloc (sizeof (struct gdbarch_tdep));
  gdbarch = gdbarch_alloc (&info, tdep);

  /* NOTE: cagney/2002-12-06: This can be deleted when this arch is
     ready to unwind the PC first (see frame.c:get_prev_frame()).  */
  set_gdbarch_deprecated_init_frame_pc (gdbarch, init_frame_pc_default);

  set_gdbarch_long_double_format (gdbarch, &floatformat_m68881_ext);
  set_gdbarch_long_double_bit (gdbarch, 96);

  set_gdbarch_function_start_offset (gdbarch, 0);

  set_gdbarch_skip_prologue (gdbarch, m68k_skip_prologue);
  set_gdbarch_deprecated_saved_pc_after_call (gdbarch, m68k_saved_pc_after_call);
  set_gdbarch_breakpoint_from_pc (gdbarch, m68k_local_breakpoint_from_pc);

  /* Stack grows down. */
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);
  set_gdbarch_parm_boundary (gdbarch, 32);

  set_gdbarch_believe_pcc_promotion (gdbarch, 1);
  set_gdbarch_decr_pc_after_break (gdbarch, 2);

  set_gdbarch_deprecated_store_struct_return (gdbarch, m68k_store_struct_return);
  set_gdbarch_deprecated_extract_return_value (gdbarch,
					       m68k_deprecated_extract_return_value);
  set_gdbarch_deprecated_store_return_value (gdbarch, m68k_store_return_value);

  set_gdbarch_deprecated_frame_chain (gdbarch, m68k_frame_chain);
  set_gdbarch_deprecated_frame_saved_pc (gdbarch, m68k_frame_saved_pc);
  set_gdbarch_deprecated_frame_init_saved_regs (gdbarch, m68k_frame_init_saved_regs);
  set_gdbarch_frameless_function_invocation (gdbarch,
					     m68k_frameless_function_invocation);
  set_gdbarch_frame_args_skip (gdbarch, 8);

  set_gdbarch_register_raw_size (gdbarch, m68k_register_raw_size);
  set_gdbarch_register_virtual_size (gdbarch, m68k_register_virtual_size);
  set_gdbarch_deprecated_max_register_raw_size (gdbarch, 12);
  set_gdbarch_deprecated_max_register_virtual_size (gdbarch, 12);
  set_gdbarch_register_virtual_type (gdbarch, m68k_register_virtual_type);
  set_gdbarch_register_name (gdbarch, m68k_register_name);
  set_gdbarch_deprecated_register_size (gdbarch, 4);
  set_gdbarch_register_byte (gdbarch, m68k_register_byte);
  set_gdbarch_num_regs (gdbarch, 29);
  set_gdbarch_register_bytes_ok (gdbarch, m68k_register_bytes_ok);
  set_gdbarch_deprecated_register_bytes (gdbarch, (16 * 4 + 8 + 8 * 12 + 3 * 4));
  set_gdbarch_sp_regnum (gdbarch, M68K_SP_REGNUM);
  set_gdbarch_deprecated_fp_regnum (gdbarch, M68K_FP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, M68K_PC_REGNUM);
  set_gdbarch_ps_regnum (gdbarch, M68K_PS_REGNUM);
  set_gdbarch_fp0_regnum (gdbarch, M68K_FP0_REGNUM);

  set_gdbarch_deprecated_use_generic_dummy_frames (gdbarch, 0);
  set_gdbarch_call_dummy_location (gdbarch, ON_STACK);
  set_gdbarch_deprecated_call_dummy_breakpoint_offset (gdbarch, 24);
  set_gdbarch_deprecated_pc_in_call_dummy (gdbarch, deprecated_pc_in_call_dummy_on_stack);
  set_gdbarch_deprecated_call_dummy_length (gdbarch, 28);
  set_gdbarch_deprecated_call_dummy_start_offset (gdbarch, 12);

  set_gdbarch_deprecated_call_dummy_words (gdbarch, call_dummy_words);
  set_gdbarch_deprecated_sizeof_call_dummy_words (gdbarch, sizeof (call_dummy_words));
  set_gdbarch_deprecated_fix_call_dummy (gdbarch, m68k_fix_call_dummy);
  set_gdbarch_deprecated_push_dummy_frame (gdbarch, m68k_push_dummy_frame);
  set_gdbarch_deprecated_pop_frame (gdbarch, m68k_pop_frame);

  /* Should be using push_dummy_call.  */
  set_gdbarch_deprecated_dummy_write_sp (gdbarch, deprecated_write_sp);

  /* Disassembler.  */
  set_gdbarch_print_insn (gdbarch, print_insn_m68k);

#if defined JB_PC && defined JB_ELEMENT_SIZE
  tdep->jb_pc = JB_PC;
  tdep->jb_elt_size = JB_ELEMENT_SIZE;
#else
  tdep->jb_pc = -1;
#endif

  /* Hook in ABI-specific overrides, if they have been registered.  */
  gdbarch_init_osabi (info, gdbarch);

  /* Now we have tuned the configuration, set a few final things,
     based on what the OS ABI has told us.  */

  if (tdep->jb_pc >= 0)
    set_gdbarch_get_longjmp_target (gdbarch, m68k_get_longjmp_target);

  return gdbarch;
}


static void
m68k_dump_tdep (struct gdbarch *current_gdbarch, struct ui_file *file)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (current_gdbarch);

  if (tdep == NULL)
    return;
}

extern initialize_file_ftype _initialize_m68k_tdep; /* -Wmissing-prototypes */

void
_initialize_m68k_tdep (void)
{
  gdbarch_register (bfd_arch_m68k, m68k_gdbarch_init, m68k_dump_tdep);
}
