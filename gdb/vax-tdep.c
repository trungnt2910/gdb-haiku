/* Print VAX instructions for GDB, the GNU debugger.
   Copyright 1986, 1989, 1991, 1992, 1995, 1996, 1998, 1999, 2000, 2002
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
#include "symtab.h"
#include "opcode/vax.h"
#include "gdbcore.h"
#include "frame.h"
#include "value.h"

/* Return 1 if P points to an invalid floating point value.
   LEN is the length in bytes -- not relevant on the Vax.  */

/* FIXME: cagney/2002-01-19: The macro below was originally defined in
   tm-vax.h and used in values.c.  Two problems.  Firstly this is a
   very non-portable and secondly it is wrong.  The VAX should be
   using floatformat and associated methods to identify and handle
   invalid floating-point values.  Adding to the poor target's woes
   there is no floatformat_vax_{f,d} and no TARGET_FLOAT_FORMAT
   et.al..  */

/* FIXME: cagney/2002-01-19: It turns out that the only thing that
   uses this macro is the vax disassembler code (so how old is this
   target?).  This target should instead be using the opcodes
   disassembler.  That allowing the macro to be eliminated.  */

#define INVALID_FLOAT(p, len) ((*(short *) p & 0xff80) == 0x8000)

/* Vax instructions are never longer than this.  */
#define MAXLEN 62

/* Number of elements in the opcode table.  */
#define NOPCODES (sizeof votstrs / sizeof votstrs[0])

static unsigned char *print_insn_arg ();

char *
vax_register_name (int regno)
{
  static char *register_names[] =
  {
    "r0",  "r1",  "r2",  "r3", "r4", "r5", "r6", "r7",
    "r8",  "r9", "r10", "r11", "ap", "fp", "sp", "pc",
    "ps",
  };

  if (regno < 0)
    return (NULL);
  if (regno >= (sizeof(register_names) / sizeof(*register_names)))
    return (NULL);
  return (register_names[regno]);
}

int
vax_register_byte (int regno)
{
  return (regno * 4);
}

int
vax_register_raw_size (int regno)
{
  return (4);
}

int
vax_register_virtual_size (int regno)
{
  return (4);
}

struct type *
vax_register_virtual_type (int regno)
{
  return (builtin_type_int);
}

void
vax_frame_init_saved_regs (struct frame_info *frame)
{
  int regnum, regmask;
  CORE_ADDR next_addr;

  if (frame->saved_regs)
    return;

  frame_saved_regs_zalloc (frame);

  regmask = read_memory_integer (frame->frame + 4, 4) >> 16;

  next_addr = frame->frame + 16;

  /* regmask's low bit is for register 0, which is the first one
     what would be pushed.  */
  for (regnum = 0; regnum < AP_REGNUM; regnum++)
    {
      if (regmask & (1 << regnum))
        frame->saved_regs[regnum] = next_addr += 4;
    }

  frame->saved_regs[SP_REGNUM] = next_addr + 4;
  if (regmask & (1 << FP_REGNUM))
    frame->saved_regs[SP_REGNUM] +=
      4 + (4 * read_memory_integer (next_addr + 4, 4));

  frame->saved_regs[PC_REGNUM] = frame->frame + 16;
  frame->saved_regs[FP_REGNUM] = frame->frame + 12;
  frame->saved_regs[AP_REGNUM] = frame->frame + 8;
  frame->saved_regs[PS_REGNUM] = frame->frame + 4;
}

CORE_ADDR
vax_frame_saved_pc (struct frame_info *frame)
{
  if (frame->signal_handler_caller)
    return (sigtramp_saved_pc (frame)); /* XXXJRT */

  return (read_memory_integer (frame->frame + 16, 4));
}

CORE_ADDR
vax_frame_args_address_correct (struct frame_info *frame)
{
  /* Cannot find the AP register value directly from the FP value.  Must
     find it saved in the frame called by this one, or in the AP register
     for the innermost frame.  However, there is no way to tell the
     difference between the innermost frame and a frame for which we
     just don't know the frame that it called (e.g. "info frame 0x7ffec789").
     For the sake of argument, suppose that the stack is somewhat trashed
     (which is one reason that "info frame" exists).  So, return 0 (indicating
     we don't know the address of the arglist) if we don't know what frame
     this frame calls.  */
  if (frame->next)
    return (read_memory_integer (frame->next->frame + 8, 4));

  return (0);
}

CORE_ADDR
vax_frame_args_address (struct frame_info *frame)
{
  /* In most of GDB, getting the args address is too important to
     just say "I don't know".  This is sometimes wrong for functions
     that aren't on top of the stack, but c'est la vie.  */
  if (frame->next)
    return (read_memory_integer (frame->next->frame + 8, 4));

  return (read_register (AP_REGNUM));
}

CORE_ADDR
vax_frame_locals_address (struct frame_info *frame)
{
  return (frame->frame);
}

int
vax_frame_num_args (struct frame_info *fi)
{
  return (0xff & read_memory_integer (FRAME_ARGS_ADDRESS (fi), 1));
}

CORE_ADDR
vax_frame_chain (struct frame_info *frame)
{
  /* In the case of the VAX, the frame's nominal address is the FP value,
     and 12 bytes later comes the saved previous FP value as a 4-byte word.  */
  if (inside_entry_file (frame->pc))
    return (0);

  return (read_memory_integer (frame->frame + 12, 4));
}

void
vax_push_dummy_frame (void)
{
  CORE_ADDR sp = read_register (SP_REGNUM);
  int regnum;

  sp = push_word (sp, 0);	/* arglist */
  for (regnum = 11; regnum >= 0; regnum--)
    sp = push_word (sp, read_register (regnum));
  sp = push_word (sp, read_register (PC_REGNUM));
  sp = push_word (sp, read_register (FP_REGNUM));
  sp = push_word (sp, read_register (AP_REGNUM));
  sp = push_word (sp, (read_register (PS_REGNUM) & 0xffef) + 0x2fff0000);
  sp = push_word (sp, 0);
  write_register (SP_REGNUM, sp);
  write_register (FP_REGNUM, sp);
  write_register (AP_REGNUM, sp + (17 * 4));
}

void
vax_pop_frame (void)
{
  CORE_ADDR fp = read_register (FP_REGNUM);
  int regnum;
  int regmask = read_memory_integer (fp + 4, 4);

  write_register (PS_REGNUM,
		  (regmask & 0xffff)
		  | (read_register (PS_REGNUM) & 0xffff0000));
  write_register (PC_REGNUM, read_memory_integer (fp + 16, 4));
  write_register (FP_REGNUM, read_memory_integer (fp + 12, 4));
  write_register (AP_REGNUM, read_memory_integer (fp + 8, 4));
  fp += 16;
  for (regnum = 0; regnum < 12; regnum++)
    if (regmask & (0x10000 << regnum))
      write_register (regnum, read_memory_integer (fp += 4, 4));
  fp = fp + 4 + ((regmask >> 30) & 3);
  if (regmask & 0x20000000)
    {
      regnum = read_memory_integer (fp, 4);
      fp += (regnum + 1) * 4;
    }
  write_register (SP_REGNUM, fp);
  flush_cached_frames ();
}

void
vax_store_struct_return (CORE_ADDR addr, CORE_ADDR sp)
{
  write_register (1, addr);
}

void
vax_extract_return_value (struct type *valtype, char *regbuf, char *valbuf)
{
  memcpy (valbuf, regbuf + REGISTER_BYTE (0), TYPE_LENGTH (valtype));
}

void
vax_store_return_value (struct type *valtype, char *valbuf)
{
  write_register_bytes (0, valbuf, TYPE_LENGTH (valtype));
}

CORE_ADDR
vax_extract_struct_value_address (char *regbuf)
{
  return (extract_address (regbuf + REGISTER_BYTE (0), REGISTER_RAW_SIZE (0)));
}

/* Advance PC across any function entry prologue instructions
   to reach some "real" code.  */

CORE_ADDR
vax_skip_prologue (CORE_ADDR pc)
{
  register int op = (unsigned char) read_memory_integer (pc, 1);
  if (op == 0x11)
    pc += 2;			/* skip brb */
  if (op == 0x31)
    pc += 3;			/* skip brw */
  if (op == 0xC2
      && ((unsigned char) read_memory_integer (pc + 2, 1)) == 0x5E)
    pc += 3;			/* skip subl2 */
  if (op == 0x9E
      && ((unsigned char) read_memory_integer (pc + 1, 1)) == 0xAE
      && ((unsigned char) read_memory_integer (pc + 3, 1)) == 0x5E)
    pc += 4;			/* skip movab */
  if (op == 0x9E
      && ((unsigned char) read_memory_integer (pc + 1, 1)) == 0xCE
      && ((unsigned char) read_memory_integer (pc + 4, 1)) == 0x5E)
    pc += 5;			/* skip movab */
  if (op == 0x9E
      && ((unsigned char) read_memory_integer (pc + 1, 1)) == 0xEE
      && ((unsigned char) read_memory_integer (pc + 6, 1)) == 0x5E)
    pc += 7;			/* skip movab */
  return pc;
}


/* Print the vax instruction at address MEMADDR in debugged memory,
   from disassembler info INFO.
   Returns length of the instruction, in bytes.  */

static int
vax_print_insn (CORE_ADDR memaddr, disassemble_info *info)
{
  unsigned char buffer[MAXLEN];
  register int i;
  register unsigned char *p;
  const char *d;

  int status = (*info->read_memory_func) (memaddr, buffer, MAXLEN, info);
  if (status != 0)
    {
      (*info->memory_error_func) (status, memaddr, info);
      return -1;
    }

  for (i = 0; i < NOPCODES; i++)
    if (votstrs[i].detail.code == buffer[0]
	|| votstrs[i].detail.code == *(unsigned short *) buffer)
      break;

  /* Handle undefined instructions.  */
  if (i == NOPCODES)
    {
      (*info->fprintf_func) (info->stream, "0%o", buffer[0]);
      return 1;
    }

  (*info->fprintf_func) (info->stream, "%s", votstrs[i].name);

  /* Point at first byte of argument data,
     and at descriptor for first argument.  */
  p = buffer + 1 + (votstrs[i].detail.code >= 0x100);
  d = votstrs[i].detail.args;

  if (*d)
    (*info->fprintf_func) (info->stream, " ");

  while (*d)
    {
      p = print_insn_arg (d, p, memaddr + (p - buffer), info);
      d += 2;
      if (*d)
	(*info->fprintf_func) (info->stream, ",");
    }
  return p - buffer;
}

static unsigned char *
print_insn_arg (char *d, register char *p, CORE_ADDR addr,
		disassemble_info *info)
{
  register int regnum = *p & 0xf;
  float floatlitbuf;

  if (*d == 'b')
    {
      if (d[1] == 'b')
	(*info->fprintf_func) (info->stream, "0x%x", addr + *p++ + 1);
      else
	{
	  (*info->fprintf_func) (info->stream, "0x%x", addr + *(short *) p + 2);
	  p += 2;
	}
    }
  else
    switch ((*p++ >> 4) & 0xf)
      {
      case 0:
      case 1:
      case 2:
      case 3:			/* Literal mode */
	if (d[1] == 'd' || d[1] == 'f' || d[1] == 'g' || d[1] == 'h')
	  {
	    *(int *) &floatlitbuf = 0x4000 + ((p[-1] & 0x3f) << 4);
	    (*info->fprintf_func) (info->stream, "$%f", floatlitbuf);
	  }
	else
	  (*info->fprintf_func) (info->stream, "$%d", p[-1] & 0x3f);
	break;

      case 4:			/* Indexed */
	p = (char *) print_insn_arg (d, p, addr + 1, info);
	(*info->fprintf_func) (info->stream, "[%s]", REGISTER_NAME (regnum));
	break;

      case 5:			/* Register */
	(*info->fprintf_func) (info->stream, REGISTER_NAME (regnum));
	break;

      case 7:			/* Autodecrement */
	(*info->fprintf_func) (info->stream, "-");
      case 6:			/* Register deferred */
	(*info->fprintf_func) (info->stream, "(%s)", REGISTER_NAME (regnum));
	break;

      case 9:			/* Autoincrement deferred */
	(*info->fprintf_func) (info->stream, "@");
	if (regnum == PC_REGNUM)
	  {
	    (*info->fprintf_func) (info->stream, "#");
	    info->target = *(long *) p;
	    (*info->print_address_func) (info->target, info);
	    p += 4;
	    break;
	  }
      case 8:			/* Autoincrement */
	if (regnum == PC_REGNUM)
	  {
	    (*info->fprintf_func) (info->stream, "#");
	    switch (d[1])
	      {
	      case 'b':
		(*info->fprintf_func) (info->stream, "%d", *p++);
		break;

	      case 'w':
		(*info->fprintf_func) (info->stream, "%d", *(short *) p);
		p += 2;
		break;

	      case 'l':
		(*info->fprintf_func) (info->stream, "%d", *(long *) p);
		p += 4;
		break;

	      case 'q':
		(*info->fprintf_func) (info->stream, "0x%x%08x",
				       ((long *) p)[1], ((long *) p)[0]);
		p += 8;
		break;

	      case 'o':
		(*info->fprintf_func) (info->stream, "0x%x%08x%08x%08x",
				       ((long *) p)[3], ((long *) p)[2],
				       ((long *) p)[1], ((long *) p)[0]);
		p += 16;
		break;

	      case 'f':
		if (INVALID_FLOAT (p, 4))
		  (*info->fprintf_func) (info->stream,
					 "<<invalid float 0x%x>>",
					 *(int *) p);
		else
		  (*info->fprintf_func) (info->stream, "%f", *(float *) p);
		p += 4;
		break;

	      case 'd':
		if (INVALID_FLOAT (p, 8))
		  (*info->fprintf_func) (info->stream,
					 "<<invalid float 0x%x%08x>>",
					 ((long *) p)[1], ((long *) p)[0]);
		else
		  (*info->fprintf_func) (info->stream, "%f", *(double *) p);
		p += 8;
		break;

	      case 'g':
		(*info->fprintf_func) (info->stream, "g-float");
		p += 8;
		break;

	      case 'h':
		(*info->fprintf_func) (info->stream, "h-float");
		p += 16;
		break;

	      }
	  }
	else
	  (*info->fprintf_func) (info->stream, "(%s)+", REGISTER_NAME (regnum));
	break;

      case 11:			/* Byte displacement deferred */
	(*info->fprintf_func) (info->stream, "@");
      case 10:			/* Byte displacement */
	if (regnum == PC_REGNUM)
	  {
	    info->target = addr + *p + 2;
	    (*info->print_address_func) (info->target, info);
	  }
	else
	  (*info->fprintf_func) (info->stream, "%d(%s)", *p, REGISTER_NAME (regnum));
	p += 1;
	break;

      case 13:			/* Word displacement deferred */
	(*info->fprintf_func) (info->stream, "@");
      case 12:			/* Word displacement */
	if (regnum == PC_REGNUM)
	  {
	    info->target = addr + *(short *) p + 3;
	    (*info->print_address_func) (info->target, info);
	  }
	else
	  (*info->fprintf_func) (info->stream, "%d(%s)",
				 *(short *) p, REGISTER_NAME (regnum));
	p += 2;
	break;

      case 15:			/* Long displacement deferred */
	(*info->fprintf_func) (info->stream, "@");
      case 14:			/* Long displacement */
	if (regnum == PC_REGNUM)
	  {
	    info->target = addr + *(short *) p + 5;
	    (*info->print_address_func) (info->target, info);
	  }
	else
	  (*info->fprintf_func) (info->stream, "%d(%s)",
				 *(long *) p, REGISTER_NAME (regnum));
	p += 4;
      }

  return (unsigned char *) p;
}

void
_initialize_vax_tdep (void)
{
  tm_print_insn = vax_print_insn;
}
