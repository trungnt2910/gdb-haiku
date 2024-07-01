/* Target-dependent code for Haiku/amd64.

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

#include "amd64-tdep.h"
#include "extract-store-integer.h"
#include "haiku-tdep.h"
#include "solib.h"

static int
amd64_haiku_sigtramp_p (const frame_info_ptr &this_frame)
{
  CORE_ADDR pc = get_frame_pc (this_frame);
  const char *solib_name
      = solib_name_from_address (get_frame_program_space (this_frame), pc);

  if (solib_name == nullptr || strcmp (solib_name, "commpage") != 0)
    return false;

  const char *name;
  find_pc_partial_function (pc, &name, NULL, NULL);

  if (name == nullptr || strcmp (name, "commpage_signal_handler") != 0)
    return false;

  return true;
}

/* Offset to mcontext_t in signal_frame_data,
   from headers/private/kernel/ksignal.h.

   The struct is private so it may change anytime.
   However, the first two members of the struct are siginfo_t and ucontext_t,
   which are public and relatively stable.  */
#define AMD64_HAIKU_SIGNAL_FRAME_DATA_MCONTEXT_OFFSET 96

static CORE_ADDR
amd64_haiku_sigcontext_addr (const frame_info_ptr &this_frame)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR bp;
  gdb_byte buf[8];

  get_frame_register (this_frame, AMD64_RBP_REGNUM, buf);
  bp = extract_unsigned_integer (buf, 8, byte_order);

  /* Layout of the stack before function call:
     - signal_frame_data
     - frame->ip (8 bytes)
     - frame->bp (8 bytes). Not written by the kernel,
       but the signal handler has a "push %rbp" instruction.  */
  return bp + 8 + 8 + AMD64_HAIKU_SIGNAL_FRAME_DATA_MCONTEXT_OFFSET;
}

/* From struct vregs at arch/x86_64/signal.h.  */
static int amd64_haiku_sc_reg_offset[] = {
  0 * 8,  /* %rax */
  1 * 8,  /* %rbx */
  2 * 8,  /* %rcx */
  3 * 8,  /* %rdx */
  5 * 8,  /* %rsi */
  4 * 8,  /* %rdi */
  6 * 8,  /* %rbp */
  15 * 8, /* %rsp */
  7 * 8,  /* %r8 */
  8 * 8,  /* %r9 */
  9 * 8,  /* %r10 */
  10 * 8, /* %r11 */
  11 * 8, /* %r12 */
  12 * 8, /* %r13 */
  13 * 8, /* %r14 */
  14 * 8, /* %r15 */
  16 * 8, /* %rip */
  17 * 8, /* %eflags */

  -1, /* %cs */
  -1, /* %ss */
  -1, /* %ds */
  -1, /* %es */
  -1, /* %fs */
  -1  /* %gs */
};

static void
amd64_haiku_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  i386_gdbarch_tdep *tdep = gdbarch_tdep<i386_gdbarch_tdep> (gdbarch);

  amd64_init_abi (info, gdbarch,
                  amd64_target_description (X86_XSTATE_SSE_MASK, true));
  haiku_init_abi (info, gdbarch);

  tdep->sigtramp_p = amd64_haiku_sigtramp_p;
  tdep->sigcontext_addr = amd64_haiku_sigcontext_addr;
  tdep->sc_reg_offset = amd64_haiku_sc_reg_offset;
  tdep->sc_num_regs = ARRAY_SIZE (amd64_haiku_sc_reg_offset);

  /* The offset of the PC in the jmp_buf structure.
     Found at src/system/libroot/posix/arch/x86_64/setjmp_internal.h.  */
  tdep->jb_pc_offset = 0;
}

static enum gdb_osabi
amd64_haiku_osabi_sniffer (bfd *abfd)
{
  const char *target_name = bfd_get_target (abfd);

  if (strcmp (target_name, "elf64-x86-64") != 0)
    return GDB_OSABI_UNKNOWN;

  if (!haiku_check_required_symbols (abfd))
    return GDB_OSABI_UNKNOWN;

  return GDB_OSABI_HAIKU;
}

void _initialize_amd64_haiku_tdep ();
void
_initialize_amd64_haiku_tdep ()
{
  gdbarch_register_osabi_sniffer (bfd_arch_i386, bfd_target_elf_flavour,
                                  amd64_haiku_osabi_sniffer);

  gdbarch_register_osabi (bfd_arch_i386, bfd_mach_x86_64, GDB_OSABI_HAIKU,
                          amd64_haiku_init_abi);
}
