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

#include "arch/amd64.h"
#include "gdbsupport/x86-xstate.h"
#include "tdesc.h"
#include "x86-tdesc.h"

#include "nat/haiku-nat.h"

#include <array>

/* Very conservative inclusion of Haiku headers to prevent name clashes.  */
#include <SupportDefs.h>
#include <arch/x86_64/arch_debugger.h>

/* Register numbers of various important registers.  */

enum amd64_regnum
{
  AMD64_RAX_REGNUM,      /* %rax */
  AMD64_RBX_REGNUM,      /* %rbx */
  AMD64_RCX_REGNUM,      /* %rcx */
  AMD64_RDX_REGNUM,      /* %rdx */
  AMD64_RSI_REGNUM,      /* %rsi */
  AMD64_RDI_REGNUM,      /* %rdi */
  AMD64_RBP_REGNUM,      /* %rbp */
  AMD64_RSP_REGNUM,      /* %rsp */
  AMD64_R8_REGNUM,       /* %r8 */
  AMD64_R9_REGNUM,       /* %r9 */
  AMD64_R10_REGNUM,      /* %r10 */
  AMD64_R11_REGNUM,      /* %r11 */
  AMD64_R12_REGNUM,      /* %r12 */
  AMD64_R13_REGNUM,      /* %r13 */
  AMD64_R14_REGNUM,      /* %r14 */
  AMD64_R15_REGNUM,      /* %r15 */
  AMD64_RIP_REGNUM,      /* %rip */
  AMD64_EFLAGS_REGNUM,   /* %eflags */
  AMD64_CS_REGNUM,       /* %cs */
  AMD64_SS_REGNUM,       /* %ss */
  AMD64_DS_REGNUM,       /* %ds */
  AMD64_ES_REGNUM,       /* %es */
  AMD64_FS_REGNUM,       /* %fs */
  AMD64_GS_REGNUM,       /* %gs */
  AMD64_ST0_REGNUM = 24, /* %st0 */
  AMD64_ST1_REGNUM,      /* %st1 */
  AMD64_FCTRL_REGNUM = AMD64_ST0_REGNUM + 8,
  AMD64_FSTAT_REGNUM = AMD64_ST0_REGNUM + 9,
  AMD64_FTAG_REGNUM = AMD64_ST0_REGNUM + 10,
  AMD64_XMM0_REGNUM = 40, /* %xmm0 */
  AMD64_XMM1_REGNUM,      /* %xmm1 */
  AMD64_MXCSR_REGNUM = AMD64_XMM0_REGNUM + 16,
  AMD64_YMM0H_REGNUM, /* %ymm0h */
  AMD64_YMM15H_REGNUM = AMD64_YMM0H_REGNUM + 15,
  AMD64_BND0R_REGNUM = AMD64_YMM15H_REGNUM + 1,
  AMD64_BND3R_REGNUM = AMD64_BND0R_REGNUM + 3,
  AMD64_BNDCFGU_REGNUM,
  AMD64_BNDSTATUS_REGNUM,
  AMD64_XMM16_REGNUM,
  AMD64_XMM31_REGNUM = AMD64_XMM16_REGNUM + 15,
  AMD64_YMM16H_REGNUM,
  AMD64_YMM31H_REGNUM = AMD64_YMM16H_REGNUM + 15,
  AMD64_K0_REGNUM,
  AMD64_K7_REGNUM = AMD64_K0_REGNUM + 7,
  AMD64_ZMM0H_REGNUM,
  AMD64_ZMM31H_REGNUM = AMD64_ZMM0H_REGNUM + 31,
  AMD64_PKRU_REGNUM,
  AMD64_FSBASE_REGNUM,
  AMD64_GSBASE_REGNUM
};

/* Number of general purpose registers.  */
#define AMD64_NUM_GREGS 24

#define AMD64_NUM_REGS (AMD64_GSBASE_REGNUM + 1)

/* At haiku_amd64_reg_offsets[REGNUM] you'll find the offset in `struct
   debug_cpu_state' where the GDB register REGNUM is stored. */
static constexpr auto haiku_amd64_reg_offsets = [] () constexpr {
  std::array<int, AMD64_NUM_GREGS> result = {};

  /* Set up the register offset table.  */
#define HAIKU_DECLARE_REG_OFFSET(gdbreg, haikureg)                            \
  result[AMD64_##gdbreg##_REGNUM]                                             \
      = offsetof (struct x86_64_debug_cpu_state, haikureg)

  HAIKU_DECLARE_REG_OFFSET (RAX, rax);
  HAIKU_DECLARE_REG_OFFSET (RBX, rbx);
  HAIKU_DECLARE_REG_OFFSET (RCX, rcx);
  HAIKU_DECLARE_REG_OFFSET (RDX, rdx);
  HAIKU_DECLARE_REG_OFFSET (RSI, rsi);
  HAIKU_DECLARE_REG_OFFSET (RDI, rdi);
  HAIKU_DECLARE_REG_OFFSET (RBP, rbp);
  HAIKU_DECLARE_REG_OFFSET (RSP, rsp);
  HAIKU_DECLARE_REG_OFFSET (R8, r8);
  HAIKU_DECLARE_REG_OFFSET (R9, r9);
  HAIKU_DECLARE_REG_OFFSET (R10, r10);
  HAIKU_DECLARE_REG_OFFSET (R11, r11);
  HAIKU_DECLARE_REG_OFFSET (R12, r12);
  HAIKU_DECLARE_REG_OFFSET (R13, r13);
  HAIKU_DECLARE_REG_OFFSET (R14, r14);
  HAIKU_DECLARE_REG_OFFSET (R15, r15);
  HAIKU_DECLARE_REG_OFFSET (RIP, rip);
  HAIKU_DECLARE_REG_OFFSET (EFLAGS, rflags);
  HAIKU_DECLARE_REG_OFFSET (CS, cs);
  HAIKU_DECLARE_REG_OFFSET (SS, ss);
  HAIKU_DECLARE_REG_OFFSET (DS, ds);
  HAIKU_DECLARE_REG_OFFSET (ES, es);
  HAIKU_DECLARE_REG_OFFSET (FS, fs);
  HAIKU_DECLARE_REG_OFFSET (GS, gs);

#undef HAIKU_DECLARE_REG_OFFSET

  return result;
}();

/* Haiku target op definitions for the amd64 architecture.  */

class haiku_amd64_target : public haiku_process_target
{
public:
  void fetch_registers (regcache *regcache, int regno) override;

  void store_registers (regcache *regcache, int regno) override;

  const gdb_byte *sw_breakpoint_from_kind (int kind, int *size) override;

protected:
  virtual void low_arch_setup (process_info *process) override;
};

/* Implement the fetch_registers target_ops method.  */

void
haiku_amd64_target::fetch_registers (struct regcache *regcache, int regno)
{
  char regs[sizeof (x86_64_debug_cpu_state)];

  if (haiku_nat::get_cpu_state (ptid_of (current_thread), &regs) < 0)
    {
      /* This happens when the inferior is killed by another process
         while being stopped. The nub port has been deleted, so we cannot
         send the required message to get the CPU state.  */
      HAIKU_TRACE ("Failed to get actual CPU state: %s", strerror (errno));
      memset (regs, 0, sizeof (regs));
    }

  if (regno == -1)
    {
      for (int i = 0; i < AMD64_NUM_GREGS; ++i)
        regcache->raw_supply (i, regs + haiku_amd64_reg_offsets[i]);
    }
  else
    {
      if (regno < AMD64_NUM_GREGS)
        regcache->raw_supply (regno, regs + haiku_amd64_reg_offsets[regno]);
      else
        {
          /* For the main GDB codebase, there is a helper function,
             amd64_supply_fxsave that does just what we want.
             However, this function is not linked to gdbserver.

             We can fetch these registers by hand, but NetBSD seems fine with
             just the general purpose ones, so keep it stubbed for now.  */
          HAIKU_TRACE ("Trying to fetch unimplemented register #%i", regno);
        }
    }
}

/* Implement the store_registers target_ops method.  */

void
haiku_amd64_target::store_registers (struct regcache *regcache, int regno)
{
  char regs[sizeof (x86_64_debug_cpu_state)];

  if (haiku_nat::get_cpu_state (ptid_of (current_thread), &regs) < 0)
    {
      HAIKU_TRACE ("Failed to get actual CPU state: %s", strerror (errno));
      return;
    }

  if (regno == -1)
    {
      for (int i = 0; i < AMD64_NUM_GREGS; ++i)
        regcache->raw_collect (i, regs + haiku_amd64_reg_offsets[i]);
    }
  else
    {
      if (regno < AMD64_NUM_GREGS)
        regcache->raw_collect (regno, regs + haiku_amd64_reg_offsets[regno]);
      else
        {
          HAIKU_TRACE ("Trying to store unimplemented register #%i", regno);
        }
    }

  if (haiku_nat::set_cpu_state (ptid_of (current_thread), &regs) < 0)
    perror_with_name (("haiku_nat::set_cpu_state"));
}

const gdb_byte *
haiku_amd64_target::sw_breakpoint_from_kind (int kind, int *size)
{
  /* From <private/kernel/arch/x86/arch_user_debugger.h>  */

  /* DEBUG_SOFTWARE_BREAKPOINT_SIZE */
  *size = 1;
  /* DEBUG_SOFTWARE_BREAKPOINT */
  static const gdb_byte x86_software_breakpoint[] = { 0xcc };
  return x86_software_breakpoint;
}

/* Architecture-specific setup for the current process.  */

void
haiku_amd64_target::low_arch_setup (process_info *process)
{
  if (process == nullptr)
    process = current_process ();

  /* Set up the target description.  */
  target_desc *tdesc = amd64_create_target_description (X86_XSTATE_AVX_MASK,
                                                        false, false, false);

  init_target_desc (tdesc, amd64_expedite_regs);

  process->tdesc = tdesc;
}

/* The singleton target ops object.  */

static haiku_amd64_target the_haiku_amd64_target;

/* The Haiku target ops object.  */

haiku_process_target *the_haiku_target = &the_haiku_amd64_target;
