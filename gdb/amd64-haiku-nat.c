/* Native-dependent code for Haiku/amd64.

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
#include "haiku-nat.h"
#include "nat/haiku-nat.h"

/* Very conservative inclusion of Haiku headers to prevent name clashes.  */
typedef uint64_t uint64;
#include <arch/x86_64/arch_debugger.h>

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

struct amd64_haiku_nat_target final : public haiku_nat_target
{
  void fetch_registers (struct regcache *, int) override;
  void store_registers (struct regcache *, int) override;
};

void
amd64_haiku_nat_target::fetch_registers (struct regcache *regcache, int regno)
{
  union
  {
    char data[sizeof (x86_64_debug_cpu_state)];
    x86_64_debug_cpu_state state;
  };

  if (haiku_nat::get_cpu_state (regcache->ptid (), &state) < 0)
    {
      /* This happens when the inferior is killed by another process
         while being stopped. The nub port has been deleted, so we cannot
         send the required message to get the CPU state.  */
      HAIKU_TRACE ("Failed to get actual CPU state: %s", strerror (errno));
      memset (&state, 0, sizeof (state));
    }

  if (regno == -1)
    {
      for (int i = 0; i < AMD64_NUM_GREGS; ++i)
        regcache->raw_supply (i, data + haiku_amd64_reg_offsets[i]);
      amd64_supply_fxsave (regcache, regno, &state.extended_registers);
    }
  else
    {
      if (regno < AMD64_NUM_GREGS)
        regcache->raw_supply (regno, data + haiku_amd64_reg_offsets[regno]);
      else
        amd64_supply_fxsave (regcache, regno, &state.extended_registers);
    }
}

void
amd64_haiku_nat_target::store_registers (struct regcache *regcache, int regno)
{
  union
  {
    char data[sizeof (x86_64_debug_cpu_state)];
    x86_64_debug_cpu_state state;
  };

  if (haiku_nat::get_cpu_state (regcache->ptid (), &state) < 0)
    {
      HAIKU_TRACE ("Failed to get actual CPU state: %s", strerror (errno));
      return;
    }

  if (regno == -1)
    {
      for (int i = 0; i < AMD64_NUM_GREGS; ++i)
        regcache->raw_collect (i, data + haiku_amd64_reg_offsets[i]);
      amd64_collect_fxsave (regcache, regno, &state.extended_registers);
    }
  else
    {
      if (regno < AMD64_NUM_GREGS)
        regcache->raw_collect (regno, data + haiku_amd64_reg_offsets[regno]);
      else
        amd64_collect_fxsave (regcache, regno, &state.extended_registers);
    }

  if (haiku_nat::set_cpu_state (regcache->ptid (), &state) < 0)
    perror_with_name (("haiku_nat::set_cpu_state"));
}

static amd64_haiku_nat_target the_amd64_haiku_nat_target;

void _initialize_amd64_haiku_nat ();
void
_initialize_amd64_haiku_nat ()
{
  haiku_target = &the_amd64_haiku_nat_target;

  add_inf_child_target (&the_amd64_haiku_nat_target);
}
