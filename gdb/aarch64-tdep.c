/* Common target dependent code for GDB on AArch64 systems.

   Copyright (C) 2009-2020 Free Software Foundation, Inc.
   Contributed by ARM Ltd.

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

#include "frame.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "dis-asm.h"
#include "regcache.h"
#include "reggroups.h"
#include "value.h"
#include "arch-utils.h"
#include "osabi.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "trad-frame.h"
#include "objfiles.h"
#include "dwarf2.h"
#include "dwarf2/frame.h"
#include "gdbtypes.h"
#include "prologue-value.h"
#include "target-descriptions.h"
#include "user-regs.h"
#include "ax-gdb.h"
#include "gdbsupport/selftest.h"

#include "aarch64-tdep.h"
#include "aarch64-ravenscar-thread.h"

#include "record.h"
#include "record-full.h"
#include "arch/aarch64-insn.h"
#include "gdbarch.h"

#include "opcode/aarch64.h"
#include <algorithm>

#include "gdbsupport/capability.h"

/* For address/int to pointer conversions.  */
#include "inferior.h"

#include "elf-bfd.h"
#include "elf/aarch64.h" /* for ELF flags.  */

#define submask(x) ((1L << ((x) + 1)) - 1)
#define bit(obj,st) (((obj) >> (st)) & 1)
#define bits(obj,st,fn) (((obj) >> (st)) & submask ((fn) - (st)))

/* A Homogeneous Floating-Point or Short-Vector Aggregate may have at most
   four members.  */
#define HA_MAX_NUM_FLDS		4

/* All possible aarch64 target descriptors.  */
struct target_desc *tdesc_aarch64_list[AARCH64_MAX_SVE_VQ + 1][2/*pauth*/][2 /* capability */];

/* Macros for setting and testing a bit in a minimal symbol that marks
   it as C64 function.  The MSB of the minimal symbol's "info" field
   is used for this purpose.

   MSYMBOL_SET_SPECIAL	Actually sets the "special" bit.
   MSYMBOL_IS_SPECIAL   Tests the "special" bit in a minimal symbol.  */

#define MSYMBOL_SET_SPECIAL(msym) \
	MSYMBOL_TARGET_FLAG_1 (msym) = 1

#define MSYMBOL_IS_SPECIAL(msym)  \
	MSYMBOL_TARGET_FLAG_1 (msym)

struct aarch64_mapping_symbol
{
  CORE_ADDR value;
  char type;

  bool operator< (const aarch64_mapping_symbol &other) const
  { return this->value < other.value; }
};

typedef std::vector<aarch64_mapping_symbol> aarch64_mapping_symbol_vec;

struct aarch64_per_bfd
{
  explicit aarch64_per_bfd (size_t num_sections)
  : section_maps (new aarch64_mapping_symbol_vec[num_sections]),
    section_maps_sorted (new bool[num_sections] ())
  {}

  DISABLE_COPY_AND_ASSIGN (aarch64_per_bfd);

  /* Information about mapping symbols ($x, $c, $d) in the objfile.

     The format is an array of vectors of aarch64_mapping_symbols, there is one
     vector for each section of the objfile (the array is index by BFD section
     index).

     For each section, the vector of aarch64_mapping_symbol is sorted by
     symbol value (address).  */
  std::unique_ptr<aarch64_mapping_symbol_vec[]> section_maps;

  /* For each corresponding element of section_maps above, is this vector
     sorted.  */
  std::unique_ptr<bool[]> section_maps_sorted;
};

/* Per-bfd data used for mapping symbols.  */
static bfd_key<aarch64_per_bfd> aarch64_bfd_data_key;

/* The list of available aarch64 set/show commands.  */
static struct cmd_list_element *set_aarch64_cmdlist = NULL;
static struct cmd_list_element *show_aarch64_cmdlist = NULL;

/* The ABI to use.  Keep this in sync with aarch64_abi_kind.  */
static const char *const aarch64_abi_strings[] =
{
  "auto",
  "AAPCS64",
  "AAPCS64-cap",
  nullptr
};

/* Variables for the ABI user setting.  */
static enum aarch64_abi_kind aarch64_current_abi_global = AARCH64_ABI_AUTO;
static const char *aarch64_current_abi_string = "auto";

static void
aarch64_update_current_architecture (void)
{
  struct gdbarch_info info;

  /* If the current architecture is not AArch64, we have nothing to do.  */
  if (gdbarch_bfd_arch_info (target_gdbarch ())->arch != bfd_arch_aarch64)
    return;

  /* Update the architecture.  */
  gdbarch_info_init (&info);

  if (!gdbarch_update_p (info))
    internal_error (__FILE__, __LINE__, _("could not update architecture"));
}

/* Sets the current ABI for AArch64.  */

static void
aarch64_set_abi (const char *args, int from_tty,
		 struct cmd_list_element *c)
{
  int abi;

  for (abi = AARCH64_ABI_AUTO; abi != AARCH64_ABI_LAST; abi++)
    if (strcmp (aarch64_current_abi_string, aarch64_abi_strings[abi]) == 0)
      {
	aarch64_current_abi_global = (enum aarch64_abi_kind) abi;
	break;
      }

  if (abi == AARCH64_ABI_LAST)
    internal_error (__FILE__, __LINE__, _("Invalid ABI accepted: %s."),
		    aarch64_current_abi_string);

  aarch64_update_current_architecture ();
}

/* Shows the current ABI for AArch64.  */

static void
aarch64_show_abi (struct ui_file *file, int from_tty,
		  struct cmd_list_element *c, const char *value)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (target_gdbarch ());

  if (aarch64_current_abi_global == AARCH64_ABI_AUTO
      && gdbarch_bfd_arch_info (target_gdbarch ())->arch == bfd_arch_aarch64)
    fprintf_filtered (file, _("\
The current AArch64 ABI is \"auto\" (currently \"%s\").\n"),
		      aarch64_abi_strings[tdep->abi]);
  else
    fprintf_filtered (file, _("The current AArch64 ABI is \"%s\".\n"),
		      aarch64_current_abi_string);
}

/* The standard register names, and all the valid aliases for them.  */
static const struct
{
  const char *const name;
  int regnum;
} aarch64_register_aliases[] =
{
  /* 64-bit register names.  */
  {"fp", AARCH64_FP_REGNUM},
  {"lr", AARCH64_LR_REGNUM},
  {"sp", AARCH64_SP_REGNUM},

  /* 32-bit register names.  */
  {"w0", AARCH64_X0_REGNUM + 0},
  {"w1", AARCH64_X0_REGNUM + 1},
  {"w2", AARCH64_X0_REGNUM + 2},
  {"w3", AARCH64_X0_REGNUM + 3},
  {"w4", AARCH64_X0_REGNUM + 4},
  {"w5", AARCH64_X0_REGNUM + 5},
  {"w6", AARCH64_X0_REGNUM + 6},
  {"w7", AARCH64_X0_REGNUM + 7},
  {"w8", AARCH64_X0_REGNUM + 8},
  {"w9", AARCH64_X0_REGNUM + 9},
  {"w10", AARCH64_X0_REGNUM + 10},
  {"w11", AARCH64_X0_REGNUM + 11},
  {"w12", AARCH64_X0_REGNUM + 12},
  {"w13", AARCH64_X0_REGNUM + 13},
  {"w14", AARCH64_X0_REGNUM + 14},
  {"w15", AARCH64_X0_REGNUM + 15},
  {"w16", AARCH64_X0_REGNUM + 16},
  {"w17", AARCH64_X0_REGNUM + 17},
  {"w18", AARCH64_X0_REGNUM + 18},
  {"w19", AARCH64_X0_REGNUM + 19},
  {"w20", AARCH64_X0_REGNUM + 20},
  {"w21", AARCH64_X0_REGNUM + 21},
  {"w22", AARCH64_X0_REGNUM + 22},
  {"w23", AARCH64_X0_REGNUM + 23},
  {"w24", AARCH64_X0_REGNUM + 24},
  {"w25", AARCH64_X0_REGNUM + 25},
  {"w26", AARCH64_X0_REGNUM + 26},
  {"w27", AARCH64_X0_REGNUM + 27},
  {"w28", AARCH64_X0_REGNUM + 28},
  {"w29", AARCH64_X0_REGNUM + 29},
  {"w30", AARCH64_X0_REGNUM + 30},

  /*  specials */
  {"ip0", AARCH64_X0_REGNUM + 16},
  {"ip1", AARCH64_X0_REGNUM + 17}
};

/* A couple register aliases for Morello.  We leave the register numbers
   undefined because those are assigned dynamically based on the various
   features a particular system supports.

   We need the static storage so we can pass a register number reference to
   GDB's hooks.  */
static struct
{
  const char *const name;
  int regnum;
} aarch64_morello_register_aliases[] =
{
  {"cip0", -1},
  {"cip1", -1},
  {"cfp", -1},
  {"clr", -1},
  {"c31", -1}
};

/* The required capability 'C' registers.  */
static const char *const aarch64_c_register_names[] =
{
  /* These registers must appear in consecutive RAW register number
     order and they must begin with AARCH64_C0_REGNUM! */
  "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
  "c8", "c9", "c10", "c11", "c12", "c13", "c14", "c15",
  "c16", "c17", "c18", "c19", "c20", "c21", "c22", "c23",
  "c24", "c25", "c26", "c27", "c28", "c29", "c30", "csp",
  "pcc", "ddc", "ctpidr", "rcsp", "rddc", "rctpidr", "cid",
  "tag_map", "cctlr"
};

/* The required core 'R' registers.  */
static const char *const aarch64_r_register_names[] =
{
  /* These registers must appear in consecutive RAW register number
     order and they must begin with AARCH64_X0_REGNUM! */
  "x0", "x1", "x2", "x3",
  "x4", "x5", "x6", "x7",
  "x8", "x9", "x10", "x11",
  "x12", "x13", "x14", "x15",
  "x16", "x17", "x18", "x19",
  "x20", "x21", "x22", "x23",
  "x24", "x25", "x26", "x27",
  "x28", "x29", "x30", "sp",
  "pc", "cpsr"
};

/* The FP/SIMD 'V' registers.  */
static const char *const aarch64_v_register_names[] =
{
  /* These registers must appear in consecutive RAW register number
     order and they must begin with AARCH64_V0_REGNUM! */
  "v0", "v1", "v2", "v3",
  "v4", "v5", "v6", "v7",
  "v8", "v9", "v10", "v11",
  "v12", "v13", "v14", "v15",
  "v16", "v17", "v18", "v19",
  "v20", "v21", "v22", "v23",
  "v24", "v25", "v26", "v27",
  "v28", "v29", "v30", "v31",
  "fpsr",
  "fpcr"
};

/* The SVE 'Z' and 'P' registers.  */
static const char *const aarch64_sve_register_names[] =
{
  /* These registers must appear in consecutive RAW register number
     order and they must begin with AARCH64_SVE_Z0_REGNUM! */
  "z0", "z1", "z2", "z3",
  "z4", "z5", "z6", "z7",
  "z8", "z9", "z10", "z11",
  "z12", "z13", "z14", "z15",
  "z16", "z17", "z18", "z19",
  "z20", "z21", "z22", "z23",
  "z24", "z25", "z26", "z27",
  "z28", "z29", "z30", "z31",
  "fpsr", "fpcr",
  "p0", "p1", "p2", "p3",
  "p4", "p5", "p6", "p7",
  "p8", "p9", "p10", "p11",
  "p12", "p13", "p14", "p15",
  "ffr", "vg"
};

static const char *const aarch64_pauth_register_names[] =
{
  /* Authentication mask for data pointer.  */
  "pauth_dmask",
  /* Authentication mask for code pointer.  */
  "pauth_cmask"
};

/* The capability pseudo registers.  These contain the same information
   as the C registers, but broken up in 3 pieces.  */
static const char *const aarch64_c_pseudo_register_names[] =
{
  "pc0", "pc1", "pc2", "pc3", "pc4", "pc5", "pc6", "pc7",
  "pc8", "pc9", "pc10", "pc11", "pc12", "pc13", "pc14", "pc15",
  "pc16", "pc17", "pc18", "pc19", "pc20", "pc21", "pc22", "pc23",
  "pc24", "pc25", "pc26", "pc27", "pc28", "pc29", "pc30", "pcsp",
  "ppcc", "pddc", "pctpidr", "prcsp", "prddc", "prctpidr", "pcid"
};

/* AArch64 prologue cache structure.  */
struct aarch64_prologue_cache
{
  /* The program counter at the start of the function.  It is used to
     identify this frame as a prologue frame.  */
  CORE_ADDR func;

  /* The program counter at the time this frame was created; i.e. where
     this function was called from.  It is used to identify this frame as a
     stub frame.  */
  CORE_ADDR prev_pc;

  /* The stack pointer at the time this frame was created; i.e. the
     caller's stack pointer when this function was called.  It is used
     to identify this frame.  */
  CORE_ADDR prev_sp;

  /* Is the target available to read from?  */
  int available_p;

  /* The frame base for this frame is just prev_sp - frame size.
     FRAMESIZE is the distance from the frame pointer to the
     initial stack pointer.  */
  int framesize;

  /* The register used to hold the frame pointer for this frame.  */
  int framereg;

  /* Saved register offsets.  */
  struct trad_frame_saved_reg *saved_regs;
};

static void
show_aarch64_debug (struct ui_file *file, int from_tty,
                    struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, _("AArch64 debugging is %s.\n"), value);
}

namespace {

/* Abstract instruction reader.  */

class abstract_instruction_reader
{
public:
  /* Read in one instruction.  */
  virtual ULONGEST read (CORE_ADDR memaddr, int len,
			 enum bfd_endian byte_order) = 0;
};

/* Instruction reader from real target.  */

class instruction_reader : public abstract_instruction_reader
{
 public:
  ULONGEST read (CORE_ADDR memaddr, int len, enum bfd_endian byte_order)
    override
  {
    return read_code_unsigned_integer (memaddr, len, byte_order);
  }
};

} // namespace

/* If address signing is enabled, mask off the signature bits from the link
   register, which is passed by value in ADDR, using the register values in
   THIS_FRAME.  */

static CORE_ADDR
aarch64_frame_unmask_lr (struct gdbarch_tdep *tdep,
			 struct frame_info *this_frame, CORE_ADDR addr)
{
  if (tdep->has_pauth ()
      && frame_unwind_register_unsigned (this_frame,
					 tdep->pauth_ra_state_regnum))
    {
      int cmask_num = AARCH64_PAUTH_CMASK_REGNUM (tdep->pauth_reg_base);
      CORE_ADDR cmask = frame_unwind_register_unsigned (this_frame, cmask_num);
      addr = addr & ~cmask;

      /* Record in the frame that the link register required unmasking.  */
      set_frame_previous_pc_masked (this_frame);
    }

  return addr;
}

/* Implement the "get_pc_address_flags" gdbarch method.  */

static std::string
aarch64_get_pc_address_flags (frame_info *frame, CORE_ADDR pc)
{
  if (pc != 0 && get_frame_pc_masked (frame))
    return "PAC";

  return "";
}

/* Analyze a prologue, looking for a recognizable stack frame
   and frame pointer.  Scan until we encounter a store that could
   clobber the stack frame unexpectedly, or an unknown instruction.  */

static CORE_ADDR
aarch64_analyze_prologue (struct gdbarch *gdbarch,
			  CORE_ADDR start, CORE_ADDR limit,
			  struct aarch64_prologue_cache *cache,
			  abstract_instruction_reader& reader)
{
  enum bfd_endian byte_order_for_code = gdbarch_byte_order_for_code (gdbarch);
  int i;

  /* Whether the stack has been set.  This should be true when we notice a SP
     to FP move or if we are using the SP as the base register for storing
     data, in case the FP is ommitted.  */
  bool seen_stack_set = false;

  /* Track X registers and D registers in prologue.  */
  pv_t regs[AARCH64_X_REGISTER_COUNT + AARCH64_D_REGISTER_COUNT];

  if (aarch64_debug)
    debug_printf ("aarch64: Entering %s\n", __func__);

  for (i = 0; i < AARCH64_X_REGISTER_COUNT + AARCH64_D_REGISTER_COUNT; i++)
    regs[i] = pv_register (i, 0);
  pv_area stack (AARCH64_SP_REGNUM, gdbarch_addr_bit (gdbarch));

  for (; start < limit; start += 4)
    {
      uint32_t insn;
      aarch64_inst inst;

      if (aarch64_debug)
	debug_printf ("aarch64: %s Reading instruction at %s\n", __func__,
		      paddress (gdbarch, start));
      insn = reader.read (start, 4, byte_order_for_code);

      if (aarch64_decode_insn (insn, &inst, 1, NULL) != 0)
	break;

      if (aarch64_debug)
	debug_printf ("aarch64: %s Fetched instruction %s\n", __func__,
		      paddress (gdbarch, insn));

      if (aarch64_debug)
	debug_printf ("aarch64: %s iclass = %d, op = %d, name = %s\n", __func__,
		      inst.opcode->iclass, inst.opcode->op, inst.opcode->name);

      if (inst.opcode->iclass == addsub_imm
	  && ((inst.opcode->op == OP_ADD
	      || inst.opcode->op == OP_A64C_ADD)
	      || strcmp ("sub", inst.opcode->name) == 0))
	{
	  unsigned rd = inst.operands[0].reg.regno;
	  unsigned rn = inst.operands[1].reg.regno;

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s addsub_imm: rd = %d, rn = %d\n",
			  __func__, rd, rn);

	  gdb_assert (aarch64_num_of_operands (inst.opcode) == 3);
	  gdb_assert (inst.operands[0].type == AARCH64_OPND_Rd_SP
		      || inst.operands[0].type == AARCH64_OPND_Cad_SP);
	  gdb_assert (inst.operands[1].type == AARCH64_OPND_Rn_SP
		      || inst.operands[1].type == AARCH64_OPND_Can_SP);
	  gdb_assert (inst.operands[2].type == AARCH64_OPND_AIMM
		      || inst.operands[2].type == AARCH64_OPND_A64C_AIMM);

	  if (inst.opcode->op == OP_ADD || inst.opcode->op == OP_A64C_ADD)
	    {
	      regs[rd] = pv_add_constant (regs[rn],
					  inst.operands[2].imm.value);

	      if (aarch64_debug)
		debug_printf ("aarch64: %s regs[%d] = regs[%d] + %ld\n",
			      __func__, rd, rn, inst.operands[2].imm.value);
	    }
	  else
	    {
	      regs[rd] = pv_add_constant (regs[rn],
					  -inst.operands[2].imm.value);

	      if (aarch64_debug)
		debug_printf ("aarch64: %s regs[%d] = regs[%d] - %ld\n",
			      __func__, rd, rn, inst.operands[2].imm.value);
	    }

	  /* Did we move SP to FP?  */
	  if (rn == AARCH64_SP_REGNUM && rd == AARCH64_FP_REGNUM)
	    seen_stack_set = true;

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s End of addsub_imm. moved sp to fp? %s\n",
			   __func__, seen_stack_set? "yes":"no");
	}
      else if (inst.opcode->iclass == pcreladdr
	       && inst.operands[1].type == AARCH64_OPND_ADDR_ADRP)
	{
	  gdb_assert (aarch64_num_of_operands (inst.opcode) == 2);
	  gdb_assert (inst.operands[0].type == AARCH64_OPND_Rd
		      || inst.operands[0].type == AARCH64_OPND_Cad);

	  regs[inst.operands[0].reg.regno] = pv_unknown ();

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s pcreladdr: register = %d\n", __func__,
			  inst.operands[0].reg.regno);
	}
      else if (inst.opcode->iclass == branch_imm)
	{
	  if (aarch64_debug)
	    debug_printf ("aarch64: %s branch_imm\n", __func__);
	  /* Stop analysis on branch.  */
	  break;
	}
      else if (inst.opcode->iclass == condbranch)
	{
	  if (aarch64_debug)
	    debug_printf ("aarch64: %s condbranch\n", __func__);
	  /* Stop analysis on branch.  */
	  break;
	}
      else if (inst.opcode->iclass == branch_reg)
	{
	  if (aarch64_debug)
	    debug_printf ("aarch64: %s branch_reg\n", __func__);
	  /* Stop analysis on branch.  */
	  break;
	}
      else if (inst.opcode->iclass == compbranch)
	{
	  if (aarch64_debug)
	    debug_printf ("aarch64: %s compbranch\n", __func__);
	  /* Stop analysis on branch.  */
	  break;
	}
      else if (inst.opcode->iclass == bitfield)
	{
	  /* Do nothing */
	}
      else if (inst.opcode->op == OP_MOVZ
	       || (inst.opcode->iclass == a64c
		   && strcmp (inst.opcode->name, "cpy") == 0))
	{
	  gdb_assert (inst.operands[0].type == AARCH64_OPND_Rd
		      || (inst.operands[0].type == AARCH64_OPND_Cad_SP
			  && inst.operands[1].type == AARCH64_OPND_Can_SP));

	  bool is_fp_or_sp = false;
	  if (inst.operands[0].reg.regno == AARCH64_FP_REGNUM
	      && inst.operands[1].reg.regno == AARCH64_SP_REGNUM)
	    is_fp_or_sp = true;

	  /* If this shows up before we set the stack, keep going.  Otherwise
	     stop the analysis if we're not dealing with SP or FP.  */
	  if (seen_stack_set && !is_fp_or_sp)
	    break;

	  regs[inst.operands[0].reg.regno] = pv_unknown ();

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s OP_MOVZ: register = %d\n", __func__,
			  inst.operands[0].reg.regno);
	}
      else if (inst.opcode->iclass == log_shift
	       && strcmp (inst.opcode->name, "orr") == 0)
	{
	  unsigned rd = inst.operands[0].reg.regno;
	  unsigned rn = inst.operands[1].reg.regno;
	  unsigned rm = inst.operands[2].reg.regno;

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s log_shift: rd = %d, rn = %d, rm = %d\n",
			  __func__, rd, rn, rm);

	  gdb_assert (inst.operands[0].type == AARCH64_OPND_Rd);
	  gdb_assert (inst.operands[1].type == AARCH64_OPND_Rn);
	  gdb_assert (inst.operands[2].type == AARCH64_OPND_Rm_SFT);

	  if (inst.operands[2].shifter.amount == 0
	      && (rn == AARCH64_SP_REGNUM))
	    regs[rd] = regs[rm];
	  else
	    {
	      if (aarch64_debug)
		{
		  debug_printf ("aarch64: prologue analysis gave up "
				"addr=%s opcode=0x%x (orr x register)\n",
				core_addr_to_string_nz (start), insn);
		}
	      break;
	    }
	}
      else if (inst.opcode->op == OP_STUR || inst.opcode->op == OP_STUR_C)
	{
	  unsigned rt = inst.operands[0].reg.regno;
	  unsigned rn = inst.operands[1].addr.base_regno;
	  int size = aarch64_get_qualifier_esize (inst.operands[0].qualifier);

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s OP_STUR: rt = %d, rn = %d\n", __func__,
			  rt, rn);

	  gdb_assert (aarch64_num_of_operands (inst.opcode) == 2);
	  gdb_assert (inst.operands[0].type == AARCH64_OPND_Rt
		      || inst.operands[0].type == AARCH64_OPND_Cat);
	  gdb_assert (inst.operands[1].type == AARCH64_OPND_ADDR_SIMM9
		      || inst.operands[1].type == AARCH64_OPND_A64C_ADDR_SIMM9);
	  gdb_assert (!inst.operands[1].addr.offset.is_reg);

	  stack.store
	    (pv_add_constant (regs[rn], inst.operands[1].addr.offset.imm),
	     size, regs[rt]);

	  /* Are we storing with SP as a base?  */
	  if (rn == AARCH64_SP_REGNUM)
	    seen_stack_set = true;

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s End of OP_STUR. moved sp to fp? %s\n",
			  __func__, seen_stack_set? "yes":"no");
	}
      else if ((inst.opcode->iclass == ldstpair_off
		|| (inst.opcode->iclass == ldstpair_indexed
		    && inst.operands[2].addr.preind))
	       && strcmp ("stp", inst.opcode->name) == 0)
	{
	  /* STP with addressing mode Pre-indexed and Base register.  */
	  unsigned rt1;
	  unsigned rt2;
	  unsigned rn = inst.operands[2].addr.base_regno;
	  int32_t imm = inst.operands[2].addr.offset.imm;
	  int size = aarch64_get_qualifier_esize (inst.operands[0].qualifier);

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s ldstpair-off: rn = %d, imm = %d"
			  " size = %d\n", __func__, rn, imm, size);

	  gdb_assert ((inst.operands[0].type == AARCH64_OPND_Rt
		       || inst.operands[0].type == AARCH64_OPND_Cat)
		      || inst.operands[0].type == AARCH64_OPND_Ft);
	  gdb_assert ((inst.operands[1].type == AARCH64_OPND_Rt2
		       || inst.operands[1].type == AARCH64_OPND_Cat2)
		      || inst.operands[1].type == AARCH64_OPND_Ft2);
	  gdb_assert (inst.operands[2].type == AARCH64_OPND_ADDR_SIMM7
		      || inst.operands[2].type == AARCH64_OPND_A64C_ADDR_SIMM7);
	  gdb_assert (!inst.operands[2].addr.offset.is_reg);

	  /* If recording this store would invalidate the store area
	     (perhaps because rn is not known) then we should abandon
	     further prologue analysis.  */
	  if (stack.store_would_trash (pv_add_constant (regs[rn], imm)))
	    break;

	  if (stack.store_would_trash (pv_add_constant (regs[rn], imm + size)))
	    break;

	  rt1 = inst.operands[0].reg.regno;
	  rt2 = inst.operands[1].reg.regno;

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s ldstpair-off: rt1 = %d, rt2 = %d\n",
			  __func__, rt1, rt2);

	  if (inst.operands[0].type == AARCH64_OPND_Ft)
	    {
	      rt1 += AARCH64_X_REGISTER_COUNT;
	      rt2 += AARCH64_X_REGISTER_COUNT;
	    }

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s ldstpair-off: rt1 = %d, rt2 = %d\n",
			  __func__, rt1, rt2);

	  stack.store (pv_add_constant (regs[rn], imm), size, regs[rt1]);
	  stack.store (pv_add_constant (regs[rn], imm + size), size, regs[rt2]);

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s ldstpair-off: Stored %d at %d + %d\n",
			  __func__, rt1, rn, imm);

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s ldstpair-off: Stored %d at %d + %d"
			  " + %d\n", __func__, rt2, rn, imm, size);

	  if (inst.operands[2].addr.writeback)
	    regs[rn] = pv_add_constant (regs[rn], imm);

	  /* Ignore the instruction that allocates stack space and sets
	     the SP.  */
	  if ((rn == AARCH64_SP_REGNUM)
	      && !inst.operands[2].addr.writeback)
	    seen_stack_set = true;

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s End of ldstpair-off: moved sp to fp?"
			  " %s\n", __func__, seen_stack_set? "yes":"no");
	}
      else if ((inst.opcode->iclass == ldst_imm9 /* Signed immediate.  */
		|| (inst.opcode->iclass == ldst_pos /* Unsigned immediate.  */
		    && (inst.opcode->op == OP_STR_POS
			|| inst.opcode->op == OP_STRF_POS
			|| inst.opcode->op == OP_STR_POS_C)))
	       && (inst.operands[1].addr.base_regno == AARCH64_SP_REGNUM)
	       && strcmp ("str", inst.opcode->name) == 0)
	{
	  /* STR (immediate) */
	  unsigned int rt = inst.operands[0].reg.regno;
	  int32_t imm = inst.operands[1].addr.offset.imm;
	  unsigned int rn = inst.operands[1].addr.base_regno;
	  int size = aarch64_get_qualifier_esize (inst.operands[0].qualifier);
	  gdb_assert ((inst.operands[0].type == AARCH64_OPND_Rt
		       || inst.operands[0].type == AARCH64_OPND_Cat)
		      || inst.operands[0].type == AARCH64_OPND_Ft);

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s ldst_imm9 str: rt = %d, rn = %d,"
			  " imm = %d\n", __func__, rt, rn, imm);

	  if (inst.operands[0].type == AARCH64_OPND_Ft)
	    rt += AARCH64_X_REGISTER_COUNT;

	  stack.store (pv_add_constant (regs[rn], imm), size, regs[rt]);
	  if (inst.operands[1].addr.writeback)
	    regs[rn] = pv_add_constant (regs[rn], imm);

	  /* Are we storing with SP as a base?  */
	  if (rn == AARCH64_SP_REGNUM)
	    seen_stack_set = true;

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s End of ldst_imm9 str: moved sp to fp?"
			  " %s\n", __func__, seen_stack_set? "yes":"no");
	}
      else if (inst.opcode->iclass == testbranch)
	{
	  if (aarch64_debug)
	    debug_printf ("aarch64: %s testbranch\n", __func__);
	  /* Stop analysis on branch.  */
	  break;
	}
      else if (inst.opcode->iclass == ic_system)
	{
	  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
	  int ra_state_val = 0;

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s ic_system\n", __func__);

	  if (insn == 0xd503233f /* paciasp.  */
	      || insn == 0xd503237f  /* pacibsp.  */)
	    {
	      /* Return addresses are mangled.  */
	      ra_state_val = 1;
	    }
	  else if (insn == 0xd50323bf /* autiasp.  */
		   || insn == 0xd50323ff /* autibsp.  */)
	    {
	      /* Return addresses are not mangled.  */
	      ra_state_val = 0;
	    }
	  else
	    {
	      if (aarch64_debug)
		debug_printf ("aarch64: prologue analysis gave up addr=%s"
			      " opcode=0x%x (iclass)\n",
			      core_addr_to_string_nz (start), insn);
	      break;
	    }

	  if (tdep->has_pauth () && cache != nullptr)
	    trad_frame_set_value (cache->saved_regs,
				  tdep->pauth_ra_state_regnum,
				  ra_state_val);
	}
      else
	{
	  if (aarch64_debug)
	    {
	      debug_printf ("aarch64: prologue analysis gave up addr=%s"
			    " opcode=0x%x\n",
			    core_addr_to_string_nz (start), insn);
	    }
	  break;
	}
    }

  if (cache == NULL)
    return start;

  if (pv_is_register (regs[AARCH64_FP_REGNUM], AARCH64_SP_REGNUM))
    {
      /* Frame pointer is fp.  Frame size is constant.  */
      cache->framereg = AARCH64_FP_REGNUM;
      cache->framesize = -regs[AARCH64_FP_REGNUM].k;
    }
  else if (pv_is_register (regs[AARCH64_SP_REGNUM], AARCH64_SP_REGNUM))
    {
      /* Try the stack pointer.  */
      cache->framesize = -regs[AARCH64_SP_REGNUM].k;
      cache->framereg = AARCH64_SP_REGNUM;
    }
  else
    {
      /* We're just out of luck.  We don't know where the frame is.  */
      cache->framereg = -1;
      cache->framesize = 0;
    }

  if (aarch64_debug)
    debug_printf ("aarch64: %s frame reg is %d, frame size is %s\n", __func__,
		  cache->framereg, core_addr_to_string_nz (cache->framesize));


  for (i = 0; i < AARCH64_X_REGISTER_COUNT; i++)
    {
      CORE_ADDR offset;

      if (stack.find_reg (gdbarch, i, &offset))
	{
	  if (aarch64_debug)
	    debug_printf ("aarch64: %s Register X%d found at offset %s\n",
			  __func__, i, core_addr_to_string_nz (offset));
	  cache->saved_regs[i].addr = offset;
	}
    }

  if (gdbarch_tdep (gdbarch)->has_capability ())
    {
      struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

      /* Also save the C registers.  */
      for (i = 0; i < AARCH64_X_REGISTER_COUNT; i++)
	{
	  CORE_ADDR offset;

	  if (stack.find_reg (gdbarch, i, &offset))
	    {
	      if (aarch64_debug)
		debug_printf ("aarch64: %s Register C%d found at offset %s\n",
			      __func__, i, core_addr_to_string_nz (offset));

	      cache->saved_regs[tdep->cap_reg_base + i].addr = offset;
	    }
	}
    }

  for (i = 0; i < AARCH64_D_REGISTER_COUNT; i++)
    {
      int regnum = gdbarch_num_regs (gdbarch);
      CORE_ADDR offset;

      if (stack.find_reg (gdbarch, i + AARCH64_X_REGISTER_COUNT,
			  &offset))
	cache->saved_regs[i + regnum + AARCH64_D0_REGNUM].addr = offset;
    }

  return start;
}

static CORE_ADDR
aarch64_analyze_prologue (struct gdbarch *gdbarch,
			  CORE_ADDR start, CORE_ADDR limit,
			  struct aarch64_prologue_cache *cache)
{
  instruction_reader reader;

  return aarch64_analyze_prologue (gdbarch, start, limit, cache,
				   reader);
}

#if GDB_SELF_TEST

namespace selftests {

/* Instruction reader from manually cooked instruction sequences.  */

class instruction_reader_test : public abstract_instruction_reader
{
public:
  template<size_t SIZE>
  explicit instruction_reader_test (const uint32_t (&insns)[SIZE])
  : m_insns (insns), m_insns_size (SIZE)
  {}

  ULONGEST read (CORE_ADDR memaddr, int len, enum bfd_endian byte_order)
    override
  {
    SELF_CHECK (len == 4);
    SELF_CHECK (memaddr % 4 == 0);
    SELF_CHECK (memaddr / 4 < m_insns_size);

    return m_insns[memaddr / 4];
  }

private:
  const uint32_t *m_insns;
  size_t m_insns_size;
};

static void
aarch64_analyze_prologue_test (void)
{
  struct gdbarch_info info;

  gdbarch_info_init (&info);
  info.bfd_arch_info = bfd_scan_arch ("aarch64");

  struct gdbarch *gdbarch = gdbarch_find_by_info (info);
  SELF_CHECK (gdbarch != NULL);

  struct aarch64_prologue_cache cache;
  cache.saved_regs = trad_frame_alloc_saved_regs (gdbarch);

  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  /* Test the simple prologue in which frame pointer is used.  */
  {
    static const uint32_t insns[] = {
      0xa9af7bfd, /* stp     x29, x30, [sp,#-272]! */
      0x910003fd, /* mov     x29, sp */
      0x97ffffe6, /* bl      0x400580 */
    };
    instruction_reader_test reader (insns);

    CORE_ADDR end = aarch64_analyze_prologue (gdbarch, 0, 128, &cache, reader);
    SELF_CHECK (end == 4 * 2);

    SELF_CHECK (cache.framereg == AARCH64_FP_REGNUM);
    SELF_CHECK (cache.framesize == 272);

    for (int i = 0; i < AARCH64_X_REGISTER_COUNT; i++)
      {
	if (i == AARCH64_FP_REGNUM)
	  SELF_CHECK (cache.saved_regs[i].addr == -272);
	else if (i == AARCH64_LR_REGNUM)
	  SELF_CHECK (cache.saved_regs[i].addr == -264);
	else
	  SELF_CHECK (cache.saved_regs[i].addr == -1);
      }

    for (int i = 0; i < AARCH64_D_REGISTER_COUNT; i++)
      {
	int regnum = gdbarch_num_regs (gdbarch);

	SELF_CHECK (cache.saved_regs[i + regnum + AARCH64_D0_REGNUM].addr
		    == -1);
      }
  }

  /* Test a prologue in which STR is used and frame pointer is not
     used.  */
  {
    static const uint32_t insns[] = {
      0xf81d0ff3, /* str	x19, [sp, #-48]! */
      0xb9002fe0, /* str	w0, [sp, #44] */
      0xf90013e1, /* str	x1, [sp, #32]*/
      0xfd000fe0, /* str	d0, [sp, #24] */
      0xaa0203f3, /* mov	x19, x2 */
      0xf94013e0, /* ldr	x0, [sp, #32] */
    };
    instruction_reader_test reader (insns);

    trad_frame_reset_saved_regs (gdbarch, cache.saved_regs);
    CORE_ADDR end = aarch64_analyze_prologue (gdbarch, 0, 128, &cache, reader);

    SELF_CHECK (end == 4 * 5);

    SELF_CHECK (cache.framereg == AARCH64_SP_REGNUM);
    SELF_CHECK (cache.framesize == 48);

    for (int i = 0; i < AARCH64_X_REGISTER_COUNT; i++)
      {
	if (i == 1)
	  SELF_CHECK (cache.saved_regs[i].addr == -16);
	else if (i == 19)
	  SELF_CHECK (cache.saved_regs[i].addr == -48);
	else
	  SELF_CHECK (cache.saved_regs[i].addr == -1);
      }

    for (int i = 0; i < AARCH64_D_REGISTER_COUNT; i++)
      {
	int regnum = gdbarch_num_regs (gdbarch);

	if (i == 0)
	  SELF_CHECK (cache.saved_regs[i + regnum + AARCH64_D0_REGNUM].addr
		      == -24);
	else
	  SELF_CHECK (cache.saved_regs[i + regnum + AARCH64_D0_REGNUM].addr
		      == -1);
      }
  }

  /* Test handling of movz before setting the frame pointer.  */
  {
    static const uint32_t insns[] = {
      0xa9bf7bfd, /* stp     x29, x30, [sp, #-16]! */
      0x52800020, /* mov     w0, #0x1 */
      0x910003fd, /* mov     x29, sp */
      0x528000a2, /* mov     w2, #0x5 */
      0x97fffff8, /* bl      6e4 */
    };

    instruction_reader_test reader (insns);

    trad_frame_reset_saved_regs (gdbarch, cache.saved_regs);
    CORE_ADDR end = aarch64_analyze_prologue (gdbarch, 0, 128, &cache, reader);

    /* We should stop at the 4th instruction.  */
    SELF_CHECK (end == (4 - 1) * 4);
    SELF_CHECK (cache.framereg == AARCH64_FP_REGNUM);
    SELF_CHECK (cache.framesize == 16);
  }

  /* Test handling of movz/stp when using the stack pointer as frame
     pointer.  */
  {
    static const uint32_t insns[] = {
      0xa9bc7bfd, /* stp     x29, x30, [sp, #-64]! */
      0x52800020, /* mov     w0, #0x1 */
      0x290207e0, /* stp     w0, w1, [sp, #16] */
      0xa9018fe2, /* stp     x2, x3, [sp, #24] */
      0x528000a2, /* mov     w2, #0x5 */
      0x97fffff8, /* bl      6e4 */
    };

    instruction_reader_test reader (insns);

    trad_frame_reset_saved_regs (gdbarch, cache.saved_regs);
    CORE_ADDR end = aarch64_analyze_prologue (gdbarch, 0, 128, &cache, reader);

    /* We should stop at the 5th instruction.  */
    SELF_CHECK (end == (5 - 1) * 4);
    SELF_CHECK (cache.framereg == AARCH64_SP_REGNUM);
    SELF_CHECK (cache.framesize == 64);
  }

  /* Test handling of movz/str when using the stack pointer as frame
     pointer  */
  {
    static const uint32_t insns[] = {
      0xa9bc7bfd, /* stp     x29, x30, [sp, #-64]! */
      0x52800020, /* mov     w0, #0x1 */
      0xb9002be4, /* str     w4, [sp, #40] */
      0xf9001be5, /* str     x5, [sp, #48] */
      0x528000a2, /* mov     w2, #0x5 */
      0x97fffff8, /* bl      6e4 */
    };

    instruction_reader_test reader (insns);

    trad_frame_reset_saved_regs (gdbarch, cache.saved_regs);
    CORE_ADDR end = aarch64_analyze_prologue (gdbarch, 0, 128, &cache, reader);

    /* We should stop at the 5th instruction.  */
    SELF_CHECK (end == (5 - 1) * 4);
    SELF_CHECK (cache.framereg == AARCH64_SP_REGNUM);
    SELF_CHECK (cache.framesize == 64);
  }

  /* Test handling of movz/stur when using the stack pointer as frame
     pointer.  */
  {
    static const uint32_t insns[] = {
      0xa9bc7bfd, /* stp     x29, x30, [sp, #-64]! */
      0x52800020, /* mov     w0, #0x1 */
      0xb80343e6, /* stur    w6, [sp, #52] */
      0xf80383e7, /* stur    x7, [sp, #56] */
      0x528000a2, /* mov     w2, #0x5 */
      0x97fffff8, /* bl      6e4 */
    };

    instruction_reader_test reader (insns);

    trad_frame_reset_saved_regs (gdbarch, cache.saved_regs);
    CORE_ADDR end = aarch64_analyze_prologue (gdbarch, 0, 128, &cache, reader);

    /* We should stop at the 5th instruction.  */
    SELF_CHECK (end == (5 - 1) * 4);
    SELF_CHECK (cache.framereg == AARCH64_SP_REGNUM);
    SELF_CHECK (cache.framesize == 64);
  }

  /* Test handling of movz when there is no frame pointer set or no stack
     pointer used.  */
  {
    static const uint32_t insns[] = {
      0xa9bf7bfd, /* stp     x29, x30, [sp, #-16]! */
      0x52800020, /* mov     w0, #0x1 */
      0x528000a2, /* mov     w2, #0x5 */
      0x97fffff8, /* bl      6e4 */
    };

    instruction_reader_test reader (insns);

    trad_frame_reset_saved_regs (gdbarch, cache.saved_regs);
    CORE_ADDR end = aarch64_analyze_prologue (gdbarch, 0, 128, &cache, reader);

    /* We should stop at the 4th instruction.  */
    SELF_CHECK (end == (4 - 1) * 4);
    SELF_CHECK (cache.framereg == AARCH64_SP_REGNUM);
    SELF_CHECK (cache.framesize == 16);
  }

  /* Test a prologue in which there is a return address signing instruction.  */
  if (tdep->has_pauth ())
    {
      static const uint32_t insns[] = {
	0xd503233f, /* paciasp */
	0xa9bd7bfd, /* stp	x29, x30, [sp, #-48]! */
	0x910003fd, /* mov	x29, sp */
	0xf801c3f3, /* str	x19, [sp, #28] */
	0xb9401fa0, /* ldr	x19, [x29, #28] */
      };
      instruction_reader_test reader (insns);

      trad_frame_reset_saved_regs (gdbarch, cache.saved_regs);
      CORE_ADDR end = aarch64_analyze_prologue (gdbarch, 0, 128, &cache,
						reader);

      SELF_CHECK (end == 4 * 4);
      SELF_CHECK (cache.framereg == AARCH64_FP_REGNUM);
      SELF_CHECK (cache.framesize == 48);

      for (int i = 0; i < AARCH64_X_REGISTER_COUNT; i++)
	{
	  if (i == 19)
	    SELF_CHECK (cache.saved_regs[i].addr == -20);
	  else if (i == AARCH64_FP_REGNUM)
	    SELF_CHECK (cache.saved_regs[i].addr == -48);
	  else if (i == AARCH64_LR_REGNUM)
	    SELF_CHECK (cache.saved_regs[i].addr == -40);
	  else
	    SELF_CHECK (cache.saved_regs[i].addr == -1);
	}

      if (tdep->has_pauth ())
	{
	  SELF_CHECK (trad_frame_value_p (cache.saved_regs,
					  tdep->pauth_ra_state_regnum));
	  SELF_CHECK (cache.saved_regs[tdep->pauth_ra_state_regnum].addr == 1);
	}
    }
}
} // namespace selftests
#endif /* GDB_SELF_TEST */

/* Implement the "skip_prologue" gdbarch method.  */

static CORE_ADDR
aarch64_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  CORE_ADDR func_addr, limit_pc;

  /* See if we can determine the end of the prologue via the symbol
     table.  If so, then return either PC, or the PC after the
     prologue, whichever is greater.  */
  if (find_pc_partial_function (pc, NULL, &func_addr, NULL))
    {
      CORE_ADDR post_prologue_pc
	= skip_prologue_using_sal (gdbarch, func_addr);

      if (post_prologue_pc != 0)
	return std::max (pc, post_prologue_pc);
    }

  /* Can't determine prologue from the symbol table, need to examine
     instructions.  */

  /* Find an upper limit on the function prologue using the debug
     information.  If the debug information could not be used to
     provide that bound, then use an arbitrary large number as the
     upper bound.  */
  limit_pc = skip_prologue_using_sal (gdbarch, pc);
  if (limit_pc == 0)
    limit_pc = pc + 128;	/* Magic.  */

  /* Try disassembling prologue.  */
  return aarch64_analyze_prologue (gdbarch, pc, limit_pc, NULL);
}

/* Scan the function prologue for THIS_FRAME and populate the prologue
   cache CACHE.  */

static void
aarch64_scan_prologue (struct frame_info *this_frame,
		       struct aarch64_prologue_cache *cache)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  CORE_ADDR block_addr = get_frame_address_in_block (this_frame);
  CORE_ADDR prologue_start;
  CORE_ADDR prologue_end;
  CORE_ADDR prev_pc = get_frame_pc (this_frame);
  struct gdbarch *gdbarch = get_frame_arch (this_frame);

  cache->prev_pc = prev_pc;

  /* Assume we do not find a frame.  */
  cache->framereg = -1;
  cache->framesize = 0;

  if (find_pc_partial_function (block_addr, NULL, &prologue_start,
				&prologue_end))
    {
      struct symtab_and_line sal = find_pc_line (prologue_start, 0);

      if (sal.line == 0)
	{
	  /* No line info so use the current PC.  */
	  prologue_end = prev_pc;
	}
      else if (sal.end < prologue_end)
	{
	  /* The next line begins after the function end.  */
	  prologue_end = sal.end;
	}

      if (aarch64_debug)
	debug_printf ("aarch64: %s Found function... \n", __func__);

      prologue_end = std::min (prologue_end, prev_pc);
      aarch64_analyze_prologue (gdbarch, prologue_start, prologue_end, cache);
    }
  else
    {
      CORE_ADDR frame_loc;

      if (aarch64_debug)
	debug_printf ("aarch64: %s Function not found... \n", __func__);

      frame_loc = get_frame_register_unsigned (this_frame, AARCH64_FP_REGNUM);
      if (frame_loc == 0)
	return;

      cache->framereg = AARCH64_FP_REGNUM;
      cache->framesize = 16;
      cache->saved_regs[29].addr = 0;
      cache->saved_regs[30].addr = 8;
    }
}

/* Fill in *CACHE with information about the prologue of *THIS_FRAME.  This
   function may throw an exception if the inferior's registers or memory is
   not available.  */

static void
aarch64_make_prologue_cache_1 (struct frame_info *this_frame,
			       struct aarch64_prologue_cache *cache)
{
  CORE_ADDR unwound_fp;
  int reg;

  aarch64_scan_prologue (this_frame, cache);

  if (cache->framereg == -1)
    return;

  unwound_fp = get_frame_register_unsigned (this_frame, cache->framereg);
  if (unwound_fp == 0)
    return;

  cache->prev_sp = unwound_fp + cache->framesize;

  /* Calculate actual addresses of saved registers using offsets
     determined by aarch64_analyze_prologue.  */
  for (reg = 0; reg < gdbarch_num_regs (get_frame_arch (this_frame)); reg++)
    if (trad_frame_addr_p (cache->saved_regs, reg))
      cache->saved_regs[reg].addr += cache->prev_sp;

  cache->func = get_frame_func (this_frame);

  cache->available_p = 1;
}

/* Allocate and fill in *THIS_CACHE with information about the prologue of
   *THIS_FRAME.  Do not do this is if *THIS_CACHE was already allocated.
   Return a pointer to the current aarch64_prologue_cache in
   *THIS_CACHE.  */

static struct aarch64_prologue_cache *
aarch64_make_prologue_cache (struct frame_info *this_frame, void **this_cache)
{
  struct aarch64_prologue_cache *cache;

  if (*this_cache != NULL)
    return (struct aarch64_prologue_cache *) *this_cache;

  cache = FRAME_OBSTACK_ZALLOC (struct aarch64_prologue_cache);
  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);
  *this_cache = cache;

  try
    {
      aarch64_make_prologue_cache_1 (this_frame, cache);
    }
  catch (const gdb_exception_error &ex)
    {
      if (ex.error != NOT_AVAILABLE_ERROR)
	throw;
    }

  return cache;
}

/* Implement the "stop_reason" frame_unwind method.  */

static enum unwind_stop_reason
aarch64_prologue_frame_unwind_stop_reason (struct frame_info *this_frame,
					   void **this_cache)
{
  struct aarch64_prologue_cache *cache
    = aarch64_make_prologue_cache (this_frame, this_cache);

  if (!cache->available_p)
    return UNWIND_UNAVAILABLE;

  /* Halt the backtrace at "_start".  */
  if (cache->prev_pc <= gdbarch_tdep (get_frame_arch (this_frame))->lowest_pc)
    return UNWIND_OUTERMOST;

  /* We've hit a wall, stop.  */
  if (cache->prev_sp == 0)
    return UNWIND_OUTERMOST;

  return UNWIND_NO_REASON;
}

/* Our frame ID for a normal frame is the current function's starting
   PC and the caller's SP when we were called.  */

static void
aarch64_prologue_this_id (struct frame_info *this_frame,
			  void **this_cache, struct frame_id *this_id)
{
  struct aarch64_prologue_cache *cache
    = aarch64_make_prologue_cache (this_frame, this_cache);

  if (!cache->available_p)
    *this_id = frame_id_build_unavailable_stack (cache->func);
  else
    *this_id = frame_id_build (cache->prev_sp, cache->func);
}

/* Implement the "prev_register" frame_unwind method.  */

static struct value *
aarch64_prologue_prev_register (struct frame_info *this_frame,
				void **this_cache, int prev_regnum)
{
  struct aarch64_prologue_cache *cache
    = aarch64_make_prologue_cache (this_frame, this_cache);

  struct gdbarch_tdep *tdep = gdbarch_tdep (get_frame_arch (this_frame));

  /* If we are asked to unwind the PC, then we need to return the LR
     instead.  The prologue may save PC, but it will point into this
     frame's prologue, not the next frame's resume location.

     We do the same for PCC and CLR.  */
  if (prev_regnum == AARCH64_PC_REGNUM || prev_regnum == tdep->cap_reg_pcc)
    {
      CORE_ADDR lr;
      struct gdbarch *gdbarch = get_frame_arch (this_frame);
      enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

      /* Fetch LR or CLR depending on the ABI.  */
      int lr_regnum;
      if (prev_regnum == AARCH64_PC_REGNUM)
	lr_regnum = AARCH64_LR_REGNUM;
      else
	lr_regnum = tdep->cap_reg_clr;

      struct value *lr_value = frame_unwind_register_value (this_frame,
							    lr_regnum);

      /* Make sure LR is available. If not, there is nothing we can do.  */
      if (lr_value == nullptr || (lr_value != nullptr
				  && value_optimized_out (lr_value)))
	throw_error (OPTIMIZED_OUT_ERROR, _("Register %d was not saved"),
		     prev_regnum);

      /* Extract only the bottom 8 bytes of CLR.  This truncates the capability
	 to 8 bytes.  For LR, this gets us the whole register.  */
      lr = extract_unsigned_integer (value_contents_all (lr_value), 8,
				     byte_order);

      if (tdep->has_pauth ()
	  && trad_frame_value_p (cache->saved_regs,
				 tdep->pauth_ra_state_regnum))
	lr = aarch64_frame_unmask_lr (tdep, this_frame, lr);

      /* Remove any potential LSB's in the address.  */
      lr = gdbarch_addr_bits_remove (gdbarch, lr);

      struct value *lr_value_adjusted
	  = frame_unwind_got_constant (this_frame, prev_regnum, lr);

      /* Copy the capability tag over, if it exists.  */
      if (prev_regnum == tdep->cap_reg_pcc && value_tagged (lr_value))
	{
	  set_value_tagged (lr_value_adjusted, 1);
	  set_value_tag (lr_value_adjusted, value_tag (lr_value));
	}

      return lr_value_adjusted;
    }

  /* SP is generally not saved to the stack, but this frame is
     identified by the next frame's stack pointer at the time of the
     call.  The value was already reconstructed into PREV_SP.  */
  /*
         +----------+  ^
         | saved lr |  |
      +->| saved fp |--+
      |  |          |
      |  |          |     <- Previous SP
      |  +----------+
      |  | saved lr |
      +--| saved fp |<- FP
         |          |
         |          |<- SP
         +----------+  */

  if (prev_regnum == AARCH64_SP_REGNUM || prev_regnum == tdep->cap_reg_csp)
    return frame_unwind_got_constant (this_frame, prev_regnum,
				      cache->prev_sp);

  return trad_frame_get_prev_register (this_frame, cache->saved_regs,
				       prev_regnum);
}

/* AArch64 prologue unwinder.  */
struct frame_unwind aarch64_prologue_unwind =
{
  NORMAL_FRAME,
  aarch64_prologue_frame_unwind_stop_reason,
  aarch64_prologue_this_id,
  aarch64_prologue_prev_register,
  NULL,
  default_frame_sniffer
};

/* Allocate and fill in *THIS_CACHE with information about the prologue of
   *THIS_FRAME.  Do not do this is if *THIS_CACHE was already allocated.
   Return a pointer to the current aarch64_prologue_cache in
   *THIS_CACHE.  */

static struct aarch64_prologue_cache *
aarch64_make_stub_cache (struct frame_info *this_frame, void **this_cache)
{
  struct aarch64_prologue_cache *cache;

  if (*this_cache != NULL)
    return (struct aarch64_prologue_cache *) *this_cache;

  cache = FRAME_OBSTACK_ZALLOC (struct aarch64_prologue_cache);
  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);
  *this_cache = cache;

  try
    {
      cache->prev_sp = get_frame_register_unsigned (this_frame,
						    AARCH64_SP_REGNUM);
      cache->prev_pc = get_frame_pc (this_frame);
      cache->available_p = 1;
    }
  catch (const gdb_exception_error &ex)
    {
      if (ex.error != NOT_AVAILABLE_ERROR)
	throw;
    }

  return cache;
}

/* Implement the "stop_reason" frame_unwind method.  */

static enum unwind_stop_reason
aarch64_stub_frame_unwind_stop_reason (struct frame_info *this_frame,
				       void **this_cache)
{
  struct aarch64_prologue_cache *cache
    = aarch64_make_stub_cache (this_frame, this_cache);

  if (!cache->available_p)
    return UNWIND_UNAVAILABLE;

  return UNWIND_NO_REASON;
}

/* Our frame ID for a stub frame is the current SP and LR.  */

static void
aarch64_stub_this_id (struct frame_info *this_frame,
		      void **this_cache, struct frame_id *this_id)
{
  struct aarch64_prologue_cache *cache
    = aarch64_make_stub_cache (this_frame, this_cache);

  if (cache->available_p)
    *this_id = frame_id_build (cache->prev_sp, cache->prev_pc);
  else
    *this_id = frame_id_build_unavailable_stack (cache->prev_pc);
}

/* Implement the "sniffer" frame_unwind method.  */

static int
aarch64_stub_unwind_sniffer (const struct frame_unwind *self,
			     struct frame_info *this_frame,
			     void **this_prologue_cache)
{
  CORE_ADDR addr_in_block;
  gdb_byte dummy[4];

  addr_in_block = get_frame_address_in_block (this_frame);
  if (in_plt_section (addr_in_block)
      /* We also use the stub winder if the target memory is unreadable
	 to avoid having the prologue unwinder trying to read it.  */
      || target_read_memory (get_frame_pc (this_frame), dummy, 4) != 0)
    return 1;

  return 0;
}

/* AArch64 stub unwinder.  */
struct frame_unwind aarch64_stub_unwind =
{
  NORMAL_FRAME,
  aarch64_stub_frame_unwind_stop_reason,
  aarch64_stub_this_id,
  aarch64_prologue_prev_register,
  NULL,
  aarch64_stub_unwind_sniffer
};

/* Return the frame base address of *THIS_FRAME.  */

static CORE_ADDR
aarch64_normal_frame_base (struct frame_info *this_frame, void **this_cache)
{
  struct aarch64_prologue_cache *cache
    = aarch64_make_prologue_cache (this_frame, this_cache);

  return cache->prev_sp - cache->framesize;
}

/* AArch64 default frame base information.  */
struct frame_base aarch64_normal_base =
{
  &aarch64_prologue_unwind,
  aarch64_normal_frame_base,
  aarch64_normal_frame_base,
  aarch64_normal_frame_base
};

/* Return the value of the REGNUM register in the previous frame of
   *THIS_FRAME.  */

static struct value *
aarch64_dwarf2_prev_register (struct frame_info *this_frame,
			      void **this_cache, int regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (regnum == AARCH64_PC_REGNUM || regnum == tdep->cap_reg_pcc)
    {
      /* Fetch LR or CLR depending on the ABI.  */
      int lr_regnum;
      if (regnum == AARCH64_PC_REGNUM)
	lr_regnum = AARCH64_LR_REGNUM;
      else
	lr_regnum = tdep->cap_reg_clr;

      struct value *lr_value = frame_unwind_register_value (this_frame,
							    lr_regnum);

      /* Make sure LR is available. If not, there is nothing we can do.  */
      if (lr_value == nullptr || (lr_value != nullptr
				  && value_optimized_out (lr_value)))
	throw_error (OPTIMIZED_OUT_ERROR, _("Register %d was not saved"),
		     regnum);

      /* Extract only the bottom 8 bytes of CLR.  This truncates the capability
	 to 8 bytes.  For LR, this gets us the whole register.  */
      CORE_ADDR lr = extract_unsigned_integer (value_contents_all (lr_value), 8,
					        gdbarch_byte_order (gdbarch));

      lr = aarch64_frame_unmask_lr (tdep, this_frame, lr);
      lr = gdbarch_addr_bits_remove (gdbarch, lr);

      struct value *lr_value_adjusted
	  = frame_unwind_got_constant (this_frame, regnum, lr);

      /* Copy the capability tag over, if it exists.  */
      if (regnum == tdep->cap_reg_pcc && value_tagged (lr_value))
	{
	  set_value_tagged (lr_value_adjusted, 1);
	  set_value_tag (lr_value_adjusted, value_tag (lr_value));
	}

      return lr_value_adjusted;
    }

  internal_error (__FILE__, __LINE__, _("Unexpected register %d"), regnum);
}

static const unsigned char op_lit0 = DW_OP_lit0;
static const unsigned char op_lit1 = DW_OP_lit1;

/* Implement the "init_reg" dwarf2_frame_ops method.  */

static void
aarch64_dwarf2_frame_init_reg (struct gdbarch *gdbarch, int regnum,
			       struct dwarf2_frame_state_reg *reg,
			       struct frame_info *this_frame)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (regnum == AARCH64_PC_REGNUM || regnum == tdep->cap_reg_pcc)
    {
      reg->how = DWARF2_FRAME_REG_FN;
      reg->loc.fn = aarch64_dwarf2_prev_register;
      return;
    }

  if (regnum == AARCH64_SP_REGNUM || regnum == tdep->cap_reg_csp)
    {
      reg->how = DWARF2_FRAME_REG_CFA;
      return;
    }

  /* Init pauth registers.  */
  if (tdep->has_pauth ())
    {
      if (regnum == tdep->pauth_ra_state_regnum)
	{
	  /* Initialize RA_STATE to zero.  */
	  reg->how = DWARF2_FRAME_REG_SAVED_VAL_EXP;
	  reg->loc.exp.start = &op_lit0;
	  reg->loc.exp.len = 1;
	  return;
	}
      else if (regnum == AARCH64_PAUTH_DMASK_REGNUM (tdep->pauth_reg_base)
	       || regnum == AARCH64_PAUTH_CMASK_REGNUM (tdep->pauth_reg_base))
	{
	  reg->how = DWARF2_FRAME_REG_SAME_VALUE;
	  return;
	}
    }
}

/* Implement the execute_dwarf_cfa_vendor_op method.  */

static bool
aarch64_execute_dwarf_cfa_vendor_op (struct gdbarch *gdbarch, gdb_byte op,
				     struct dwarf2_frame_state *fs)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  struct dwarf2_frame_state_reg *ra_state;

  if (op == DW_CFA_AARCH64_negate_ra_state)
    {
      /* On systems without pauth, treat as a nop.  */
      if (!tdep->has_pauth ())
	return true;

      /* Allocate RA_STATE column if it's not allocated yet.  */
      fs->regs.alloc_regs (AARCH64_DWARF_PAUTH_RA_STATE + 1);

      /* Toggle the status of RA_STATE between 0 and 1.  */
      ra_state = &(fs->regs.reg[AARCH64_DWARF_PAUTH_RA_STATE]);
      ra_state->how = DWARF2_FRAME_REG_SAVED_VAL_EXP;

      if (ra_state->loc.exp.start == nullptr
	  || ra_state->loc.exp.start == &op_lit0)
	ra_state->loc.exp.start = &op_lit1;
      else
	ra_state->loc.exp.start = &op_lit0;

      ra_state->loc.exp.len = 1;

      return true;
    }

  return false;
}

/* Used for matching BRK instructions for AArch64.  */
static constexpr uint32_t BRK_INSN_MASK = 0xffe0001f;
static constexpr uint32_t BRK_INSN_BASE = 0xd4200000;

/* Implementation of gdbarch_program_breakpoint_here_p for aarch64.  */

static bool
aarch64_program_breakpoint_here_p (gdbarch *gdbarch, CORE_ADDR address)
{
  const uint32_t insn_len = 4;
  gdb_byte target_mem[4];

  /* Enable the automatic memory restoration from breakpoints while
     we read the memory.  Otherwise we may find temporary breakpoints, ones
     inserted by GDB, and flag them as permanent breakpoints.  */
  scoped_restore restore_memory
    = make_scoped_restore_show_memory_breakpoints (0);

  if (target_read_memory (address, target_mem, insn_len) == 0)
    {
      uint32_t insn =
	(uint32_t) extract_unsigned_integer (target_mem, insn_len,
					     gdbarch_byte_order_for_code (gdbarch));

      /* Check if INSN is a BRK instruction pattern.  There are multiple choices
	 of such instructions with different immediate values.  Different OS'
	 may use a different variation, but they have the same outcome.  */
	return ((insn & BRK_INSN_MASK) == BRK_INSN_BASE);
    }

  return false;
}

/* When arguments must be pushed onto the stack, they go on in reverse
   order.  The code below implements a FILO (stack) to do this.  */

struct stack_item_t
{
  /* Value to pass on stack.  It can be NULL if this item is for stack
     padding.  */
  const gdb_byte *data;

  /* Size in bytes of value to pass on stack.  */
  int len;

  /* The argument value, in case further processing is needed.  */
  struct value *arg_value;
};

/* Implement the gdbarch type alignment method, overrides the generic
   alignment algorithm for anything that is aarch64 specific.  */

static ULONGEST
aarch64_type_align (gdbarch *gdbarch, struct type *t)
{
  t = check_typedef (t);
  if (t->code () == TYPE_CODE_ARRAY && t->is_vector ())
    {
      /* Use the natural alignment for vector types (the same for
	 scalar type), but the maximum alignment is 128-bit.  */
      if (TYPE_LENGTH (t) > 16)
	return 16;
      else
	return TYPE_LENGTH (t);
    }

  /* Allow the common code to calculate the alignment.  */
  return 0;
}

/* Worker function for aapcs_is_vfp_call_or_return_candidate.

   Return the number of register required, or -1 on failure.

   When encountering a base element, if FUNDAMENTAL_TYPE is not set then set it
   to the element, else fail if the type of this element does not match the
   existing value.  */

static int
aapcs_is_vfp_call_or_return_candidate_1 (struct type *type,
					 struct type **fundamental_type)
{
  if (type == nullptr)
    return -1;

  switch (type->code ())
    {
    case TYPE_CODE_FLT:
      if (TYPE_LENGTH (type) > 16)
	return -1;

      if (*fundamental_type == nullptr)
	*fundamental_type = type;
      else if (TYPE_LENGTH (type) != TYPE_LENGTH (*fundamental_type)
	       || type->code () != (*fundamental_type)->code ())
	return -1;

      return 1;

    case TYPE_CODE_COMPLEX:
      {
	struct type *target_type = check_typedef (TYPE_TARGET_TYPE (type));
	if (TYPE_LENGTH (target_type) > 16)
	  return -1;

	if (*fundamental_type == nullptr)
	  *fundamental_type = target_type;
	else if (TYPE_LENGTH (target_type) != TYPE_LENGTH (*fundamental_type)
		 || target_type->code () != (*fundamental_type)->code ())
	  return -1;

	return 2;
      }

    case TYPE_CODE_ARRAY:
      {
	if (type->is_vector ())
	  {
	    if (TYPE_LENGTH (type) != 8 && TYPE_LENGTH (type) != 16)
	      return -1;

	    if (*fundamental_type == nullptr)
	      *fundamental_type = type;
	    else if (TYPE_LENGTH (type) != TYPE_LENGTH (*fundamental_type)
		     || type->code () != (*fundamental_type)->code ())
	      return -1;

	    return 1;
	  }
	else
	  {
	    struct type *target_type = TYPE_TARGET_TYPE (type);
	    int count = aapcs_is_vfp_call_or_return_candidate_1
			  (target_type, fundamental_type);

	    if (count == -1)
	      return count;

	    count *= (TYPE_LENGTH (type) / TYPE_LENGTH (target_type));
	      return count;
	  }
      }

    case TYPE_CODE_STRUCT:
    case TYPE_CODE_UNION:
      {
	int count = 0;

	for (int i = 0; i < type->num_fields (); i++)
	  {
	    /* Ignore any static fields.  */
	    if (field_is_static (&type->field (i)))
	      continue;

	    struct type *member = check_typedef (type->field (i).type ());

	    int sub_count = aapcs_is_vfp_call_or_return_candidate_1
			      (member, fundamental_type);
	    if (sub_count == -1)
	      return -1;
	    count += sub_count;
	  }

	/* Ensure there is no padding between the fields (allowing for empty
	   zero length structs)  */
	int ftype_length = (*fundamental_type == nullptr)
			   ? 0 : TYPE_LENGTH (*fundamental_type);
	if (count * ftype_length != TYPE_LENGTH (type))
	  return -1;

	return count;
      }

    default:
      break;
    }

  return -1;
}

/* Return true if an argument, whose type is described by TYPE, can be passed or
   returned in simd/fp registers, providing enough parameter passing registers
   are available.  This is as described in the AAPCS64.

   Upon successful return, *COUNT returns the number of needed registers,
   *FUNDAMENTAL_TYPE contains the type of those registers.

   Candidate as per the AAPCS64 5.4.2.C is either a:
   - float.
   - short-vector.
   - HFA (Homogeneous Floating-point Aggregate, 4.3.5.1). A Composite type where
     all the members are floats and has at most 4 members.
   - HVA (Homogeneous Short-vector Aggregate, 4.3.5.2). A Composite type where
     all the members are short vectors and has at most 4 members.
   - Complex (7.1.1)

   Note that HFAs and HVAs can include nested structures and arrays.  */

static bool
aapcs_is_vfp_call_or_return_candidate (struct type *type, int *count,
				       struct type **fundamental_type)
{
  if (type == nullptr)
    return false;

  *fundamental_type = nullptr;

  int ag_count = aapcs_is_vfp_call_or_return_candidate_1 (type,
							  fundamental_type);

  if (ag_count > 0 && ag_count <= HA_MAX_NUM_FLDS)
    {
      *count = ag_count;
      return true;
    }
  else
    return false;
}

/* AArch64 function call information structure.  */
struct aarch64_call_info
{
  /* the current argument number.  */
  unsigned argnum = 0;

  /* The next general purpose register number, equivalent to NGRN as
     described in the AArch64 Procedure Call Standard.  */
  unsigned ngrn = 0;

  /* The next SIMD and floating point register number, equivalent to
     NSRN as described in the AArch64 Procedure Call Standard.  */
  unsigned nsrn = 0;

  /* The next stacked argument address, equivalent to NSAA as
     described in the AArch64 Procedure Call Standard.  */
  unsigned nsaa = 0;

  /* Stack item vector.  */
  std::vector<stack_item_t> si;
};

/* Helper function. Returns true if REGNUM is a tagged register, otherwise
   returns false.  */

static bool
morello_is_tagged_register (struct gdbarch *gdbarch, int regnum)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  /* Only Morello's registers have tags.  */
  if (!tdep->has_capability ())
    return false;

  /* The last two registers of the C register set don't have tags.  */
  if (regnum < tdep->cap_reg_base ||
      regnum > tdep->cap_reg_last - 2)
    return false;

  return true;
}

/* Implementation of the gdbarch_register_set_tag hook.  */

static void
aarch64_register_set_tag (struct gdbarch *gdbarch, struct regcache *regcache,
			  int regnum, bool tag)
{
  if (!morello_is_tagged_register (gdbarch, regnum))
    return;

  CORE_ADDR tag_map = 0;
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  /* Read the tag register, adjust and write back.  */
  regcache->cooked_read (tdep->cap_reg_last - 1, (gdb_byte *) &tag_map);

  /* The CSP/PCC tags are swapped in the tag_map because the ordering of CSP/PCC
     in struct user_morello_state is different from GDB's register description.

     Make sure we account for that when setting the tag from those
     registers.  */
  if (regnum == tdep->cap_reg_pcc)
    regnum = tdep->cap_reg_csp;
  else if (regnum == tdep->cap_reg_csp)
    regnum = tdep->cap_reg_pcc;

  int shift = regnum - tdep->cap_reg_base;
  tag_map = _set_bit (tag_map, shift, tag ? 1 : 0);
  regcache->cooked_write (tdep->cap_reg_last - 1, (gdb_byte *) &tag_map);
}

/* Pass a value in a sequence of consecutive C registers.  The caller
   is responsible for ensuring sufficient registers are available.  */

static void
pass_in_c (struct gdbarch *gdbarch, struct regcache *regcache,
	   struct aarch64_call_info *info, struct type *type,
	   struct value *arg)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  int regnum = tdep->cap_reg_base + info->ngrn;
  const gdb_byte *buf = value_contents (arg);
  gdb_byte tmpbuf[C_REGISTER_SIZE];
  size_t len = TYPE_LENGTH (type);
  size_t xfer_len = 0;
  CORE_ADDR address = value_address (arg);

  /* One more argument allocated.  */
  info->argnum++;

  while (len > 0)
    {
      /* Determine the transfer size.  */
      xfer_len = len < C_REGISTER_SIZE ? len : C_REGISTER_SIZE;
      /* Zero out any unspecified bytes.  */
      memset (tmpbuf, 0, C_REGISTER_SIZE);
      memcpy (tmpbuf, buf, xfer_len);

      if (aarch64_debug)
	{
	  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
	  CORE_ADDR regval
	    = extract_unsigned_integer (tmpbuf, xfer_len, byte_order);

	  CORE_ADDR regval2;
	  if (xfer_len > 8)
	    regval2
	      = extract_unsigned_integer (tmpbuf + 8, xfer_len, byte_order);
	  else
	    regval2 = 0;

	  debug_printf ("arg %d in %s = 0x%s 0x%s\n", info->argnum,
			gdbarch_register_name (gdbarch, regnum),
			phex (regval, X_REGISTER_SIZE),
			phex (regval2, X_REGISTER_SIZE));
	}

      /* Write the argument to the capability register.  */
      regcache->raw_write (regnum, tmpbuf);

      if (type->contains_capability () || type->code () == TYPE_CODE_CAPABILITY
	  || TYPE_CAPABILITY (type))
	{
	  /* We need to read the tags from memory.  */
	  gdb::byte_vector cap = target_read_capability (address);
	  bool tag = cap[0] == 0 ? false : true;
	  aarch64_register_set_tag (gdbarch, regcache, regnum, tag);

	  if (aarch64_debug)
	    debug_printf ("aarch64: %s Read tag %s from address %s\n",
			  __func__, tag == true ? "true" : "false",
			  paddress (gdbarch, address));

	  address += xfer_len;
	}

      len -= xfer_len;
      buf += xfer_len;
      regnum++;
    }
  if (aarch64_debug)
    debug_printf ("aarch64: leaving %s\n", __func__);
}

/* Pass a value in a sequence of consecutive X registers.  The caller
   is responsible for ensuring sufficient registers are available.  */

static void
pass_in_x (struct gdbarch *gdbarch, struct regcache *regcache,
	   struct aarch64_call_info *info, struct type *type,
	   struct value *arg)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int len = TYPE_LENGTH (type);
  enum type_code typecode = type->code ();
  int regnum = AARCH64_X0_REGNUM + info->ngrn;
  const bfd_byte *buf = value_contents (arg);

  info->argnum++;

  while (len > 0)
    {
      int partial_len = len < X_REGISTER_SIZE ? len : X_REGISTER_SIZE;
      CORE_ADDR regval = extract_unsigned_integer (buf, partial_len,
						   byte_order);


      /* Adjust sub-word struct/union args when big-endian.  */
      if (byte_order == BFD_ENDIAN_BIG
	  && partial_len < X_REGISTER_SIZE
	  && (typecode == TYPE_CODE_STRUCT || typecode == TYPE_CODE_UNION))
	regval <<= ((X_REGISTER_SIZE - partial_len) * TARGET_CHAR_BIT);

      if (aarch64_debug)
	{
	  debug_printf ("arg %d in %s = 0x%s\n", info->argnum,
			gdbarch_register_name (gdbarch, regnum),
			phex (regval, X_REGISTER_SIZE));
	}
      regcache_cooked_write_unsigned (regcache, regnum, regval);
      len -= partial_len;
      buf += partial_len;
      regnum++;
    }
  if (aarch64_debug)
    debug_printf ("aarch64: leaving %s\n", __func__);
}

/* Attempt to marshall a value in a V register.  Return 1 if
   successful, or 0 if insufficient registers are available.  This
   function, unlike the equivalent pass_in_x() function does not
   handle arguments spread across multiple registers.  */

static int
pass_in_v (struct gdbarch *gdbarch,
	   struct regcache *regcache,
	   struct aarch64_call_info *info,
	   int len, const bfd_byte *buf)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  if (info->nsrn < 8)
    {
      int regnum = AARCH64_V0_REGNUM + info->nsrn;
      /* Enough space for a full vector register.  */
      gdb_byte reg[register_size (gdbarch, regnum)];
      gdb_assert (len <= sizeof (reg));

      info->argnum++;
      info->nsrn++;

      memset (reg, 0, sizeof (reg));
      /* PCS C.1, the argument is allocated to the least significant
	 bits of V register.  */
      memcpy (reg, buf, len);
      regcache->cooked_write (regnum, reg);

      if (aarch64_debug)
	{
	  debug_printf ("arg %d in %s\n", info->argnum,
			gdbarch_register_name (gdbarch, regnum));
	}
      if (aarch64_debug)
	debug_printf ("aarch64: leaving %s\n", __func__);

      return 1;
    }
  info->nsrn = 8;

  if (aarch64_debug)
    debug_printf ("aarch64: leaving %s\n", __func__);

  return 0;
}

/* Marshall an argument onto the stack.  */

static void
pass_on_stack (struct aarch64_call_info *info, struct type *type,
	       struct value *arg)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  const bfd_byte *buf = value_contents (arg);
  int len = TYPE_LENGTH (type);
  int align;
  stack_item_t item;

  info->argnum++;

  align = type_align (type);

  /* PCS C.17 Stack should be aligned to the larger of 8 bytes or the
     Natural alignment of the argument's type.  */
  align = align_up (align, 8);

  /* The AArch64 PCS requires at most doubleword alignment.  */
  if (align > 16)
    align = 16;

  if (aarch64_debug)
    {
      debug_printf ("arg %d len=%d @ sp + %d\n", info->argnum, len,
		    info->nsaa);
    }

  item.len = len;
  item.data = buf;
  item.arg_value = arg;
  info->si.push_back (item);

  info->nsaa += len;
  if (info->nsaa & (align - 1))
    {
      /* Push stack alignment padding.  */
      int pad = align - (info->nsaa & (align - 1));

      item.len = pad;
      item.data = NULL;

      info->si.push_back (item);
      info->nsaa += pad;
    }
  if (aarch64_debug)
    debug_printf ("aarch64: leaving %s\n", __func__);
}

/* Marshall an argument into a sequence of one or more consecutive C
   registers or, if insufficient C registers are available then onto
   the stack.  */

static void
pass_in_c_or_stack (struct gdbarch *gdbarch, struct regcache *regcache,
		    struct aarch64_call_info *info, struct type *type,
		    struct value *arg)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  int len = TYPE_LENGTH (type);
  int nregs = (len + C_REGISTER_SIZE - 1) / C_REGISTER_SIZE;

  if (info->ngrn + nregs <= 8)
    {
      pass_in_c (gdbarch, regcache, info, type, arg);
      info->ngrn += nregs;
    }
  else
    {
      info->ngrn = 8;
      pass_on_stack (info, type, arg);
    }

  if (aarch64_debug)
    debug_printf ("aarch64: leaving %s\n", __func__);
}

/* Marshall an argument into a sequence of one or more consecutive X
   registers or, if insufficient X registers are available then onto
   the stack.  */

static void
pass_in_x_or_stack (struct gdbarch *gdbarch, struct regcache *regcache,
		    struct aarch64_call_info *info, struct type *type,
		    struct value *arg)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  int len = TYPE_LENGTH (type);
  int nregs = (len + X_REGISTER_SIZE - 1) / X_REGISTER_SIZE;

  /* PCS C.13 - Pass in registers if we have enough spare */
  if (info->ngrn + nregs <= 8)
    {
      pass_in_x (gdbarch, regcache, info, type, arg);
      info->ngrn += nregs;
    }
  else
    {
      info->ngrn = 8;
      pass_on_stack (info, type, arg);
    }

  if (aarch64_debug)
    debug_printf ("aarch64: leaving %s\n", __func__);
}

/* Morello: Marshall an argument into a sequence of one or more C registers.
   If we should not pass arguments in C registers, then try X registers or
   the stack.  */

static void
pass_in_c_x_or_stack (struct gdbarch *gdbarch, struct regcache *regcache,
		      struct aarch64_call_info *info, struct type *type,
		      struct value *arg)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  /* Check if we have a case where we need to pass arguments via the C
     registers.  */
  if (TYPE_CAPABILITY (type) || type->contains_capability ())
    pass_in_c_or_stack (gdbarch, regcache, info, type, arg);
  else
    pass_in_x_or_stack (gdbarch, regcache, info, type, arg);

  if (aarch64_debug)
    debug_printf ("aarch64: leaving %s\n", __func__);
}

/* Pass a value, which is of type arg_type, in a V register.  Assumes value is a
   aapcs_is_vfp_call_or_return_candidate and there are enough spare V
   registers.  A return value of false is an error state as the value will have
   been partially passed to the stack.  */
static bool
pass_in_v_vfp_candidate (struct gdbarch *gdbarch, struct regcache *regcache,
			 struct aarch64_call_info *info, struct type *arg_type,
			 struct value *arg)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  switch (arg_type->code ())
    {
    case TYPE_CODE_FLT:
      return pass_in_v (gdbarch, regcache, info, TYPE_LENGTH (arg_type),
			value_contents (arg));
      break;

    case TYPE_CODE_COMPLEX:
      {
	const bfd_byte *buf = value_contents (arg);
	struct type *target_type = check_typedef (TYPE_TARGET_TYPE (arg_type));

	if (!pass_in_v (gdbarch, regcache, info, TYPE_LENGTH (target_type),
			buf))
	  return false;

	return pass_in_v (gdbarch, regcache, info, TYPE_LENGTH (target_type),
			  buf + TYPE_LENGTH (target_type));
      }

    case TYPE_CODE_ARRAY:
      if (arg_type->is_vector ())
	return pass_in_v (gdbarch, regcache, info, TYPE_LENGTH (arg_type),
			  value_contents (arg));
      /* fall through.  */

    case TYPE_CODE_STRUCT:
    case TYPE_CODE_UNION:
      for (int i = 0; i < arg_type->num_fields (); i++)
	{
	  /* Don't include static fields.  */
	  if (field_is_static (&arg_type->field (i)))
	    continue;

	  struct value *field = value_primitive_field (arg, 0, i, arg_type);
	  struct type *field_type = check_typedef (value_type (field));

	  if (!pass_in_v_vfp_candidate (gdbarch, regcache, info, field_type,
					field))
	    return false;
	}
      return true;

    default:
      return false;
    }
}

static bool
type_fields_overlap_capabilities (struct type *type)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  /* Types not containing capabilities and having sizes smaller than
     8 bytes don't have members overlapping capabilities.  */
  if (!type->contains_capability () || TYPE_LENGTH (type) < 8)
    return false;

  /* Byte range 8~15 */
  int range_1_position = 8 * TARGET_CHAR_BIT;
  /* Byte range 24~31 */
  int range_2_position = 192 * TARGET_CHAR_BIT;
  int range_bitsize = 8 * TARGET_CHAR_BIT;

  for (int index = 0; index < type->num_fields (); index++)
    {
      if (type->field (index).type ()->code () == TYPE_CODE_CAPABILITY
	  || type->field (index).type ()->code () == TYPE_CODE_PTR)
	continue;

      int bitpos = TYPE_FIELD_BITPOS (type, index);
      int bitsize = TYPE_FIELD_BITSIZE (type, index);

      /* Test bytes 8~15.  */
      if (range_1_position <= (bitpos + bitsize)
	  && bitpos <= (range_1_position + range_bitsize))
	return true;

      /* Test bytes 24~31.  */
      if (range_2_position <= (bitpos + bitsize)
	  && bitpos <= (range_2_position + range_bitsize))
	return true;
    }
  return false;
}

/* Convert a 64-bit pointer to a capability using the SOURCE capability.  */

static struct value *
convert_pointer_to_capability (struct gdbarch *gdbarch, struct value *source,
			       CORE_ADDR pointer)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  gdb_assert (TYPE_CAPABILITY (value_type (source)));

  if (source == nullptr)
    return nullptr;

  if (value_contents (source) == nullptr)
    return nullptr;

  capability cap;

  memcpy (&cap.m_cap, value_contents (source), sizeof (cap.m_cap));

  if (value_tagged (source))
    cap.set_tag (value_tag (source));

  /* Adjust the capability value to that of the pointer.  This assumes the
     capability has enough bounds to honor this value.  */
  cap.set_value (pointer);

  struct value *result = value_copy (source);

  /* Adjust the contents of the new capability.  */
  memcpy (value_contents_writeable (result), &cap.m_cap, sizeof (cap.m_cap));
  set_value_tag (result, cap.get_tag ());

  return result;
}

/* Write the contents of ARG to DESTINATION, also taking care of copying the
   tags from ARG's source location to the destination location.  */

static void
morello_write_memory_with_capabilities (CORE_ADDR destination,
					struct value *arg)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  gdb_assert (arg != nullptr);

  struct type *type = value_type (arg);
  const gdb_byte *buffer = value_contents (arg);
  size_t size = TYPE_LENGTH (type);
  CORE_ADDR source = value_address (arg);

  write_memory (destination, buffer, size);

  if (!type->contains_capability ())
    return;

  /* If the type contains capabilities, we need to copy the tags as well.
     Given this type contains capabilities, the data should be aligned to
     16-bytes, which matches the tag granule.  */
  int granules = size / MORELLO_MEMORY_TAG_GRANULE_SIZE;

  while (granules != 0)
    {
      /* Read both the source capability and the destination capability.  */
      gdb::byte_vector source_cap = target_read_capability (source);
      gdb::byte_vector dest_cap = target_read_capability (destination);

      /* Copy the source tag granule to the destination tag granule.  */
      dest_cap[0] = source_cap[0];
      target_write_capability (destination, dest_cap);
      granules--;

      source += MORELLO_MEMORY_TAG_GRANULE_SIZE;
      destination += MORELLO_MEMORY_TAG_GRANULE_SIZE;
    }

  if (aarch64_debug)
    debug_printf ("aarch64: Exiting %s\n", __func__);
}

/* Implement the "push_dummy_call" gdbarch method for Morello.  */

static CORE_ADDR
morello_push_dummy_call (struct gdbarch *gdbarch, struct value *function,
			 struct regcache *regcache, CORE_ADDR bp_addr,
			 int nargs,
			 struct value **args, CORE_ADDR sp,
			 function_call_return_method return_method,
			 CORE_ADDR struct_addr)
{
  int argnum;
  struct aarch64_call_info info;
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  /* We should only be here if this is a Morello architecture.  */
  gdb_assert (tdep->has_capability ());

  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  if (aarch64_debug)
    debug_printf ("aarch64: %s Number of arguments: %s\n", __func__,
		  pulongest (nargs));

  /* Morello AAPCS64-cap ABI.  */
  bool aapcs64_cap = (tdep->abi == AARCH64_ABI_AAPCS64_CAP);

  if (aarch64_debug)
    {
      if (aapcs64_cap)
	debug_printf ("aarch64: %s ABI is AAPCS64-CAP\n", __func__);
      else
	debug_printf ("aarch64: %s ABI is AAPCS64\n", __func__);
    }

  /* We need to know what the type of the called function is in order
     to determine the number of named/anonymous arguments for the
     actual argument placement, and the return type in order to handle
     return value correctly.

     The generic code above us views the decision of return in memory
     or return in registers as a two stage processes.  The language
     handler is consulted first and may decide to return in memory (eg
     class with copy constructor returned by value), this will cause
     the generic code to allocate space AND insert an initial leading
     argument.

     If the language code does not decide to pass in memory then the
     target code is consulted.

     If the language code decides to pass in memory we want to move
     the pointer inserted as the initial argument from the argument
     list and into X8, the conventional AArch64 struct return pointer
     register.  */

  /* Set the return address.  For the AArch64, the return breakpoint
     is always at BP_ADDR.  */

  /* We should use CLR for AARCH64-CAP and LR for AAPCS64.  */
  int regnum = AARCH64_LR_REGNUM;

  if (aapcs64_cap)
    {
      regnum = tdep->cap_reg_clr;

      /* For now, assume BP_ADDR is within the bounds of the CLR
	 capability.  */
      struct value *clr = regcache->cooked_read_value (regnum);
      regcache->cooked_write (regnum, value_contents (clr));
      aarch64_register_set_tag (gdbarch, regcache, regnum, value_tag (clr));
    }

  if (aarch64_debug)
    debug_printf ("aarch64: Breakpoint address in %s is %s\n",
		  gdbarch_register_name (gdbarch, regnum),
		  paddress (gdbarch, bp_addr));

  regcache_cooked_write_unsigned (regcache, AARCH64_LR_REGNUM, bp_addr);

  /* If we were given an initial argument for the return slot, lose it.  */
  if (return_method == return_method_hidden_param)
    {
      args++;
      nargs--;
    }

  /* The struct_return pointer occupies X8.  */
  if (return_method != return_method_normal)
    {
      /* We should use C8 for AARCH64-CAP and X8 for AAPCS64.  */
      regnum = AARCH64_STRUCT_RETURN_REGNUM;

      if (aapcs64_cap)
	{
	  regnum = tdep->cap_reg_base + AARCH64_STRUCT_RETURN_REGNUM;

	  /* For now, assume STRUCT_ADDR is within the bounds of the CSP
	     capability.  */
	  struct value *csp = regcache->cooked_read_value (regnum);
	  regcache->cooked_write (regnum, value_contents (csp));
	  aarch64_register_set_tag (gdbarch, regcache, regnum, value_tag (csp));
	}

      if (aarch64_debug)
	{
	  debug_printf ("aarch64: struct return in %s = 0x%s\n",
			gdbarch_register_name (gdbarch,
					       regnum),
			paddress (gdbarch, struct_addr));
	}

      regcache_cooked_write_unsigned (regcache, AARCH64_STRUCT_RETURN_REGNUM,
				      struct_addr);
    }

  for (argnum = 0; argnum < nargs; argnum++)
    {
      struct value *arg = args[argnum];
      struct type *arg_type, *fundamental_type;
      int len, elements;

      if (aarch64_debug)
	debug_printf ("aarch64: %s Processing argument %s\n", __func__,
		      pulongest (argnum));

      arg_type = check_typedef (value_type (arg));
      len = TYPE_LENGTH (arg_type);

      /* If arg can be passed in v registers as per the AAPCS64, then do so if
	 if there are enough spare registers.  */
      if (aapcs_is_vfp_call_or_return_candidate (arg_type, &elements,
						 &fundamental_type))
	{
	  if (info.nsrn + elements <= 8)
	    {
	      /* We know that we have sufficient registers available therefore
		 this will never need to fallback to the stack.  */
	      if (!pass_in_v_vfp_candidate (gdbarch, regcache, &info, arg_type,
					    arg))
		gdb_assert_not_reached ("Failed to push args");
	    }
	  else
	    {
	      info.nsrn = 8;
	      pass_on_stack (&info, arg_type, arg);
	    }
	  continue;
	}

      switch (arg_type->code ())
	{
	case TYPE_CODE_INT:
	case TYPE_CODE_BOOL:
	case TYPE_CODE_CHAR:
	case TYPE_CODE_RANGE:
	case TYPE_CODE_ENUM:
	  if (len < 4)
	    {
	      if (aarch64_debug)
		debug_printf ("aarch64: %s Handling types with length < 4\n",
			      __func__);

	      /* Promote to 32 bit integer.  */
	      if (arg_type->is_unsigned ())
		arg_type = builtin_type (gdbarch)->builtin_uint32;
	      else
		arg_type = builtin_type (gdbarch)->builtin_int32;
	      arg = value_cast (arg_type, arg);
	    }
	  if (aarch64_debug && len >= 4)
	    debug_printf ("aarch64: %s Handling types with length >= 4\n",
			  __func__);
	  pass_in_x_or_stack (gdbarch, regcache, &info, arg_type, arg);
	  break;

	case TYPE_CODE_STRUCT:
	case TYPE_CODE_ARRAY:
	case TYPE_CODE_UNION:
	  /* Morello AAPCS: B.5:  */
	  if (arg_type->contains_capability ()
	      && (len > 32 || type_fields_overlap_capabilities (arg_type)))
	    {
	      if (aarch64_debug)
		debug_printf ("aarch64: %s Composite type with capabilities "
			      "and len > 32 or overlapping types\n", __func__);
	      /* If the argument is a Composite Type containing Capabilities
		 and the size is larger than 32 bytes or there are
		 addressable members which are not Capabilities that
		 overlap bytes 8-15 or 24-31 of the argument (if such bytes
		 exist) then the argument is copied to memory allocated by
		 the caller and the argument is replaced by a pointer to
		 the copy in AAPCS64 or a capability to a copy in
		 AAPCS64-cap.  */

	      /* Allocate aligned storage.  */
	      sp = align_down (sp - len, 16);

	      /* Write the real data into the stack.  Since this type contains
		 capabilities, we need to handle writing the capabilities and
		 adjusting the memory tags.  */
	      morello_write_memory_with_capabilities (sp, arg);

	      /* Construct the indirection.  Create a capability or a pointer
		 depending on the ELF ABI being used (AAPCS64-cap or
		 AAPCS64).  */
	      if (aapcs64_cap)
		{
		  /* Derive a capability from CSP and forge the indirection
		     capability.  */
		  struct value *csp
		    = regcache->cooked_read_value (tdep->cap_reg_csp);
		  arg = convert_pointer_to_capability (gdbarch, csp, sp);
		  arg_type = value_type (csp);
		}
	      else
		{
		  /* Use a regular pointer.  */
		  arg_type = lookup_pointer_type (arg_type);
		  arg = value_from_pointer (arg_type, sp);
		}
	      pass_in_c_x_or_stack (gdbarch, regcache, &info, arg_type, arg);
	    }
	  else if (len > 16 && !arg_type->contains_capability ())
	    {
	      if (aarch64_debug)
		debug_printf ("aarch64: %s Composite type without capabilities "
			      "and len > 16\n", __func__);
	      /* Morello AAPCS B.3: Aggregates larger than 16 bytes, not
		 containing capabilities, are passed by invisible reference.  */

	      /* Allocate aligned storage.  */
	      sp = align_down (sp - len, 16);

	      /* Write the real data into the stack.  */
	      write_memory (sp, value_contents (arg), len);

	      /* Construct the indirection.  Create a capability or a pointer
		 depending on the ELF ABI being used (AAPCS64-cap or
		 AAPCS64).  */
	      if (aapcs64_cap)
		{
		  /* Derive a capability from CSP and forge the indirection
		     capability.  */
		  struct value *csp
		    = regcache->cooked_read_value (tdep->cap_reg_csp);
		  arg = convert_pointer_to_capability (gdbarch, csp, sp);
		  arg_type = value_type (csp);
		}
	      else
		{
		  /* Use a regular pointer.  */
		  arg_type = lookup_pointer_type (arg_type);
		  arg = value_from_pointer (arg_type, sp);
		}
	      pass_in_c_x_or_stack (gdbarch, regcache, &info, arg_type, arg);
	    }
	  else
	    {
	      /* PCS C.15 / C.18 multiple values pass.  */
	      /* Morello AAPCS C.16 / C.8.  */
	      if (aarch64_debug)
		debug_printf ("aarch64: %s Composite type default case "
			      "len is %s\n", __func__, pulongest (len));
	      pass_in_c_x_or_stack (gdbarch, regcache, &info, arg_type, arg);
	    }
	  break;

	default:
	  if (aarch64_debug)
	    debug_printf ("aarch64: %s default case\n", __func__);
	  pass_in_c_x_or_stack (gdbarch, regcache, &info, arg_type, arg);
	  break;
	}
    }

  /* Make sure stack retains 16 byte alignment.  */
  if (info.nsaa & 15)
    sp -= 16 - (info.nsaa & 15);

  while (!info.si.empty ())
    {
      const stack_item_t &si = info.si.back ();

      sp -= si.len;
      if (si.data != NULL)
	morello_write_memory_with_capabilities (sp, si.arg_value);
      info.si.pop_back ();
    }

  regnum = AARCH64_SP_REGNUM;

  /* We should use CSP for AARCH64-CAP and SP for AAPCS64.  */
  if (aapcs64_cap)
    {
      regnum = tdep->cap_reg_csp;

      struct value *csp = regcache->cooked_read_value (regnum);
      regcache->cooked_write (regnum, value_contents (csp));
      aarch64_register_set_tag (gdbarch, regcache, regnum, value_tag (csp));
    }

    if (aarch64_debug)
      debug_printf ("aarch64: Adjusting stack pointer in %s to %s\n",
		    gdbarch_register_name (gdbarch, regnum),
		    paddress (gdbarch, sp));

  regcache_cooked_write_unsigned (regcache, AARCH64_SP_REGNUM, sp);

  if (aarch64_debug)
    debug_printf ("aarch64: Exiting %s\n", __func__);

  return sp;
}

/* Implement the "push_dummy_call" gdbarch method for generic AARCH64.  */

static CORE_ADDR
aarch64_push_dummy_call (struct gdbarch *gdbarch, struct value *function,
			 struct regcache *regcache, CORE_ADDR bp_addr,
			 int nargs,
			 struct value **args, CORE_ADDR sp,
			 function_call_return_method return_method,
			 CORE_ADDR struct_addr)
{
  int argnum;
  struct aarch64_call_info info;

  /* We need to know what the type of the called function is in order
     to determine the number of named/anonymous arguments for the
     actual argument placement, and the return type in order to handle
     return value correctly.

     The generic code above us views the decision of return in memory
     or return in registers as a two stage processes.  The language
     handler is consulted first and may decide to return in memory (eg
     class with copy constructor returned by value), this will cause
     the generic code to allocate space AND insert an initial leading
     argument.

     If the language code does not decide to pass in memory then the
     target code is consulted.

     If the language code decides to pass in memory we want to move
     the pointer inserted as the initial argument from the argument
     list and into X8, the conventional AArch64 struct return pointer
     register.  */

  /* Set the return address.  For the AArch64, the return breakpoint
     is always at BP_ADDR.  */
  regcache_cooked_write_unsigned (regcache, AARCH64_LR_REGNUM, bp_addr);

  /* If we were given an initial argument for the return slot, lose it.  */
  if (return_method == return_method_hidden_param)
    {
      args++;
      nargs--;
    }

  /* The struct_return pointer occupies X8.  */
  if (return_method != return_method_normal)
    {
      if (aarch64_debug)
	{
	  debug_printf ("struct return in %s = 0x%s\n",
			gdbarch_register_name (gdbarch,
					       AARCH64_STRUCT_RETURN_REGNUM),
			paddress (gdbarch, struct_addr));
	}
      regcache_cooked_write_unsigned (regcache, AARCH64_STRUCT_RETURN_REGNUM,
				      struct_addr);
    }

  for (argnum = 0; argnum < nargs; argnum++)
    {
      struct value *arg = args[argnum];
      struct type *arg_type, *fundamental_type;
      int len, elements;

      arg_type = check_typedef (value_type (arg));
      len = TYPE_LENGTH (arg_type);

      /* If arg can be passed in v registers as per the AAPCS64, then do so if
	 if there are enough spare registers.  */
      if (aapcs_is_vfp_call_or_return_candidate (arg_type, &elements,
						 &fundamental_type))
	{
	  if (info.nsrn + elements <= 8)
	    {
	      /* We know that we have sufficient registers available therefore
		 this will never need to fallback to the stack.  */
	      if (!pass_in_v_vfp_candidate (gdbarch, regcache, &info, arg_type,
					    arg))
		gdb_assert_not_reached ("Failed to push args");
	    }
	  else
	    {
	      info.nsrn = 8;
	      pass_on_stack (&info, arg_type, arg);
	    }
	  continue;
	}

      switch (arg_type->code ())
	{
	case TYPE_CODE_INT:
	case TYPE_CODE_BOOL:
	case TYPE_CODE_CHAR:
	case TYPE_CODE_RANGE:
	case TYPE_CODE_ENUM:
	  if (len < 4)
	    {
	      /* Promote to 32 bit integer.  */
	      if (arg_type->is_unsigned ())
		arg_type = builtin_type (gdbarch)->builtin_uint32;
	      else
		arg_type = builtin_type (gdbarch)->builtin_int32;
	      arg = value_cast (arg_type, arg);
	    }
	  pass_in_x_or_stack (gdbarch, regcache, &info, arg_type, arg);
	  break;

	case TYPE_CODE_STRUCT:
	case TYPE_CODE_ARRAY:
	case TYPE_CODE_UNION:
	  if (len > 16)
	    {
	      /* PCS B.7 Aggregates larger than 16 bytes are passed by
		 invisible reference.  */

	      /* Allocate aligned storage.  */
	      sp = align_down (sp - len, 16);

	      /* Write the real data into the stack.  */
	      write_memory (sp, value_contents (arg), len);

	      /* Construct the indirection.  */
	      arg_type = lookup_pointer_type (arg_type);
	      arg = value_from_pointer (arg_type, sp);
	      pass_in_x_or_stack (gdbarch, regcache, &info, arg_type, arg);
	    }
	  else
	    /* PCS C.15 / C.18 multiple values pass.  */
	    pass_in_x_or_stack (gdbarch, regcache, &info, arg_type, arg);
	  break;

	default:
	  pass_in_x_or_stack (gdbarch, regcache, &info, arg_type, arg);
	  break;
	}
    }

  /* Make sure stack retains 16 byte alignment.  */
  if (info.nsaa & 15)
    sp -= 16 - (info.nsaa & 15);

  while (!info.si.empty ())
    {
      const stack_item_t &si = info.si.back ();

      sp -= si.len;
      if (si.data != NULL)
	write_memory (sp, si.data, si.len);
      info.si.pop_back ();
    }

  /* Finally, update the SP register.  */
  regcache_cooked_write_unsigned (regcache, AARCH64_SP_REGNUM, sp);

  return sp;
}

/* Implement the "frame_align" gdbarch method.  */

static CORE_ADDR
aarch64_frame_align (struct gdbarch *gdbarch, CORE_ADDR sp)
{
  /* Align the stack to sixteen bytes.  */
  return sp & ~(CORE_ADDR) 15;
}

/* Return the type for an AdvSISD Q register.  */

static struct type *
aarch64_vnq_type (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->vnq_type == NULL)
    {
      struct type *t;
      struct type *elem;

      t = arch_composite_type (gdbarch, "__gdb_builtin_type_vnq",
			       TYPE_CODE_UNION);

      elem = builtin_type (gdbarch)->builtin_uint128;
      append_composite_type_field (t, "u", elem);

      elem = builtin_type (gdbarch)->builtin_int128;
      append_composite_type_field (t, "s", elem);

      tdep->vnq_type = t;
    }

  return tdep->vnq_type;
}

/* Return the type for an AdvSISD D register.  */

static struct type *
aarch64_vnd_type (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->vnd_type == NULL)
    {
      struct type *t;
      struct type *elem;

      t = arch_composite_type (gdbarch, "__gdb_builtin_type_vnd",
			       TYPE_CODE_UNION);

      elem = builtin_type (gdbarch)->builtin_double;
      append_composite_type_field (t, "f", elem);

      elem = builtin_type (gdbarch)->builtin_uint64;
      append_composite_type_field (t, "u", elem);

      elem = builtin_type (gdbarch)->builtin_int64;
      append_composite_type_field (t, "s", elem);

      tdep->vnd_type = t;
    }

  return tdep->vnd_type;
}

/* Return the type for an AdvSISD S register.  */

static struct type *
aarch64_vns_type (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->vns_type == NULL)
    {
      struct type *t;
      struct type *elem;

      t = arch_composite_type (gdbarch, "__gdb_builtin_type_vns",
			       TYPE_CODE_UNION);

      elem = builtin_type (gdbarch)->builtin_float;
      append_composite_type_field (t, "f", elem);

      elem = builtin_type (gdbarch)->builtin_uint32;
      append_composite_type_field (t, "u", elem);

      elem = builtin_type (gdbarch)->builtin_int32;
      append_composite_type_field (t, "s", elem);

      tdep->vns_type = t;
    }

  return tdep->vns_type;
}

/* Return the type for an AdvSISD H register.  */

static struct type *
aarch64_vnh_type (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->vnh_type == NULL)
    {
      struct type *t;
      struct type *elem;

      t = arch_composite_type (gdbarch, "__gdb_builtin_type_vnh",
			       TYPE_CODE_UNION);

      elem = builtin_type (gdbarch)->builtin_half;
      append_composite_type_field (t, "f", elem);

      elem = builtin_type (gdbarch)->builtin_uint16;
      append_composite_type_field (t, "u", elem);

      elem = builtin_type (gdbarch)->builtin_int16;
      append_composite_type_field (t, "s", elem);

      tdep->vnh_type = t;
    }

  return tdep->vnh_type;
}

/* Return the type for an AdvSISD B register.  */

static struct type *
aarch64_vnb_type (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->vnb_type == NULL)
    {
      struct type *t;
      struct type *elem;

      t = arch_composite_type (gdbarch, "__gdb_builtin_type_vnb",
			       TYPE_CODE_UNION);

      elem = builtin_type (gdbarch)->builtin_uint8;
      append_composite_type_field (t, "u", elem);

      elem = builtin_type (gdbarch)->builtin_int8;
      append_composite_type_field (t, "s", elem);

      tdep->vnb_type = t;
    }

  return tdep->vnb_type;
}

/* Return the type for an AdvSISD V register.  */

static struct type *
aarch64_vnv_type (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->vnv_type == NULL)
    {
      /* The other AArch64 pseudo registers (Q,D,H,S,B) refer to a single value
	 slice from the non-pseudo vector registers.  However NEON V registers
	 are always vector registers, and need constructing as such.  */
      const struct builtin_type *bt = builtin_type (gdbarch);

      struct type *t = arch_composite_type (gdbarch, "__gdb_builtin_type_vnv",
					    TYPE_CODE_UNION);

      struct type *sub = arch_composite_type (gdbarch, "__gdb_builtin_type_vnd",
				 TYPE_CODE_UNION);
      append_composite_type_field (sub, "f",
				   init_vector_type (bt->builtin_double, 2));
      append_composite_type_field (sub, "u",
				   init_vector_type (bt->builtin_uint64, 2));
      append_composite_type_field (sub, "s",
				   init_vector_type (bt->builtin_int64, 2));
      append_composite_type_field (t, "d", sub);

      sub = arch_composite_type (gdbarch, "__gdb_builtin_type_vns",
				 TYPE_CODE_UNION);
      append_composite_type_field (sub, "f",
				   init_vector_type (bt->builtin_float, 4));
      append_composite_type_field (sub, "u",
				   init_vector_type (bt->builtin_uint32, 4));
      append_composite_type_field (sub, "s",
				   init_vector_type (bt->builtin_int32, 4));
      append_composite_type_field (t, "s", sub);

      sub = arch_composite_type (gdbarch, "__gdb_builtin_type_vnh",
				 TYPE_CODE_UNION);
      append_composite_type_field (sub, "f",
				   init_vector_type (bt->builtin_half, 8));
      append_composite_type_field (sub, "u",
				   init_vector_type (bt->builtin_uint16, 8));
      append_composite_type_field (sub, "s",
				   init_vector_type (bt->builtin_int16, 8));
      append_composite_type_field (t, "h", sub);

      sub = arch_composite_type (gdbarch, "__gdb_builtin_type_vnb",
				 TYPE_CODE_UNION);
      append_composite_type_field (sub, "u",
				   init_vector_type (bt->builtin_uint8, 16));
      append_composite_type_field (sub, "s",
				   init_vector_type (bt->builtin_int8, 16));
      append_composite_type_field (t, "b", sub);

      sub = arch_composite_type (gdbarch, "__gdb_builtin_type_vnq",
				 TYPE_CODE_UNION);
      append_composite_type_field (sub, "u",
				   init_vector_type (bt->builtin_uint128, 1));
      append_composite_type_field (sub, "s",
				   init_vector_type (bt->builtin_int128, 1));
      append_composite_type_field (t, "q", sub);

      tdep->vnv_type = t;
    }

  return tdep->vnv_type;
}

/* Return the type for a capability pseudo register.  */

static struct type *
morello_capability_pseudo_type (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->morello_capability_pseudo_type == NULL)
    {
      struct type *t;
      struct type *elem;

      t = arch_composite_type (gdbarch, "__gdb_builtin_type_capability",
			       TYPE_CODE_STRUCT);

      /* Lower 64 bits of the capability.  */
      elem = builtin_type (gdbarch)->builtin_uint64;
      append_composite_type_field (t, "l", elem);

      /* Upper 64 bits of the capability.  */
      elem = builtin_type (gdbarch)->builtin_uint64;
      append_composite_type_field (t, "u", elem);

      /* Tag bit of the capability.  */
      elem = builtin_type (gdbarch)->builtin_bool;
      append_composite_type_field (t, "t", elem);

      tdep->morello_capability_pseudo_type = t;
    }

  return tdep->morello_capability_pseudo_type;
}

/* Implement the "dwarf2_reg_to_regnum" gdbarch method.  */

static int
aarch64_dwarf_reg_to_regnum (struct gdbarch *gdbarch, int reg)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (reg >= AARCH64_DWARF_X0 && reg <= AARCH64_DWARF_X0 + 30)
    return AARCH64_X0_REGNUM + reg - AARCH64_DWARF_X0;

  if (reg == AARCH64_DWARF_SP)
    return AARCH64_SP_REGNUM;

  if (reg >= AARCH64_DWARF_V0 && reg <= AARCH64_DWARF_V0 + 31)
    return AARCH64_V0_REGNUM + reg - AARCH64_DWARF_V0;

  if (reg == AARCH64_DWARF_SVE_VG)
    return AARCH64_SVE_VG_REGNUM;

  if (reg == AARCH64_DWARF_SVE_FFR)
    return AARCH64_SVE_FFR_REGNUM;

  if (reg >= AARCH64_DWARF_SVE_P0 && reg <= AARCH64_DWARF_SVE_P0 + 15)
    return AARCH64_SVE_P0_REGNUM + reg - AARCH64_DWARF_SVE_P0;

  if (reg >= AARCH64_DWARF_SVE_Z0 && reg <= AARCH64_DWARF_SVE_Z0 + 15)
    return AARCH64_SVE_Z0_REGNUM + reg - AARCH64_DWARF_SVE_Z0;

  if (tdep->has_pauth ())
    {
      if (reg >= AARCH64_DWARF_PAUTH_DMASK && reg <= AARCH64_DWARF_PAUTH_CMASK)
	return tdep->pauth_reg_base + reg - AARCH64_DWARF_PAUTH_DMASK;

      if (reg == AARCH64_DWARF_PAUTH_RA_STATE)
	return tdep->pauth_ra_state_regnum;
    }

  if (tdep->has_capability ())
    {
      if (reg >= AARCH64_DWARF_C0 && reg <= AARCH64_DWARF_C0 + 30)
	return tdep->cap_reg_base + (reg - AARCH64_DWARF_C0);

      if (reg == AARCH64_DWARF_CSP)
	return tdep->cap_reg_csp;
    }

  return -1;
}

/* Search for the mapping symbol covering MEMADDR.  If one is found,
   return its type.  Otherwise, return 0.  If START is non-NULL,
   set *START to the location of the mapping symbol.  */

static char
aarch64_find_mapping_symbol (CORE_ADDR memaddr, CORE_ADDR *start)
{
  struct obj_section *sec;

  /* If there are mapping symbols, consult them.  */
  sec = find_pc_section (memaddr);
  if (sec != NULL)
    {
      aarch64_per_bfd *data = aarch64_bfd_data_key.get (sec->objfile->obfd);
      if (data != NULL)
	{
	  unsigned int section_idx = sec->the_bfd_section->index;
	  aarch64_mapping_symbol_vec &map
	    = data->section_maps[section_idx];

	  /* Sort the vector on first use.  */
	  if (!data->section_maps_sorted[section_idx])
	    {
	      std::sort (map.begin (), map.end ());
	      data->section_maps_sorted[section_idx] = true;
	    }

	  struct aarch64_mapping_symbol map_key
	    = { memaddr - obj_section_addr (sec), 0 };
	  aarch64_mapping_symbol_vec::const_iterator it
	    = std::lower_bound (map.begin (), map.end (), map_key);

	  /* std::lower_bound finds the earliest ordered insertion
	     point.  If the symbol at this position starts at this exact
	     address, we use that; otherwise, the preceding
	     mapping symbol covers this address.  */
	  if (it < map.end ())
	    {
	      if (it->value == map_key.value)
		{
		  if (start)
		    *start = it->value + obj_section_addr (sec);
		  return it->type;
		}
	    }

	  if (it > map.begin ())
	    {
	      aarch64_mapping_symbol_vec::const_iterator prev_it
		= it - 1;

	      if (start)
		*start = prev_it->value + obj_section_addr (sec);
	      return prev_it->type;
	    }
	}
    }

  return 0;
}

/* Determine if the program counter specified in MEMADDR is in a C64
   function.  This function should be called for addresses unrelated to
   any executing frame.  */

static bool
aarch64_pc_is_c64 (struct gdbarch *gdbarch, CORE_ADDR memaddr)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  /* If we're using the AAPCS64-CAP ABI, then this is pure-cap and it is
     always C64.  */
  if (tdep->abi == AARCH64_ABI_AAPCS64_CAP)
    return true;

  /* If there are mapping symbols, consult them.  */
  char type = aarch64_find_mapping_symbol (memaddr, NULL);
  if (type)
    return type == 'c';

  /* C64 functions have a "special" bit set in minimal symbols.  */
  struct bound_minimal_symbol sym;
  sym = lookup_minimal_symbol_by_pc (memaddr);
  if (sym.minsym)
    return (MSYMBOL_IS_SPECIAL (sym.minsym));

  /* Otherwise we're out of luck; we assume A64.  */
  return false;
}

/* Implement the "print_insn" gdbarch method.  */

static int
aarch64_gdb_print_insn (bfd_vma memaddr, disassemble_info *info)
{
  gdb_disassembler *di
    = static_cast<gdb_disassembler *>(info->application_data);
  struct gdbarch *gdbarch = di->arch ();
  struct aarch64_private_data data;

  info->private_data = static_cast<void *> (&data);

  if (aarch64_pc_is_c64 (gdbarch, memaddr))
    data.instruction_type = MAP_TYPE_C64;

  info->symbols = NULL;

  return default_print_insn (memaddr, info);
}

/* AArch64 BRK software debug mode instruction.
   Note that AArch64 code is always little-endian.
   1101.0100.0010.0000.0000.0000.0000.0000 = 0xd4200000.  */
constexpr gdb_byte aarch64_default_breakpoint[] = {0x00, 0x00, 0x20, 0xd4};

typedef BP_MANIPULATION (aarch64_default_breakpoint) aarch64_breakpoint;

/* Extract from an array REGS containing the (raw) register state a
   function return value of type TYPE, and copy that, in virtual
   format, into VALBUF.  Morello version.  */

static void
morello_extract_return_value (struct value *value, struct regcache *regs,
			      gdb_byte *valbuf)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  struct type *type = value_type (value);
  struct gdbarch *gdbarch = regs->arch ();
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int elements;
  struct type *fundamental_type;
  /* Morello AAPCS64-cap ABI.  */
  bool aapcs64_cap = (tdep->abi == AARCH64_ABI_AAPCS64_CAP);

  if (aarch64_debug)
    debug_printf ("aarch64: %s: ABI is %s\n", __func__,
		  aapcs64_cap ? "AAPCS64-CAP" : "AAPCS64");

  if (aapcs_is_vfp_call_or_return_candidate (type, &elements,
					     &fundamental_type))
    {
      int len = TYPE_LENGTH (fundamental_type);

      for (int i = 0; i < elements; i++)
	{
	  int regno = AARCH64_V0_REGNUM + i;
	  /* Enough space for a full vector register.  */
	  gdb_byte buf[register_size (gdbarch, regno)];
	  gdb_assert (len <= sizeof (buf));

	  if (aarch64_debug)
	    {
	      debug_printf ("read HFA or HVA return value element %d from %s\n",
			    i + 1,
			    gdbarch_register_name (gdbarch, regno));
	    }
	  regs->cooked_read (regno, buf);

	  memcpy (valbuf, buf, len);
	  valbuf += len;
	}
    }
  else if (type->code () == TYPE_CODE_PTR
	   || type->code () == TYPE_CODE_CAPABILITY
	   || TYPE_IS_REFERENCE (type))
    {
      if (aarch64_debug)
	debug_printf ("aarch64: %s: Pointer/Capability types\n", __func__);

      int regno;

      if (aapcs64_cap)
	{
	  regno = tdep->cap_reg_base + AARCH64_X0_REGNUM;
	  set_value_tagged (value, true);
	  set_value_tag (value, true);
	}
      else
	regno = AARCH64_X0_REGNUM;

      regs->cooked_read (regno, valbuf);
    }
  else if (type->code () == TYPE_CODE_INT
	   || type->code () == TYPE_CODE_CHAR
	   || type->code () == TYPE_CODE_BOOL
	   || type->code () == TYPE_CODE_ENUM)
    {
      if (aarch64_debug)
	debug_printf ("aarch64: %s: Integral types, size %s\n", __func__,
		      pulongest (TYPE_LENGTH (type)));

      /* If the type is a plain integer, then the access is
	 straight-forward.  Otherwise we have to play around a bit
	 more.  */
      int len = TYPE_LENGTH (type);
      int regno = AARCH64_X0_REGNUM;
      ULONGEST tmp;

      while (len > 0)
	{
	  /* By using store_unsigned_integer we avoid having to do
	     anything special for small big-endian values.  */
	  regcache_cooked_read_unsigned (regs, regno++, &tmp);
	  store_unsigned_integer (valbuf,
				  (len > X_REGISTER_SIZE
				   ? X_REGISTER_SIZE : len), byte_order, tmp);
	  len -= X_REGISTER_SIZE;
	  valbuf += X_REGISTER_SIZE;
	}
    }
  else
    {
      if (aarch64_debug)
	debug_printf ("aarch64: %s: Composite types, size %s\n", __func__,
		      pulongest (TYPE_LENGTH (type)));
      /* For a structure or union the behaviour is as if the value had
         been stored to word-aligned memory and then loaded into
         registers with 64-bit load instruction(s).  */
      int len = TYPE_LENGTH (type);
      int regno = tdep->cap_reg_base + AARCH64_X0_REGNUM;
      bfd_byte buf[C_REGISTER_SIZE];

      while (len > 0)
	{
	  memset (valbuf, 0, C_REGISTER_SIZE);
	  regs->cooked_read (regno++, buf);
	  memcpy (valbuf, buf, len > C_REGISTER_SIZE ? C_REGISTER_SIZE : len);
	  len -= C_REGISTER_SIZE;
	  valbuf += C_REGISTER_SIZE;
	}
    }
  if (aarch64_debug)
    debug_printf ("aarch64: leaving %s\n", __func__);
}


/* Will a function return an aggregate type in memory or in a
   register?  Return 0 if an aggregate type can be returned in a
   register, 1 if it must be returned in memory.  Morello implementation.  */

static bool
morello_return_in_memory (struct gdbarch *gdbarch, struct type *type)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  type = check_typedef (type);
  int elements;
  struct type *fundamental_type;

  if (aapcs_is_vfp_call_or_return_candidate (type, &elements,
					     &fundamental_type))
    {
      /* v0-v7 are used to return values and one register is allocated
	 for one member.  However, HFA or HVA has at most four members.  */

      if (aarch64_debug)
	debug_printf ("aarch64: %s: Morello AAPCS VFP\n", __func__);

      return false;
    }

  size_t length = TYPE_LENGTH (type);

  /* Morello AAPCS B.5 */
  if (type->contains_capability ()
      && (length > 32 || type_fields_overlap_capabilities (type)))
    {
      if (aarch64_debug)
	debug_printf ("aarch64: %s: Morello AAPCS B.5\n", __func__);

      return true;
    }

  /* Morello AAPCS B.3 */
  if (length > 16 && !type->contains_capability ())
    {
      if (aarch64_debug)
	debug_printf ("aarch64: %s: Morello AAPCS B.3\n", __func__);

      return true;
    }

  return false;
}

/* Extract from an array REGS containing the (raw) register state a
   function return value of type TYPE, and copy that, in virtual
   format, into VALBUF.  */

static void
aarch64_extract_return_value (struct type *type, struct regcache *regs,
			      gdb_byte *valbuf)
{
  struct gdbarch *gdbarch = regs->arch ();
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int elements;
  struct type *fundamental_type;

  if (aapcs_is_vfp_call_or_return_candidate (type, &elements,
					     &fundamental_type))
    {
      int len = TYPE_LENGTH (fundamental_type);

      for (int i = 0; i < elements; i++)
	{
	  int regno = AARCH64_V0_REGNUM + i;
	  /* Enough space for a full vector register.  */
	  gdb_byte buf[register_size (gdbarch, regno)];
	  gdb_assert (len <= sizeof (buf));

	  if (aarch64_debug)
	    {
	      debug_printf ("read HFA or HVA return value element %d from %s\n",
			    i + 1,
			    gdbarch_register_name (gdbarch, regno));
	    }
	  regs->cooked_read (regno, buf);

	  memcpy (valbuf, buf, len);
	  valbuf += len;
	}
    }
  else if (type->code () == TYPE_CODE_INT
	   || type->code () == TYPE_CODE_CHAR
	   || type->code () == TYPE_CODE_BOOL
	   || type->code () == TYPE_CODE_PTR
	   || TYPE_IS_REFERENCE (type)
	   || type->code () == TYPE_CODE_ENUM)
    {
      /* If the type is a plain integer, then the access is
	 straight-forward.  Otherwise we have to play around a bit
	 more.  */
      int len = TYPE_LENGTH (type);
      int regno = AARCH64_X0_REGNUM;
      ULONGEST tmp;

      while (len > 0)
	{
	  /* By using store_unsigned_integer we avoid having to do
	     anything special for small big-endian values.  */
	  regcache_cooked_read_unsigned (regs, regno++, &tmp);
	  store_unsigned_integer (valbuf,
				  (len > X_REGISTER_SIZE
				   ? X_REGISTER_SIZE : len), byte_order, tmp);
	  len -= X_REGISTER_SIZE;
	  valbuf += X_REGISTER_SIZE;
	}
    }
  else
    {
      /* For a structure or union the behaviour is as if the value had
         been stored to word-aligned memory and then loaded into
         registers with 64-bit load instruction(s).  */
      int len = TYPE_LENGTH (type);
      int regno = AARCH64_X0_REGNUM;
      bfd_byte buf[X_REGISTER_SIZE];

      while (len > 0)
	{
	  regs->cooked_read (regno++, buf);
	  memcpy (valbuf, buf, len > X_REGISTER_SIZE ? X_REGISTER_SIZE : len);
	  len -= X_REGISTER_SIZE;
	  valbuf += X_REGISTER_SIZE;
	}
    }
}

/* Will a function return an aggregate type in memory or in a
   register?  Return 0 if an aggregate type can be returned in a
   register, 1 if it must be returned in memory.  */

static int
aarch64_return_in_memory (struct gdbarch *gdbarch, struct type *type)
{
  type = check_typedef (type);
  int elements;
  struct type *fundamental_type;

  if (aapcs_is_vfp_call_or_return_candidate (type, &elements,
					     &fundamental_type))
    {
      /* v0-v7 are used to return values and one register is allocated
	 for one member.  However, HFA or HVA has at most four members.  */
      return 0;
    }

  if (TYPE_LENGTH (type) > 16)
    {
      /* PCS B.6 Aggregates larger than 16 bytes are passed by
         invisible reference.  */

      return 1;
    }

  return 0;
}

/* Write into appropriate registers a function return value of type
   TYPE, given in virtual format.  Morello version.  */

static void
morello_store_return_value (struct value *value, struct regcache *regs,
			    const gdb_byte *valbuf)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  struct type *type = value_type (value);
  struct gdbarch *gdbarch = regs->arch ();
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int elements;
  struct type *fundamental_type;
  /* Morello AAPCS64-cap ABI.  */
  bool aapcs64_cap = (tdep->abi == AARCH64_ABI_AAPCS64_CAP);

  if (aarch64_debug)
    debug_printf ("aarch64: %s: ABI is %s\n", __func__,
		  aapcs64_cap ? "AAPCS64-CAP" : "AAPCS64");

  if (aapcs_is_vfp_call_or_return_candidate (type, &elements,
					     &fundamental_type))
    {
      int len = TYPE_LENGTH (fundamental_type);

      for (int i = 0; i < elements; i++)
	{
	  int regno = AARCH64_V0_REGNUM + i;
	  /* Enough space for a full vector register.  */
	  gdb_byte tmpbuf[register_size (gdbarch, regno)];
	  gdb_assert (len <= sizeof (tmpbuf));

	  if (aarch64_debug)
	    {
	      debug_printf ("write HFA or HVA return value element %d to %s\n",
			    i + 1,
			    gdbarch_register_name (gdbarch, regno));
	    }

	  memcpy (tmpbuf, valbuf,
		  len > V_REGISTER_SIZE ? V_REGISTER_SIZE : len);
	  regs->cooked_write (regno, tmpbuf);
	  valbuf += len;
	}
    }
  else if (type->code () == TYPE_CODE_PTR
	   || type->code () == TYPE_CODE_CAPABILITY
	   || TYPE_IS_REFERENCE (type))
    {
      int regno;

      if (aarch64_debug)
	debug_printf ("aarch64: %s: Pointer/Capability types\n", __func__);

      if (aapcs64_cap || type->code () == TYPE_CODE_CAPABILITY)
	regno = tdep->cap_reg_base + AARCH64_X0_REGNUM;
      else
	regno = AARCH64_X0_REGNUM;

      regs->cooked_write (regno, valbuf);

      /* Also store the tag if we are dealing with a capability.  */
      if (aapcs64_cap || type->code () == TYPE_CODE_CAPABILITY)
	aarch64_register_set_tag (gdbarch, regs, regno, value_tag (value));
    }
  else if (type->code () == TYPE_CODE_INT
	   || type->code () == TYPE_CODE_CHAR
	   || type->code () == TYPE_CODE_BOOL
	   || type->code () == TYPE_CODE_ENUM)
    {
      if (aarch64_debug)
	debug_printf ("aarch64: %s: Integral types, size %s\n", __func__,
		      pulongest (TYPE_LENGTH (type)));

      if (TYPE_LENGTH (type) <= X_REGISTER_SIZE)
	{
	  /* Values of one word or less are zero/sign-extended and
	     returned in r0.  */
	  int regno = AARCH64_X0_REGNUM;
	  bfd_byte tmpbuf[X_REGISTER_SIZE];
	  LONGEST val = unpack_long (type, valbuf);

	  memset (tmpbuf, 0, X_REGISTER_SIZE);
	  store_signed_integer (tmpbuf, X_REGISTER_SIZE, byte_order, val);
	  regs->cooked_write (regno, tmpbuf);
	}
      else
	{
	  /* Integral values greater than one word are stored in
	     consecutive registers starting with r0.  This will always
	     be a multiple of the register size.  */
	  int len = TYPE_LENGTH (type);
	  int regno = tdep->cap_reg_base + AARCH64_X0_REGNUM;

	  while (len > 0)
	    {
	      regs->cooked_write (regno++, valbuf);
	      len -= X_REGISTER_SIZE;
	      valbuf += X_REGISTER_SIZE;
	    }
	}
    }
  else
    {
      if (aarch64_debug)
	debug_printf ("aarch64: %s: Composite types, size %s\n", __func__,
		      pulongest (TYPE_LENGTH (type)));
      /* For a structure or union the behaviour is as if the value had
	 been stored to word-aligned memory and then loaded into
	 registers with 64-bit load instruction(s).  */

      int regno;
      size_t buffer_size;

      if (aapcs64_cap || type->contains_capability ())
	{
	  regno = tdep->cap_reg_base + AARCH64_X0_REGNUM;
	  buffer_size = C_REGISTER_SIZE;
	}
      else
	{
	  regno = AARCH64_X0_REGNUM;
	  buffer_size = X_REGISTER_SIZE;
	}

      int len = TYPE_LENGTH (type);
      bfd_byte tmpbuf[buffer_size];
      CORE_ADDR address = value_address (value);

      while (len > 0)
	{
	  memset (tmpbuf, 0, buffer_size);
	  memcpy (tmpbuf, valbuf,
		  len > buffer_size ? buffer_size : len);
	  regs->cooked_write (regno++, tmpbuf);

	  if (aapcs64_cap || type->contains_capability ())
	    {
	      /* We need to read the tags from memory.  */
	      gdb::byte_vector cap = target_read_capability (address);
	      bool tag = cap[0] == 0 ? false : true;
	      aarch64_register_set_tag (gdbarch, regs, regno, tag);

	      if (aarch64_debug)
		debug_printf ("aarch64: %s Read tag %s from address %s\n",
			      __func__, tag == true ? "true" : "false",
			      paddress (gdbarch, address));
	      address += buffer_size;
	    }

	  len -= buffer_size;
	  valbuf += buffer_size;
	}
    }
  if (aarch64_debug)
    debug_printf ("aarch64: leaving %s\n", __func__);
}

/* Write into appropriate registers a function return value of type
   TYPE, given in virtual format.  */

static void
aarch64_store_return_value (struct type *type, struct regcache *regs,
			    const gdb_byte *valbuf)
{
  struct gdbarch *gdbarch = regs->arch ();
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int elements;
  struct type *fundamental_type;

  if (aapcs_is_vfp_call_or_return_candidate (type, &elements,
					     &fundamental_type))
    {
      int len = TYPE_LENGTH (fundamental_type);

      for (int i = 0; i < elements; i++)
	{
	  int regno = AARCH64_V0_REGNUM + i;
	  /* Enough space for a full vector register.  */
	  gdb_byte tmpbuf[register_size (gdbarch, regno)];
	  gdb_assert (len <= sizeof (tmpbuf));

	  if (aarch64_debug)
	    {
	      debug_printf ("write HFA or HVA return value element %d to %s\n",
			    i + 1,
			    gdbarch_register_name (gdbarch, regno));
	    }

	  memcpy (tmpbuf, valbuf,
		  len > V_REGISTER_SIZE ? V_REGISTER_SIZE : len);
	  regs->cooked_write (regno, tmpbuf);
	  valbuf += len;
	}
    }
  else if (type->code () == TYPE_CODE_INT
	   || type->code () == TYPE_CODE_CHAR
	   || type->code () == TYPE_CODE_BOOL
	   || type->code () == TYPE_CODE_PTR
	   || TYPE_IS_REFERENCE (type)
	   || type->code () == TYPE_CODE_ENUM)
    {
      if (TYPE_LENGTH (type) <= X_REGISTER_SIZE)
	{
	  /* Values of one word or less are zero/sign-extended and
	     returned in r0.  */
	  bfd_byte tmpbuf[X_REGISTER_SIZE];
	  LONGEST val = unpack_long (type, valbuf);

	  store_signed_integer (tmpbuf, X_REGISTER_SIZE, byte_order, val);
	  regs->cooked_write (AARCH64_X0_REGNUM, tmpbuf);
	}
      else
	{
	  /* Integral values greater than one word are stored in
	     consecutive registers starting with r0.  This will always
	     be a multiple of the regiser size.  */
	  int len = TYPE_LENGTH (type);
	  int regno = AARCH64_X0_REGNUM;

	  while (len > 0)
	    {
	      regs->cooked_write (regno++, valbuf);
	      len -= X_REGISTER_SIZE;
	      valbuf += X_REGISTER_SIZE;
	    }
	}
    }
  else
    {
      /* For a structure or union the behaviour is as if the value had
	 been stored to word-aligned memory and then loaded into
	 registers with 64-bit load instruction(s).  */
      int len = TYPE_LENGTH (type);
      int regno = AARCH64_X0_REGNUM;
      bfd_byte tmpbuf[X_REGISTER_SIZE];

      while (len > 0)
	{
	  memcpy (tmpbuf, valbuf,
		  len > X_REGISTER_SIZE ? X_REGISTER_SIZE : len);
	  regs->cooked_write (regno++, tmpbuf);
	  len -= X_REGISTER_SIZE;
	  valbuf += X_REGISTER_SIZE;
	}
    }
}

/* Implement the "return_value" gdbarch method for Morello.  */

static enum return_value_convention
morello_return_value (struct gdbarch *gdbarch, struct value *func_value,
		      struct type *valtype, struct regcache *regcache,
		      struct value *value,
		      gdb_byte *readbuf, const gdb_byte *writebuf)
{
  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  if (valtype->code () == TYPE_CODE_STRUCT
      || valtype->code () == TYPE_CODE_UNION
      || valtype->code () == TYPE_CODE_ARRAY)
    {
      if (morello_return_in_memory (gdbarch, valtype))
	{
	  if (aarch64_debug)
	    debug_printf ("return value in memory\n");

	  if (aarch64_debug)
	    debug_printf ("aarch64: exiting %s\n", __func__);

	  return RETURN_VALUE_STRUCT_CONVENTION;
	}
    }

  if (writebuf)
    morello_store_return_value (value, regcache, writebuf);

  if (readbuf)
    morello_extract_return_value (value, regcache, readbuf);

  if (aarch64_debug)
    debug_printf ("return value in registers\n");

  if (aarch64_debug)
    debug_printf ("aarch64: exiting %s\n", __func__);

  return RETURN_VALUE_REGISTER_CONVENTION;
}

/* Implement the "return_value" gdbarch method for generic AARCH64.  */

static enum return_value_convention
aarch64_return_value (struct gdbarch *gdbarch, struct value *func_value,
		      struct type *valtype, struct regcache *regcache,
		      struct value *value,
		      gdb_byte *readbuf, const gdb_byte *writebuf)
{

  if (valtype->code () == TYPE_CODE_STRUCT
      || valtype->code () == TYPE_CODE_UNION
      || valtype->code () == TYPE_CODE_ARRAY)
    {
      if (aarch64_return_in_memory (gdbarch, valtype))
	{
	  if (aarch64_debug)
	    debug_printf ("return value in memory\n");
	  return RETURN_VALUE_STRUCT_CONVENTION;
	}
    }

  if (writebuf)
    aarch64_store_return_value (valtype, regcache, writebuf);

  if (readbuf)
    aarch64_extract_return_value (valtype, regcache, readbuf);

  if (aarch64_debug)
    debug_printf ("return value in registers\n");

  return RETURN_VALUE_REGISTER_CONVENTION;
}

/* Implement the "get_longjmp_target" gdbarch method.  */

static int
aarch64_get_longjmp_target (struct frame_info *frame, CORE_ADDR *pc)
{
  CORE_ADDR jb_addr;
  gdb_byte buf[X_REGISTER_SIZE];
  struct gdbarch *gdbarch = get_frame_arch (frame);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  jb_addr = get_frame_register_unsigned (frame, AARCH64_X0_REGNUM);

  if (target_read_memory (jb_addr + tdep->jb_pc * tdep->jb_elt_size, buf,
			  X_REGISTER_SIZE))
    return 0;

  *pc = extract_unsigned_integer (buf, X_REGISTER_SIZE, byte_order);
  return 1;
}

/* Implement the "gen_return_address" gdbarch method.  */

static void
aarch64_gen_return_address (struct gdbarch *gdbarch,
			    struct agent_expr *ax, struct axs_value *value,
			    CORE_ADDR scope)
{
  value->type = register_type (gdbarch, AARCH64_LR_REGNUM);
  value->kind = axs_lvalue_register;
  value->u.reg = AARCH64_LR_REGNUM;
}


static bool is_capability_pseudo (gdbarch *gdbarch, int regnum)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->has_capability () && regnum >= tdep->cap_pseudo_base
      && regnum < tdep->cap_pseudo_base + tdep->cap_pseudo_count)
    return true;

  return false;
}

/* Return the pseudo register name corresponding to register regnum.  */

static const char *
aarch64_pseudo_register_name (struct gdbarch *gdbarch, int regnum)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  static const char *const q_name[] =
    {
      "q0", "q1", "q2", "q3",
      "q4", "q5", "q6", "q7",
      "q8", "q9", "q10", "q11",
      "q12", "q13", "q14", "q15",
      "q16", "q17", "q18", "q19",
      "q20", "q21", "q22", "q23",
      "q24", "q25", "q26", "q27",
      "q28", "q29", "q30", "q31",
    };

  static const char *const d_name[] =
    {
      "d0", "d1", "d2", "d3",
      "d4", "d5", "d6", "d7",
      "d8", "d9", "d10", "d11",
      "d12", "d13", "d14", "d15",
      "d16", "d17", "d18", "d19",
      "d20", "d21", "d22", "d23",
      "d24", "d25", "d26", "d27",
      "d28", "d29", "d30", "d31",
    };

  static const char *const s_name[] =
    {
      "s0", "s1", "s2", "s3",
      "s4", "s5", "s6", "s7",
      "s8", "s9", "s10", "s11",
      "s12", "s13", "s14", "s15",
      "s16", "s17", "s18", "s19",
      "s20", "s21", "s22", "s23",
      "s24", "s25", "s26", "s27",
      "s28", "s29", "s30", "s31",
    };

  static const char *const h_name[] =
    {
      "h0", "h1", "h2", "h3",
      "h4", "h5", "h6", "h7",
      "h8", "h9", "h10", "h11",
      "h12", "h13", "h14", "h15",
      "h16", "h17", "h18", "h19",
      "h20", "h21", "h22", "h23",
      "h24", "h25", "h26", "h27",
      "h28", "h29", "h30", "h31",
    };

  static const char *const b_name[] =
    {
      "b0", "b1", "b2", "b3",
      "b4", "b5", "b6", "b7",
      "b8", "b9", "b10", "b11",
      "b12", "b13", "b14", "b15",
      "b16", "b17", "b18", "b19",
      "b20", "b21", "b22", "b23",
      "b24", "b25", "b26", "b27",
      "b28", "b29", "b30", "b31",
    };

  int p_regnum = regnum - gdbarch_num_regs (gdbarch);

  if (p_regnum >= AARCH64_Q0_REGNUM && p_regnum < AARCH64_Q0_REGNUM + 32)
    return q_name[p_regnum - AARCH64_Q0_REGNUM];

  if (p_regnum >= AARCH64_D0_REGNUM && p_regnum < AARCH64_D0_REGNUM + 32)
    return d_name[p_regnum - AARCH64_D0_REGNUM];

  if (p_regnum >= AARCH64_S0_REGNUM && p_regnum < AARCH64_S0_REGNUM + 32)
    return s_name[p_regnum - AARCH64_S0_REGNUM];

  if (p_regnum >= AARCH64_H0_REGNUM && p_regnum < AARCH64_H0_REGNUM + 32)
    return h_name[p_regnum - AARCH64_H0_REGNUM];

  if (p_regnum >= AARCH64_B0_REGNUM && p_regnum < AARCH64_B0_REGNUM + 32)
    return b_name[p_regnum - AARCH64_B0_REGNUM];

  if (tdep->has_sve ())
    {
      static const char *const sve_v_name[] =
	{
	  "v0", "v1", "v2", "v3",
	  "v4", "v5", "v6", "v7",
	  "v8", "v9", "v10", "v11",
	  "v12", "v13", "v14", "v15",
	  "v16", "v17", "v18", "v19",
	  "v20", "v21", "v22", "v23",
	  "v24", "v25", "v26", "v27",
	  "v28", "v29", "v30", "v31",
	};

      if (p_regnum >= AARCH64_SVE_V0_REGNUM
	  && p_regnum < AARCH64_SVE_V0_REGNUM + AARCH64_V_REGS_NUM)
	return sve_v_name[p_regnum - AARCH64_SVE_V0_REGNUM];
    }

  /* RA_STATE is used for unwinding only.  Do not assign it a name - this
     prevents it from being read by methods such as
     mi_cmd_trace_frame_collected.  */
  if (tdep->has_pauth () && regnum == tdep->pauth_ra_state_regnum)
    return "";

  /* Pseudo capability registers.  */
  if (is_capability_pseudo (gdbarch, regnum))
    {
      int c_regnum = regnum - tdep->cap_pseudo_base;

      return aarch64_c_pseudo_register_names[c_regnum];
    }

  internal_error (__FILE__, __LINE__,
		  _("aarch64_pseudo_register_name: bad register number %d"),
		  p_regnum);
}

/* Implement the "pseudo_register_type" tdesc_arch_data method.  */

static struct type *
aarch64_pseudo_register_type (struct gdbarch *gdbarch, int regnum)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  int p_regnum = regnum - gdbarch_num_regs (gdbarch);

  if (p_regnum >= AARCH64_Q0_REGNUM && p_regnum < AARCH64_Q0_REGNUM + 32)
    return aarch64_vnq_type (gdbarch);

  if (p_regnum >= AARCH64_D0_REGNUM && p_regnum < AARCH64_D0_REGNUM + 32)
    return aarch64_vnd_type (gdbarch);

  if (p_regnum >= AARCH64_S0_REGNUM && p_regnum < AARCH64_S0_REGNUM + 32)
    return aarch64_vns_type (gdbarch);

  if (p_regnum >= AARCH64_H0_REGNUM && p_regnum < AARCH64_H0_REGNUM + 32)
    return aarch64_vnh_type (gdbarch);

  if (p_regnum >= AARCH64_B0_REGNUM && p_regnum < AARCH64_B0_REGNUM + 32)
    return aarch64_vnb_type (gdbarch);

  if (tdep->has_sve () && p_regnum >= AARCH64_SVE_V0_REGNUM
      && p_regnum < AARCH64_SVE_V0_REGNUM + AARCH64_V_REGS_NUM)
    return aarch64_vnv_type (gdbarch);

  if (tdep->has_pauth () && regnum == tdep->pauth_ra_state_regnum)
    return builtin_type (gdbarch)->builtin_uint64;

  /* Pseudo capability registers.  */
  if (is_capability_pseudo (gdbarch, regnum))
    return morello_capability_pseudo_type (gdbarch);

  internal_error (__FILE__, __LINE__,
		  _("aarch64_pseudo_register_type: bad register number %d"),
		  p_regnum);
}

/* Implement the "pseudo_register_reggroup_p" tdesc_arch_data method.  */

static int
aarch64_pseudo_register_reggroup_p (struct gdbarch *gdbarch, int regnum,
				    struct reggroup *group)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  int p_regnum = regnum - gdbarch_num_regs (gdbarch);

  if (p_regnum >= AARCH64_Q0_REGNUM && p_regnum < AARCH64_Q0_REGNUM + 32)
    return group == all_reggroup || group == vector_reggroup;
  else if (p_regnum >= AARCH64_D0_REGNUM && p_regnum < AARCH64_D0_REGNUM + 32)
    return (group == all_reggroup || group == vector_reggroup
	    || group == float_reggroup);
  else if (p_regnum >= AARCH64_S0_REGNUM && p_regnum < AARCH64_S0_REGNUM + 32)
    return (group == all_reggroup || group == vector_reggroup
	    || group == float_reggroup);
  else if (p_regnum >= AARCH64_H0_REGNUM && p_regnum < AARCH64_H0_REGNUM + 32)
    return group == all_reggroup || group == vector_reggroup;
  else if (p_regnum >= AARCH64_B0_REGNUM && p_regnum < AARCH64_B0_REGNUM + 32)
    return group == all_reggroup || group == vector_reggroup;
  else if (tdep->has_sve () && p_regnum >= AARCH64_SVE_V0_REGNUM
	   && p_regnum < AARCH64_SVE_V0_REGNUM + AARCH64_V_REGS_NUM)
    return group == all_reggroup || group == vector_reggroup;
  /* RA_STATE is used for unwinding only.  Do not assign it to any groups.  */
  if (tdep->has_pauth () && regnum == tdep->pauth_ra_state_regnum)
    return 0;

  /* The capability pseudo registers are just helper.  They don't belong
     to any group.  */
  if (is_capability_pseudo (gdbarch, regnum))
    return 0;

  return group == all_reggroup;
}

/* Helper for aarch64_pseudo_read_value.  */

static struct value *
aarch64_pseudo_read_value_1 (struct gdbarch *gdbarch,
			     readable_regcache *regcache, int regnum_offset,
			     int regsize, struct value *result_value)
{
  unsigned v_regnum = AARCH64_V0_REGNUM + regnum_offset;

  /* Enough space for a full vector register.  */
  gdb_byte reg_buf[register_size (gdbarch, AARCH64_V0_REGNUM)];
  gdb_static_assert (AARCH64_V0_REGNUM == AARCH64_SVE_Z0_REGNUM);

  if (regcache->raw_read (v_regnum, reg_buf) != REG_VALID)
    mark_value_bytes_unavailable (result_value, 0,
				  TYPE_LENGTH (value_type (result_value)));
  else
    memcpy (value_contents_raw (result_value), reg_buf, regsize);

  return result_value;
 }

/* Implement the "pseudo_register_read_value" gdbarch method.  */

static struct value *
aarch64_pseudo_read_value (struct gdbarch *gdbarch, readable_regcache *regcache,
			   int regnum)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  struct value *result_value = allocate_value (register_type (gdbarch, regnum));

  VALUE_LVAL (result_value) = lval_register;
  VALUE_REGNUM (result_value) = regnum;

  /* Read the capability pseudo registers.  */
  if (is_capability_pseudo (gdbarch, regnum))
    {
      gdb_byte lower_bytes[8];
      gdb_byte upper_bytes[8];

      int c_regnum = regnum - tdep->cap_pseudo_base;
      /* Fetch the corresponding C register this pseudo register maps to.  */
      int c_real_regnum = tdep->cap_reg_base + c_regnum;

      /* Read the lower 64 bits.  */
      if (regcache->raw_read_part (c_real_regnum, 0,
				   8, lower_bytes) != REG_VALID)
	mark_value_bytes_unavailable (result_value, 0, 8);
      else
	memcpy (value_contents_raw (result_value), lower_bytes, 8);

      /* Read the upper 64 bits.  */
      if (regcache->raw_read_part (c_real_regnum, 8,
				   8, upper_bytes) != REG_VALID)
	mark_value_bytes_unavailable (result_value, 0, 8);
      else
	memcpy (value_contents_raw (result_value) + 8, upper_bytes, 8);

      bool tag = gdbarch_register_tag (gdbarch, regcache, c_real_regnum);
      memcpy (value_contents_raw (result_value) + 16, &tag, 1);

      /* If we are dealing with the tag pseudo register, we need to isolate the
	 specific tag we're dealing with.  */
      return result_value;
    }

  regnum -= gdbarch_num_regs (gdbarch);

  if (regnum >= AARCH64_Q0_REGNUM && regnum < AARCH64_Q0_REGNUM + 32)
    return aarch64_pseudo_read_value_1 (gdbarch, regcache,
					regnum - AARCH64_Q0_REGNUM,
					Q_REGISTER_SIZE, result_value);

  if (regnum >= AARCH64_D0_REGNUM && regnum < AARCH64_D0_REGNUM + 32)
    return aarch64_pseudo_read_value_1 (gdbarch, regcache,
					regnum - AARCH64_D0_REGNUM,
					D_REGISTER_SIZE, result_value);

  if (regnum >= AARCH64_S0_REGNUM && regnum < AARCH64_S0_REGNUM + 32)
    return aarch64_pseudo_read_value_1 (gdbarch, regcache,
					regnum - AARCH64_S0_REGNUM,
					S_REGISTER_SIZE, result_value);

  if (regnum >= AARCH64_H0_REGNUM && regnum < AARCH64_H0_REGNUM + 32)
    return aarch64_pseudo_read_value_1 (gdbarch, regcache,
					regnum - AARCH64_H0_REGNUM,
					H_REGISTER_SIZE, result_value);

  if (regnum >= AARCH64_B0_REGNUM && regnum < AARCH64_B0_REGNUM + 32)
    return aarch64_pseudo_read_value_1 (gdbarch, regcache,
					regnum - AARCH64_B0_REGNUM,
					B_REGISTER_SIZE, result_value);

  if (tdep->has_sve () && regnum >= AARCH64_SVE_V0_REGNUM
      && regnum < AARCH64_SVE_V0_REGNUM + 32)
    return aarch64_pseudo_read_value_1 (gdbarch, regcache,
					regnum - AARCH64_SVE_V0_REGNUM,
					V_REGISTER_SIZE, result_value);

  gdb_assert_not_reached ("regnum out of bound");
}

/* Helper for aarch64_pseudo_write.  */

static void
aarch64_pseudo_write_1 (struct gdbarch *gdbarch, struct regcache *regcache,
			int regnum_offset, int regsize, const gdb_byte *buf)
{
  unsigned v_regnum = AARCH64_V0_REGNUM + regnum_offset;

  /* Enough space for a full vector register.  */
  gdb_byte reg_buf[register_size (gdbarch, AARCH64_V0_REGNUM)];
  gdb_static_assert (AARCH64_V0_REGNUM == AARCH64_SVE_Z0_REGNUM);

  /* Ensure the register buffer is zero, we want gdb writes of the
     various 'scalar' pseudo registers to behavior like architectural
     writes, register width bytes are written the remainder are set to
     zero.  */
  memset (reg_buf, 0, register_size (gdbarch, AARCH64_V0_REGNUM));

  memcpy (reg_buf, buf, regsize);
  regcache->raw_write (v_regnum, reg_buf);
}

/* Implement the "pseudo_register_write" gdbarch method.  */

static void
aarch64_pseudo_write (struct gdbarch *gdbarch, struct regcache *regcache,
		      int regnum, const gdb_byte *buf)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  /* Write the capability pseudo registers.  */
  if (is_capability_pseudo (gdbarch, regnum))
    {
      gdb_byte lower_bytes[8];
      gdb_byte upper_bytes[8];
      gdb_byte tag;

      /* Copy over the different fields.  */
      memcpy (lower_bytes, buf, 8);
      memcpy (upper_bytes, buf + 8, 8);
      memcpy (&tag, buf + 16, 1);

      /* Fetch the capability pseudo register index.  */
      int c_regnum = regnum - tdep->cap_pseudo_base;
      /* Fetch the actual C register this pseudo register maps to.  */
      int c_real_regnum = tdep->cap_reg_base + c_regnum;

      regcache->raw_write_part (c_real_regnum, 0, 8, lower_bytes);
      regcache->raw_write_part (c_real_regnum, 8, 8, upper_bytes);

      aarch64_register_set_tag (gdbarch, regcache, c_real_regnum,
				(tag != 0)? true : false);
      return;
    }

  regnum -= gdbarch_num_regs (gdbarch);

  if (regnum >= AARCH64_Q0_REGNUM && regnum < AARCH64_Q0_REGNUM + 32)
    return aarch64_pseudo_write_1 (gdbarch, regcache,
				   regnum - AARCH64_Q0_REGNUM, Q_REGISTER_SIZE,
				   buf);

  if (regnum >= AARCH64_D0_REGNUM && regnum < AARCH64_D0_REGNUM + 32)
    return aarch64_pseudo_write_1 (gdbarch, regcache,
				   regnum - AARCH64_D0_REGNUM, D_REGISTER_SIZE,
				   buf);

  if (regnum >= AARCH64_S0_REGNUM && regnum < AARCH64_S0_REGNUM + 32)
    return aarch64_pseudo_write_1 (gdbarch, regcache,
				   regnum - AARCH64_S0_REGNUM, S_REGISTER_SIZE,
				   buf);

  if (regnum >= AARCH64_H0_REGNUM && regnum < AARCH64_H0_REGNUM + 32)
    return aarch64_pseudo_write_1 (gdbarch, regcache,
				   regnum - AARCH64_H0_REGNUM, H_REGISTER_SIZE,
				   buf);

  if (regnum >= AARCH64_B0_REGNUM && regnum < AARCH64_B0_REGNUM + 32)
    return aarch64_pseudo_write_1 (gdbarch, regcache,
				   regnum - AARCH64_B0_REGNUM, B_REGISTER_SIZE,
				   buf);

  if (tdep->has_sve () && regnum >= AARCH64_SVE_V0_REGNUM
      && regnum < AARCH64_SVE_V0_REGNUM + 32)
    return aarch64_pseudo_write_1 (gdbarch, regcache,
				   regnum - AARCH64_SVE_V0_REGNUM,
				   V_REGISTER_SIZE, buf);

  gdb_assert_not_reached ("regnum out of bound");
}

/* Callback function for user_reg_add.  */

static struct value *
value_of_aarch64_user_reg (struct frame_info *frame, const void *baton)
{
  const int *reg_p = (const int *) baton;

  return value_of_register (*reg_p, frame);
}


/* Implement the "software_single_step" gdbarch method, needed to
   single step through atomic sequences on AArch64.  */

static std::vector<CORE_ADDR>
aarch64_software_single_step (struct regcache *regcache)
{
  struct gdbarch *gdbarch = regcache->arch ();
  enum bfd_endian byte_order_for_code = gdbarch_byte_order_for_code (gdbarch);
  const int insn_size = 4;
  const int atomic_sequence_length = 16; /* Instruction sequence length.  */
  CORE_ADDR pc = regcache_read_pc (regcache);
  CORE_ADDR breaks[2] = { CORE_ADDR_MAX, CORE_ADDR_MAX };
  CORE_ADDR loc = pc;
  CORE_ADDR closing_insn = 0;
  uint32_t insn = read_memory_unsigned_integer (loc, insn_size,
						byte_order_for_code);
  int index;
  int insn_count;
  int bc_insn_count = 0; /* Conditional branch instruction count.  */
  int last_breakpoint = 0; /* Defaults to 0 (no breakpoints placed).  */
  aarch64_inst inst;

  if (aarch64_decode_insn (insn, &inst, 1, NULL) != 0)
    return {};

  /* Look for a Load Exclusive instruction which begins the sequence.  */
  if (inst.opcode->iclass != ldstexcl || bit (insn, 22) == 0)
    return {};

  for (insn_count = 0; insn_count < atomic_sequence_length; ++insn_count)
    {
      loc += insn_size;
      insn = read_memory_unsigned_integer (loc, insn_size,
					   byte_order_for_code);

      if (aarch64_decode_insn (insn, &inst, 1, NULL) != 0)
	return {};
      /* Check if the instruction is a conditional branch.  */
      if (inst.opcode->iclass == condbranch)
	{
	  gdb_assert (inst.operands[0].type == AARCH64_OPND_ADDR_PCREL19);

	  if (bc_insn_count >= 1)
	    return {};

	  /* It is, so we'll try to set a breakpoint at the destination.  */
	  breaks[1] = loc + inst.operands[0].imm.value;

	  bc_insn_count++;
	  last_breakpoint++;
	}

      /* Look for the Store Exclusive which closes the atomic sequence.  */
      if (inst.opcode->iclass == ldstexcl && bit (insn, 22) == 0)
	{
	  closing_insn = loc;
	  break;
	}
    }

  /* We didn't find a closing Store Exclusive instruction, fall back.  */
  if (!closing_insn)
    return {};

  /* Insert breakpoint after the end of the atomic sequence.  */
  breaks[0] = loc + insn_size;

  /* Check for duplicated breakpoints, and also check that the second
     breakpoint is not within the atomic sequence.  */
  if (last_breakpoint
      && (breaks[1] == breaks[0]
	  || (breaks[1] >= pc && breaks[1] <= closing_insn)))
    last_breakpoint = 0;

  std::vector<CORE_ADDR> next_pcs;

  /* Insert the breakpoint at the end of the sequence, and one at the
     destination of the conditional branch, if it exists.  */
  for (index = 0; index <= last_breakpoint; index++)
    next_pcs.push_back (breaks[index]);

  return next_pcs;
}

struct aarch64_displaced_step_closure : public displaced_step_closure
{
  /* It is true when condition instruction, such as B.CON, TBZ, etc,
     is being displaced stepping.  */
  bool cond = false;

  /* PC adjustment offset after displaced stepping.  If 0, then we don't
     write the PC back, assuming the PC is already the right address.  */
  int32_t pc_adjust = 0;
};

/* Data when visiting instructions for displaced stepping.  */

struct aarch64_displaced_step_data
{
  struct aarch64_insn_data base;

  /* The address where the instruction will be executed at.  */
  CORE_ADDR new_addr;
  /* Buffer of instructions to be copied to NEW_ADDR to execute.  */
  uint32_t insn_buf[AARCH64_DISPLACED_MODIFIED_INSNS];
  /* Number of instructions in INSN_BUF.  */
  unsigned insn_count;
  /* Registers when doing displaced stepping.  */
  struct regcache *regs;
  /* The gdbarch.  */
  struct gdbarch *gdbarch;

  aarch64_displaced_step_closure *dsc;
};

/* Implementation of aarch64_insn_visitor method "b".  */

static void
aarch64_displaced_step_b (const int is_bl, const int32_t offset,
			  struct aarch64_insn_data *data)
{
  struct aarch64_displaced_step_data *dsd
    = (struct aarch64_displaced_step_data *) data;
  int64_t new_offset = data->insn_addr - dsd->new_addr + offset;
  struct gdbarch *gdbarch = dsd->gdbarch;

  if (aarch64_debug)
    debug_printf ("aarch64_displaced_step_b: Insn address %s, offset %s\n"
		  "new_offset: %s, new_addr: %s",
		  paddress (gdbarch, data->insn_addr),
		  paddress (gdbarch, offset),
		  paddress (gdbarch, new_offset),
		  paddress (gdbarch, dsd->new_addr));

  if (can_encode_int32 (new_offset, 28))
    {
      /* Emit B rather than BL, because executing BL on a new address
	 will get the wrong address into LR.  In order to avoid this,
	 we emit B, and update LR if the instruction is BL.  */
      emit_b (dsd->insn_buf, 0, new_offset);
      dsd->insn_count++;
    }
  else
    {
      /* Write NOP.  */
      emit_nop (dsd->insn_buf);
      dsd->insn_count++;
      dsd->dsc->pc_adjust = offset;
    }

  if (is_bl)
    {
      /* Update LR.  */
      regcache_cooked_write_unsigned (dsd->regs, AARCH64_LR_REGNUM,
				      data->insn_addr + 4);
    }
}

/* Implementation of aarch64_insn_visitor method "b_cond".  */

static void
aarch64_displaced_step_b_cond (const unsigned cond, const int32_t offset,
			       struct aarch64_insn_data *data)
{
  struct aarch64_displaced_step_data *dsd
    = (struct aarch64_displaced_step_data *) data;

  /* GDB has to fix up PC after displaced step this instruction
     differently according to the condition is true or false.  Instead
     of checking COND against conditional flags, we can use
     the following instructions, and GDB can tell how to fix up PC
     according to the PC value.

     B.COND TAKEN    ; If cond is true, then jump to TAKEN.
     INSN1     ;
     TAKEN:
     INSN2
  */

  emit_bcond (dsd->insn_buf, cond, 8);
  dsd->dsc->cond = true;
  dsd->dsc->pc_adjust = offset;
  dsd->insn_count = 1;
}

/* Dynamically allocate a new register.  If we know the register
   statically, we should make it a global as above instead of using this
   helper function.  */

static struct aarch64_register
aarch64_register (unsigned num, int is64)
{
  return (struct aarch64_register) { num, is64 };
}

/* Implementation of aarch64_insn_visitor method "cb".  */

static void
aarch64_displaced_step_cb (const int32_t offset, const int is_cbnz,
			   const unsigned rn, int is64,
			   struct aarch64_insn_data *data)
{
  struct aarch64_displaced_step_data *dsd
    = (struct aarch64_displaced_step_data *) data;

  /* The offset is out of range for a compare and branch
     instruction.  We can use the following instructions instead:

	 CBZ xn, TAKEN   ; xn == 0, then jump to TAKEN.
	 INSN1     ;
	 TAKEN:
	 INSN2
  */
  emit_cb (dsd->insn_buf, is_cbnz, aarch64_register (rn, is64), 8);
  dsd->insn_count = 1;
  dsd->dsc->cond = true;
  dsd->dsc->pc_adjust = offset;
}

/* Implementation of aarch64_insn_visitor method "tb".  */

static void
aarch64_displaced_step_tb (const int32_t offset, int is_tbnz,
			   const unsigned rt, unsigned bit,
			   struct aarch64_insn_data *data)
{
  struct aarch64_displaced_step_data *dsd
    = (struct aarch64_displaced_step_data *) data;

  /* The offset is out of range for a test bit and branch
     instruction We can use the following instructions instead:

     TBZ xn, #bit, TAKEN ; xn[bit] == 0, then jump to TAKEN.
     INSN1         ;
     TAKEN:
     INSN2

  */
  emit_tb (dsd->insn_buf, is_tbnz, bit, aarch64_register (rt, 1), 8);
  dsd->insn_count = 1;
  dsd->dsc->cond = true;
  dsd->dsc->pc_adjust = offset;
}

/* Implementation of aarch64_insn_visitor method "adr".  */

static void
aarch64_displaced_step_adr (const int32_t offset, const unsigned rd,
			    const int is_adrp, struct aarch64_insn_data *data)
{
  struct aarch64_displaced_step_data *dsd
    = (struct aarch64_displaced_step_data *) data;
  /* We know exactly the address the ADR{P,} instruction will compute.
     We can just write it to the destination register.  */
  CORE_ADDR address = data->insn_addr + offset;

  if (is_adrp)
    {
      /* Clear the lower 12 bits of the offset to get the 4K page.  */
      regcache_cooked_write_unsigned (dsd->regs, AARCH64_X0_REGNUM + rd,
				      address & ~0xfff);
    }
  else
      regcache_cooked_write_unsigned (dsd->regs, AARCH64_X0_REGNUM + rd,
				      address);

  dsd->dsc->pc_adjust = 4;
  emit_nop (dsd->insn_buf);
  dsd->insn_count = 1;
}

/* Implementation of aarch64_insn_visitor method "ldr_literal".  */

static void
aarch64_displaced_step_ldr_literal (const int32_t offset, const int is_sw,
				    const unsigned rt, const int is64,
				    struct aarch64_insn_data *data)
{
  struct aarch64_displaced_step_data *dsd
    = (struct aarch64_displaced_step_data *) data;
  CORE_ADDR address = data->insn_addr + offset;
  struct aarch64_memory_operand zero = { MEMORY_OPERAND_OFFSET, 0 };

  regcache_cooked_write_unsigned (dsd->regs, AARCH64_X0_REGNUM + rt,
				  address);

  if (is_sw)
    dsd->insn_count = emit_ldrsw (dsd->insn_buf, aarch64_register (rt, 1),
				  aarch64_register (rt, 1), zero);
  else
    dsd->insn_count = emit_ldr (dsd->insn_buf, aarch64_register (rt, is64),
				aarch64_register (rt, 1), zero);

  dsd->dsc->pc_adjust = 4;
}

/* Implementation of aarch64_insn_visitor method "others".  */

static void
aarch64_displaced_step_others (const uint32_t insn,
			       struct aarch64_insn_data *data)
{
  struct aarch64_displaced_step_data *dsd
    = (struct aarch64_displaced_step_data *) data;

  aarch64_emit_insn (dsd->insn_buf, insn);
  dsd->insn_count = 1;

  if ((insn & 0xfffffc1f) == 0xd65f0000)
    {
      /* RET */
      dsd->dsc->pc_adjust = 0;
    }
  else
    dsd->dsc->pc_adjust = 4;
}

static const struct aarch64_insn_visitor visitor =
{
  aarch64_displaced_step_b,
  aarch64_displaced_step_b_cond,
  aarch64_displaced_step_cb,
  aarch64_displaced_step_tb,
  aarch64_displaced_step_adr,
  aarch64_displaced_step_ldr_literal,
  aarch64_displaced_step_others,
};

/* Implement the "displaced_step_copy_insn" gdbarch method.  */

displaced_step_closure_up
aarch64_displaced_step_copy_insn (struct gdbarch *gdbarch,
				  CORE_ADDR from, CORE_ADDR to,
				  struct regcache *regs)
{
  enum bfd_endian byte_order_for_code = gdbarch_byte_order_for_code (gdbarch);
  uint32_t insn = read_memory_unsigned_integer (from, 4, byte_order_for_code);
  struct aarch64_displaced_step_data dsd;
  aarch64_inst inst;

  if (aarch64_decode_insn (insn, &inst, 1, NULL) != 0)
    return NULL;

  /* Look for a Load Exclusive instruction which begins the sequence.  */
  if (inst.opcode->iclass == ldstexcl && bit (insn, 22))
    {
      /* We can't displaced step atomic sequences.  */
      return NULL;
    }

  std::unique_ptr<aarch64_displaced_step_closure> dsc
    (new aarch64_displaced_step_closure);
  dsd.base.insn_addr = from;
  dsd.new_addr = to;
  dsd.regs = regs;
  dsd.gdbarch = gdbarch;
  dsd.dsc = dsc.get ();
  dsd.insn_count = 0;
  aarch64_relocate_instruction (insn, &visitor,
				(struct aarch64_insn_data *) &dsd);
  gdb_assert (dsd.insn_count <= AARCH64_DISPLACED_MODIFIED_INSNS);

  if (dsd.insn_count != 0)
    {
      int i;

      /* Instruction can be relocated to scratch pad.  Copy
	 relocated instruction(s) there.  */
      for (i = 0; i < dsd.insn_count; i++)
	{
	  if (debug_displaced)
	    {
	      debug_printf ("displaced: writing insn ");
	      debug_printf ("%.8x", dsd.insn_buf[i]);
	      debug_printf (" at %s\n", paddress (gdbarch, to + i * 4));
	    }
	  write_memory_unsigned_integer (to + i * 4, 4, byte_order_for_code,
					 (ULONGEST) dsd.insn_buf[i]);
	}
    }
  else
    {
      dsc = NULL;
    }

  /* This is a work around for a problem with g++ 4.8.  */
  return displaced_step_closure_up (dsc.release ());
}

/* Implement the "displaced_step_fixup" gdbarch method.  */

void
aarch64_displaced_step_fixup (struct gdbarch *gdbarch,
			      struct displaced_step_closure *dsc_,
			      CORE_ADDR from, CORE_ADDR to,
			      struct regcache *regs)
{
  aarch64_displaced_step_closure *dsc = (aarch64_displaced_step_closure *) dsc_;

  ULONGEST pc;

  regcache_cooked_read_unsigned (regs, AARCH64_PC_REGNUM, &pc);

  if (debug_displaced)
    debug_printf ("Displaced: PC after stepping: %s (was %s).\n",
		  paddress (gdbarch, pc), paddress (gdbarch, to));

  if (dsc->cond)
    {
      if (debug_displaced)
	debug_printf ("Displaced: [Conditional] pc_adjust before: %d\n",
		      dsc->pc_adjust);

      if (pc - to == 8)
	{
	  /* Condition is true.  */
	}
      else if (pc - to == 4)
	{
	  /* Condition is false.  */
	  dsc->pc_adjust = 4;
	}
      else
	gdb_assert_not_reached ("Unexpected PC value after displaced stepping");

      if (debug_displaced)
	debug_printf ("Displaced: [Conditional] pc_adjust after: %d\n",
		      dsc->pc_adjust);
    }

  if (debug_displaced)
    debug_printf ("Displaced: %s PC by %d\n",
		  dsc->pc_adjust? "adjusting" : "not adjusting",
		  dsc->pc_adjust);


  if (dsc->pc_adjust != 0)
    {
      /* Make sure the previous instruction was executed (that is, the PC
	 has changed).  If the PC didn't change, then discard the adjustment
	 offset.  Otherwise we may skip an instruction before its execution
	 took place.  */
      if ((pc - to) == 0)
	{
	  if (debug_displaced)
	    debug_printf ("Displaced: PC did not move. Discarding PC "
			  "adjustment.\n");
	  dsc->pc_adjust = 0;
	}

      if (debug_displaced)
	{
	  debug_printf ("Displaced: fixup: set PC to %s:%d\n",
			paddress (gdbarch, from), dsc->pc_adjust);
	}
      regcache_cooked_write_unsigned (regs, AARCH64_PC_REGNUM,
				      from + dsc->pc_adjust);
    }
}

/* Implement the "displaced_step_hw_singlestep" gdbarch method.  */

int
aarch64_displaced_step_hw_singlestep (struct gdbarch *gdbarch,
				      struct displaced_step_closure *closure)
{
  return 1;
}

/* Get the correct target description for the given VQ value.
   If VQ is zero then it is assumed SVE is not supported.
   (It is not possible to set VQ to zero on an SVE system).  */

const target_desc *
aarch64_read_description (uint64_t vq, bool pauth_p, bool capability_p)
{
  if (vq > AARCH64_MAX_SVE_VQ)
    error (_("VQ is %" PRIu64 ", maximum supported value is %d"), vq,
	   AARCH64_MAX_SVE_VQ);

  struct target_desc *tdesc = tdesc_aarch64_list[vq][pauth_p][capability_p];

  if (tdesc == NULL)
    {
      tdesc = aarch64_create_target_description (vq, pauth_p, capability_p);
      tdesc_aarch64_list[vq][pauth_p][capability_p] = tdesc;
    }

  return tdesc;
}

/* Return the VQ used when creating the target description TDESC.  */

static uint64_t
aarch64_get_tdesc_vq (const struct target_desc *tdesc)
{
  const struct tdesc_feature *feature_sve;

  if (!tdesc_has_registers (tdesc))
    return 0;

  feature_sve = tdesc_find_feature (tdesc, "org.gnu.gdb.aarch64.sve");

  if (feature_sve == nullptr)
    return 0;

  uint64_t vl = tdesc_register_bitsize (feature_sve,
					aarch64_sve_register_names[0]) / 8;
  return sve_vq_from_vl (vl);
}

/* Add all the expected register sets into GDBARCH.  */

static void
aarch64_add_reggroups (struct gdbarch *gdbarch)
{
  reggroup_add (gdbarch, general_reggroup);
  reggroup_add (gdbarch, float_reggroup);
  reggroup_add (gdbarch, system_reggroup);
  reggroup_add (gdbarch, vector_reggroup);
  reggroup_add (gdbarch, all_reggroup);
  reggroup_add (gdbarch, save_reggroup);
  reggroup_add (gdbarch, restore_reggroup);
}

/* Implement the "cannot_store_register" gdbarch method.  */

static int
aarch64_cannot_store_register (struct gdbarch *gdbarch, int regnum)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep->has_pauth ())
    {
      /* Pointer authentication registers are read-only.  */
      return (regnum == AARCH64_PAUTH_DMASK_REGNUM (tdep->pauth_reg_base)
	      || regnum == AARCH64_PAUTH_CMASK_REGNUM (tdep->pauth_reg_base));
    }

  return 0;
}

/* Implementation of `address_class_type_flags' gdbarch method.

   This method maps DW_AT_address_class attributes to a
   type_instance_flag_value.  */

static type_instance_flags
aarch64_address_class_type_flags (int byte_size, int dwarf2_addr_class)
{
  /* The value 1 of the DW_AT_address_class attribute corresponds to the
     __capability qualifier, meaning a capability for Morello.  */

  if (dwarf2_addr_class == 1)
    return TYPE_INSTANCE_FLAG_CAPABILITY;
  return 0;
}

/* Implementation of `address_class_type_flags_to_name' gdbarch method.

   Convert a type_instance_flag_value to an address space qualifier.  */

static const char*
aarch64_address_class_type_flags_to_name (struct gdbarch *gdbarch,
					  type_instance_flags type_flags)
{
    /* No need to display the extra __capability modifier.  GDB already takes
       cares of this.  */
    return NULL;
}

/* Implementation of `address_class_name_to_type_flags' gdbarch method.

   Convert an address space qualifier to a type_instance_flag_value.  */

static bool
aarch64_address_class_name_to_type_flags (struct gdbarch *gdbarch,
					  const char* name,
					  type_instance_flags *type_flags_ptr)
{
  if (strcmp (name, "__capability") == 0)
    {
      *type_flags_ptr = TYPE_INSTANCE_FLAG_CAPABILITY;
      return true;
    }
  else
    return false;
}

/* Implements the gdbarch_pointer_to_address hook.  */

static CORE_ADDR
aarch64_pointer_to_address (struct gdbarch *gdbarch, struct type *type,
			    const gdb_byte *buf)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  if (aarch64_debug)
    debug_printf ("aarch64: entering %s\n", __func__);

  if (type->length <= 8)
    return signed_pointer_to_address (gdbarch, type, buf);
  else
    {
      /* Convert a capability to a regular 64-bit address, discarding
	 the extra information.  */
      return extract_unsigned_integer (buf, 8, byte_order);
    }

  if (aarch64_debug)
    debug_printf ("aarch64: Exiting %s\n", __func__);
}

/* Implements the gdbarch_address_to_pointer hook.  */

static void
aarch64_address_to_pointer (struct gdbarch *gdbarch, struct type *type,
			    gdb_byte *buf, CORE_ADDR addr)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  if (aarch64_debug)
    debug_printf ("aarch64: Entering %s\n", __func__);

  if (type->length <= 8)
    address_to_signed_pointer (gdbarch, type, buf, addr);
  else
    {
      /* Create a fake capability with only the address part.  */
      memset (buf, 0, type->length);
      store_unsigned_integer (buf, 8, byte_order, addr);
    }

  if (aarch64_debug)
    debug_printf ("aarch64: Exiting %s\n", __func__);
}

/* Implements the gdbarch_integer_to_address hook.  */

static CORE_ADDR
aarch64_integer_to_address (struct gdbarch *gdbarch,
			    struct type *type, const gdb_byte *buf)
{
  if (aarch64_debug)
    debug_printf ("aarch64: Entering %s\n", __func__);

  return aarch64_pointer_to_address (gdbarch, type, buf);

  if (aarch64_debug)
    debug_printf ("aarch64: Exiting %s\n", __func__);
}

/* Remove useless bits from addresses in a running program.  This is
   important for Morello due to the C64 mode having the LSB set.  */

static CORE_ADDR
aarch64_addr_bits_remove (struct gdbarch *gdbarch, CORE_ADDR val)
{
  return (val & ~1);
}

/* Given ABFD, try to determine if we are dealing with a symbol file
   that uses capabilities.

   Return true if the symbol file uses capabilities and false otherwise.  */

static bool
aarch64_bfd_has_capabilities (bfd *abfd)
{
  if (aarch64_debug)
    debug_printf ("%s: Entering\n", __func__);

  gdb_assert (abfd != nullptr);

  int e_flags = elf_elfheader (abfd)->e_flags;

  if (aarch64_debug)
    debug_printf ("%s: e_flags = %x\n", __func__, e_flags);

  if (e_flags & EF_AARCH64_CHERI_PURECAP)
    return true;

  if (aarch64_debug)
    debug_printf ("%s: e_flags doesn't contain EF_AARCH64_CHERI_PURECAP.\n",
		  __func__);

  /* Use the LSB of e_entry for now.  If the LSB is set, this means we have a
     Morello pure capability binary.  */
  if (elf_elfheader (abfd)->e_entry & 1)
    return true;

  if (aarch64_debug)
    debug_printf ("%s: e_entry's LSB is not set.  Assuming AAPCS64 ABI.\n",
		  __func__);

  /* Assume this is a Hybrid ABI ELF.  */
  return false;
}

/* Test whether SYM corresponds to an address in C64 code.  If so,
   set a special bit in MSYM to indicate that it does.  */

static void
aarch64_elf_make_msymbol_special(asymbol *sym, struct minimal_symbol *msym)
{
  if (aarch64_debug)
    debug_printf ("%s: Entering\n", __func__);

  /* We are interested in symbols that represent functions whose addresses
     have the LSB set.  */
  if ((sym->flags & BSF_FUNCTION)
      && (MSYMBOL_VALUE_RAW_ADDRESS (msym) & 1))
    {
      /* Set the special bit and mask off the LSB.  */
      MSYMBOL_SET_SPECIAL (msym);
      SET_MSYMBOL_VALUE_ADDRESS (msym, MSYMBOL_VALUE_RAW_ADDRESS (msym) & ~1);
    }

  if (aarch64_debug)
    debug_printf ("%s: Symbol %s is %sspecial\n", __func__,
		  sym->name, MSYMBOL_IS_SPECIAL (msym)? "" : "not ");
}

/* Record mapping symbols for Morello.  From the documentation, those
   can be:

   $x or $x.<any...>: Start of a sequence of A64 instructions

   $c or $c.<any...>: Start of a sequence of C64 instructions

   $d or $d.<any...>: Start of a sequence of data items (for example, a literal
		      pool)
*/

static void
aarch64_record_special_symbol (struct gdbarch *gdbarch, struct objfile *objfile,
			       asymbol *sym)
{
  if (aarch64_debug)
    debug_printf ("%s: Entering\n", __func__);

  const char *name = bfd_asymbol_name (sym);
  struct aarch64_per_bfd *data;
  struct aarch64_mapping_symbol new_map_sym;

  gdb_assert (name[0] == '$');

  if(aarch64_debug)
    debug_printf ("%s: Checking symbol %s\n", __func__, name);

  if (name[1] != 'x' && name[1] != 'c' && name[1] != 'd')
    return;

  data = aarch64_bfd_data_key.get (objfile->obfd);
  if (data == NULL)
    data = aarch64_bfd_data_key.emplace (objfile->obfd,
					 objfile->obfd->section_count);
  aarch64_mapping_symbol_vec &map
    = data->section_maps[bfd_asymbol_section (sym)->index];

  new_map_sym.value = sym->value;
  new_map_sym.type = name[1];

  /* Insert at the end, the vector will be sorted on first use.  */
  map.push_back (new_map_sym);

  if (aarch64_debug)
    debug_printf ("%s: Symbol %s recorded as special.\n", __func__,
		  name);
}

/* Implements the gdbarch_register_has_tag hook.  */

static bool
aarch64_register_has_tag (struct gdbarch *gdbarch,
			  readable_regcache *regcache,
			  int regnum)
{
  if (aarch64_debug)
    debug_printf ("%s: Entering\n", __func__);

  if (!morello_is_tagged_register (gdbarch, regnum))
    return false;

  if (aarch64_debug)
    debug_printf ("%s: regnum %d\n", __func__, regnum);

  return true;
}

/* Implements the gdbarch_register_tag hook.  */

static bool
aarch64_register_tag (struct gdbarch *gdbarch,
		      readable_regcache *regcache,
		      int regnum)
{
  if (aarch64_debug)
    debug_printf ("%s: Entering\n", __func__);

  if (!morello_is_tagged_register (gdbarch, regnum))
    return false;

  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  /* The CSP/PCC tags are swapped in the tag_map because the ordering of CSP/PCC
     in struct user_morello_state is different from GDB's register description.

     Make sure we account for that when extracting the tag from those
     registers.  */
  if (regnum == tdep->cap_reg_pcc)
    regnum = tdep->cap_reg_csp;
  else if (regnum == tdep->cap_reg_csp)
    regnum = tdep->cap_reg_pcc;

  /* Find the proper bit within the tag_map.  */
  int shift = regnum - tdep->cap_reg_base;
  ULONGEST tag_map = 0;

  /* Fetch the tag_map register.  */
  regcache->cooked_read (tdep->cap_reg_last - 1, &tag_map);

  if (aarch64_debug)
    debug_printf ("%s: regnum %d, shift %d, tag bit %ld, tag_map %lx\n",
		  __func__, regnum, shift,
		  (tag_map >> shift) & 1, tag_map);

  if (((tag_map >> shift) & 1) == 0)
    return false;

  return true;
}

/* Morello-specific hook to write the PC.  This is mostly used when calling
   a function by hand.  Different DSO's have different bounds for PCC, so GDB
   would need to figure out those bounds.

   Given that information is not currently available, we set maximum bounds
   for PCC as a compromise.  */

static void
morello_write_pc (struct regcache *regs, CORE_ADDR pc)
{
  struct gdbarch *gdbarch = regs->arch ();
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  regs->cooked_write_part (tdep->cap_reg_pcc, 0, sizeof (pc),
			   (const gdb_byte *) &pc);

  /* Upper 64 bits of the capability with maximum bounds and reasonable
     permissions.  We only adjust this if we are using the purecap ABI.  */
  pc = 0xffffc00000010005;
  regs->cooked_write_part (tdep->cap_reg_pcc, 8, sizeof (pc),
			   (const gdb_byte *) &pc);

  /* We may need to set the tag of the PCC here, but we don't do so at the
     moment.  If this turns out to be a problem in the future, we should
     force the tag to 1.  */
}

/* Initialize the current architecture based on INFO.  If possible,
   re-use an architecture from ARCHES, which is a list of
   architectures already created during this debugging session.

   Called e.g. at program startup, when reading a core file, and when
   reading a binary file.  */

static struct gdbarch *
aarch64_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  const struct tdesc_feature *feature_core, *feature_fpu, *feature_sve;
  const struct tdesc_feature *feature_pauth;
  bool valid_p = true;
  int i, num_regs = 0, num_pseudo_regs = 0;
  int first_pauth_regnum = -1, pauth_ra_state_offset = -1;
  aarch64_abi_kind abi = (aarch64_current_abi_global == AARCH64_ABI_AUTO)?
    AARCH64_ABI_AAPCS64 : aarch64_current_abi_global;

  /* Use the vector length passed via the target info.  Here -1 is used for no
     SVE, and 0 is unset.  If unset then use the vector length from the existing
     tdesc.  */
  uint64_t vq = 0;
  if (info.id == (int *) -1)
    vq = 0;
  else if (info.id != 0)
    vq = (uint64_t) info.id;
  else
    vq = aarch64_get_tdesc_vq (info.target_desc);

  if (vq > AARCH64_MAX_SVE_VQ)
    internal_error (__FILE__, __LINE__, _("VQ out of bounds: %s (max %d)"),
		    pulongest (vq), AARCH64_MAX_SVE_VQ);

  /* If we have a symbol file, try to determine if it uses capabilities or if
     it is just regular AArch64.  */
  bool have_capability = false;
  if (aarch64_current_abi_global == AARCH64_ABI_AUTO && info.abfd != NULL)
    {
      if (aarch64_bfd_has_capabilities (info.abfd))
	{
	  abi = AARCH64_ABI_AAPCS64_CAP;
	  have_capability = true;
	}
    }
  else if (aarch64_current_abi_global == AARCH64_ABI_AAPCS64_CAP)
    have_capability = true;

  /* If there is already a candidate, use it.  */
  for (gdbarch_list *best_arch = gdbarch_list_lookup_by_info (arches, &info);
       best_arch != nullptr;
       best_arch = gdbarch_list_lookup_by_info (best_arch->next, &info))
    {
      struct gdbarch_tdep *tdep = gdbarch_tdep (best_arch->gdbarch);
      if (tdep && tdep->vq == vq
	  && tdep->abi == abi)
	return best_arch->gdbarch;
    }

  /* Ensure we always have a target descriptor, and that it is for the given VQ
     value.  */
  const struct target_desc *tdesc = info.target_desc;
  if (!tdesc_has_registers (tdesc) || vq != aarch64_get_tdesc_vq (tdesc))
    tdesc = aarch64_read_description (vq, false, have_capability);
  gdb_assert (tdesc);

  feature_core = tdesc_find_feature (tdesc,"org.gnu.gdb.aarch64.core");
  feature_fpu = tdesc_find_feature (tdesc, "org.gnu.gdb.aarch64.fpu");
  feature_sve = tdesc_find_feature (tdesc, "org.gnu.gdb.aarch64.sve");
  feature_pauth = tdesc_find_feature (tdesc, "org.gnu.gdb.aarch64.pauth");

  if (feature_core == nullptr)
    return nullptr;

  tdesc_arch_data_up tdesc_data = tdesc_data_alloc ();

  /* Validate the description provides the mandatory core R registers
     and allocate their numbers.  */
  for (i = 0; i < ARRAY_SIZE (aarch64_r_register_names); i++)
    valid_p &= tdesc_numbered_register (feature_core, tdesc_data.get (),
					AARCH64_X0_REGNUM + i,
					aarch64_r_register_names[i]);

  num_regs = AARCH64_X0_REGNUM + i;

  /* Add the V registers.  */
  if (feature_fpu != nullptr)
    {
      if (feature_sve != nullptr)
	error (_("Program contains both fpu and SVE features."));

      /* Validate the description provides the mandatory V registers
	 and allocate their numbers.  */
      for (i = 0; i < ARRAY_SIZE (aarch64_v_register_names); i++)
	valid_p &= tdesc_numbered_register (feature_fpu, tdesc_data.get (),
					    AARCH64_V0_REGNUM + i,
					    aarch64_v_register_names[i]);

      num_regs = AARCH64_V0_REGNUM + i;
    }

  /* Add the SVE registers.  */
  if (feature_sve != nullptr)
    {
      /* Validate the description provides the mandatory SVE registers
	 and allocate their numbers.  */
      for (i = 0; i < ARRAY_SIZE (aarch64_sve_register_names); i++)
	valid_p &= tdesc_numbered_register (feature_sve, tdesc_data.get (),
					    AARCH64_SVE_Z0_REGNUM + i,
					    aarch64_sve_register_names[i]);

      num_regs = AARCH64_SVE_Z0_REGNUM + i;
      num_pseudo_regs += 32;	/* add the Vn register pseudos.  */
    }

  if (feature_fpu != nullptr || feature_sve != nullptr)
    {
      num_pseudo_regs += 32;	/* add the Qn scalar register pseudos */
      num_pseudo_regs += 32;	/* add the Dn scalar register pseudos */
      num_pseudo_regs += 32;	/* add the Sn scalar register pseudos */
      num_pseudo_regs += 32;	/* add the Hn scalar register pseudos */
      num_pseudo_regs += 32;	/* add the Bn scalar register pseudos */
    }

  /* Add the pauth registers.  */
  if (feature_pauth != NULL)
    {
      first_pauth_regnum = num_regs;
      pauth_ra_state_offset = num_pseudo_regs;
      /* Validate the descriptor provides the mandatory PAUTH registers and
	 allocate their numbers.  */
      for (i = 0; i < ARRAY_SIZE (aarch64_pauth_register_names); i++)
	valid_p &= tdesc_numbered_register (feature_pauth, tdesc_data.get (),
					    first_pauth_regnum + i,
					    aarch64_pauth_register_names[i]);

      num_regs += i;
      num_pseudo_regs += 1;	/* Count RA_STATE pseudo register.  */
    }

  /* Add the capability registers.  */
  const struct tdesc_feature *feature_capability
      = tdesc_find_feature (tdesc,"org.gnu.gdb.aarch64.capability");
  int first_cap_regnum = -1;
  int last_cap_regnum = -1;
  int first_cap_pseudo = -1;

  if (feature_capability != nullptr)
    {
      first_cap_regnum = num_regs;

      for (i = 0; i < ARRAY_SIZE (aarch64_c_register_names); i++)
	valid_p &= tdesc_numbered_register (feature_capability,
					    tdesc_data.get (),
					    first_cap_regnum + i,
					    aarch64_c_register_names[i]);

      last_cap_regnum = first_cap_regnum + i - 1;
      num_regs += i;

      /* Also add pseudo registers to make it easier to set the whole 129
	 bits of the C registers.  Each C register is broken into 3 fields:

	 - lower 64 bits: Contains the value (pointer).
	 - upper 64 bits: Contains the bounds/permissions/flags.
	 - tag bit (1 bit): Contains the capability tag.
      */

      first_cap_pseudo = num_pseudo_regs;
      /* 39 pseudo capability registers.  */
      num_pseudo_regs += AARCH64_C_PSEUDO_COUNT;
    }

  if (!valid_p)
    return nullptr;

  /* AArch64 code is always little-endian.  */
  info.byte_order_for_code = BFD_ENDIAN_LITTLE;

  struct gdbarch_tdep *tdep = XCNEW (struct gdbarch_tdep);
  struct gdbarch *gdbarch = gdbarch_alloc (&info, tdep);

  tdep->abi = abi;
  /* This should be low enough for everything.  */
  tdep->lowest_pc = 0x20;
  tdep->jb_pc = -1;		/* Longjump support not enabled by default.  */
  tdep->jb_elt_size = 8;
  tdep->vq = vq;
  tdep->pauth_reg_base = first_pauth_regnum;
  tdep->pauth_ra_state_regnum = (feature_pauth == NULL) ? -1
				: pauth_ra_state_offset + num_regs;

  /* Initialize the capability register numbers.  */
  tdep->cap_reg_base = first_cap_regnum;
  tdep->cap_reg_last = last_cap_regnum;
  tdep->cap_reg_clr = (first_cap_regnum == -1)? -1 : first_cap_regnum + 30;
  tdep->cap_reg_csp = (first_cap_regnum == -1)? -1 : first_cap_regnum + 31;
  tdep->cap_reg_pcc = (first_cap_regnum == -1)? -1 : first_cap_regnum + 32;
  tdep->cap_reg_rcsp = (first_cap_regnum == -1)? -1 : first_cap_regnum + 35;

  set_gdbarch_push_dummy_call (gdbarch, aarch64_push_dummy_call);
  set_gdbarch_frame_align (gdbarch, aarch64_frame_align);

  /* Advance PC across function entry code.  */
  set_gdbarch_skip_prologue (gdbarch, aarch64_skip_prologue);

  /* The stack grows downward.  */
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);

  /* Breakpoint manipulation.  */
  set_gdbarch_breakpoint_kind_from_pc (gdbarch,
				       aarch64_breakpoint::kind_from_pc);
  set_gdbarch_sw_breakpoint_from_kind (gdbarch,
				       aarch64_breakpoint::bp_from_kind);
  set_gdbarch_have_nonsteppable_watchpoint (gdbarch, 1);
  set_gdbarch_software_single_step (gdbarch, aarch64_software_single_step);

  /* Information about registers, etc.  */
  set_gdbarch_sp_regnum (gdbarch, AARCH64_SP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, AARCH64_PC_REGNUM);
  set_gdbarch_num_regs (gdbarch, num_regs);

  set_gdbarch_num_pseudo_regs (gdbarch, num_pseudo_regs);
  set_gdbarch_pseudo_register_read_value (gdbarch, aarch64_pseudo_read_value);
  set_gdbarch_pseudo_register_write (gdbarch, aarch64_pseudo_write);
  set_tdesc_pseudo_register_name (gdbarch, aarch64_pseudo_register_name);
  set_tdesc_pseudo_register_type (gdbarch, aarch64_pseudo_register_type);
  set_tdesc_pseudo_register_reggroup_p (gdbarch,
					aarch64_pseudo_register_reggroup_p);
  set_gdbarch_cannot_store_register (gdbarch, aarch64_cannot_store_register);

  /* ABI */
  set_gdbarch_short_bit (gdbarch, 16);
  set_gdbarch_int_bit (gdbarch, 32);
  set_gdbarch_float_bit (gdbarch, 32);
  set_gdbarch_double_bit (gdbarch, 64);
  set_gdbarch_long_double_bit (gdbarch, 128);
  set_gdbarch_long_bit (gdbarch, 64);
  set_gdbarch_long_long_bit (gdbarch, 64);
  set_gdbarch_ptr_bit (gdbarch, 64);
  /* Regardless of the ABI, capabilities are always 128-bit.  */
  set_gdbarch_capability_bit (gdbarch, 128);
  set_gdbarch_char_signed (gdbarch, 0);
  set_gdbarch_wchar_signed (gdbarch, 0);
  set_gdbarch_float_format (gdbarch, floatformats_ieee_single);
  set_gdbarch_double_format (gdbarch, floatformats_ieee_double);
  set_gdbarch_long_double_format (gdbarch, floatformats_ia64_quad);
  set_gdbarch_type_align (gdbarch, aarch64_type_align);

  /* Internal <-> external register number maps.  */
  set_gdbarch_dwarf2_reg_to_regnum (gdbarch, aarch64_dwarf_reg_to_regnum);

  /* Returning results.  */
  set_gdbarch_return_value (gdbarch, aarch64_return_value);

  /* Disassembly.  */
  set_gdbarch_print_insn (gdbarch, aarch64_gdb_print_insn);

  /* Virtual tables.  */
  set_gdbarch_vbit_in_delta (gdbarch, 1);

  /* Register architecture.  */
  aarch64_add_reggroups (gdbarch);

  /* Hook in the ABI-specific overrides, if they have been registered.  */
  info.target_desc = tdesc;
  info.tdesc_data = tdesc_data.get ();
  gdbarch_init_osabi (info, gdbarch);

  dwarf2_frame_set_init_reg (gdbarch, aarch64_dwarf2_frame_init_reg);
  /* Register DWARF CFA vendor handler.  */
  set_gdbarch_execute_dwarf_cfa_vendor_op (gdbarch,
					   aarch64_execute_dwarf_cfa_vendor_op);

  /* Permanent/Program breakpoint handling.  */
  set_gdbarch_program_breakpoint_here_p (gdbarch,
					 aarch64_program_breakpoint_here_p);

  /* Add some default predicates.  */
  frame_unwind_append_unwinder (gdbarch, &aarch64_stub_unwind);
  dwarf2_append_unwinders (gdbarch);
  frame_unwind_append_unwinder (gdbarch, &aarch64_prologue_unwind);

  frame_base_set_default (gdbarch, &aarch64_normal_base);

  /* Now we have tuned the configuration, set a few final things,
     based on what the OS ABI has told us.  */

  if (tdep->jb_pc >= 0)
    set_gdbarch_get_longjmp_target (gdbarch, aarch64_get_longjmp_target);

  set_gdbarch_gen_return_address (gdbarch, aarch64_gen_return_address);

  set_gdbarch_get_pc_address_flags (gdbarch, aarch64_get_pc_address_flags);

  tdesc_use_registers (gdbarch, tdesc, std::move (tdesc_data));

  /* Add standard register aliases.  */
  for (i = 0; i < ARRAY_SIZE (aarch64_register_aliases); i++)
    user_reg_add (gdbarch, aarch64_register_aliases[i].name,
		  value_of_aarch64_user_reg,
		  &aarch64_register_aliases[i].regnum);

  register_aarch64_ravenscar_ops (gdbarch);

  /* Set address class hooks for capabilities.  */
  if (feature_capability)
    {
      if (have_capability)
	{
	  /* These hooks only make sense if we are using the AAPCS64-CAP
	     ABI.  */
	  set_gdbarch_sp_regnum (gdbarch, tdep->cap_reg_csp);
	  set_gdbarch_pc_regnum (gdbarch, tdep->cap_reg_pcc);

	  /* Hook to adjust the PCC bounds.  */
	  set_gdbarch_write_pc (gdbarch, morello_write_pc);

	  /* Morello-specific implementations for function calls and returning
	     of results.  */
	  set_gdbarch_push_dummy_call (gdbarch, morello_push_dummy_call);
	  set_gdbarch_return_value (gdbarch, morello_return_value);
	}

      /* Address manipulation.  */
      set_gdbarch_addr_bits_remove (gdbarch, aarch64_addr_bits_remove);

      set_gdbarch_address_class_type_flags
	(gdbarch, aarch64_address_class_type_flags);
      set_gdbarch_address_class_name_to_type_flags
	(gdbarch, aarch64_address_class_name_to_type_flags);
      set_gdbarch_address_class_type_flags_to_name
	(gdbarch, aarch64_address_class_type_flags_to_name);

      /* For converting between pointer/capability.  */
      set_gdbarch_pointer_to_address (gdbarch, aarch64_pointer_to_address);
      set_gdbarch_address_to_pointer (gdbarch, aarch64_address_to_pointer);
      set_gdbarch_integer_to_address (gdbarch, aarch64_integer_to_address);

      /* For marking special symbols indicating a C64 region.  */
      set_gdbarch_elf_make_msymbol_special (gdbarch,
					    aarch64_elf_make_msymbol_special);
      /* For recording mapping symbols.  */
      set_gdbarch_record_special_symbol (gdbarch,
					 aarch64_record_special_symbol);

      /* For fetching register tag information.  */
      set_gdbarch_register_has_tag (gdbarch, aarch64_register_has_tag);
      set_gdbarch_register_tag (gdbarch, aarch64_register_tag);
      set_gdbarch_register_set_tag (gdbarch, aarch64_register_set_tag);

      /* Create the Morello register aliases.  */
      /* cip0 and cip1 */
      aarch64_morello_register_aliases[0].regnum = tdep->cap_reg_base + 16;
      aarch64_morello_register_aliases[1].regnum = tdep->cap_reg_base + 17;
      /* cfp */
      aarch64_morello_register_aliases[2].regnum = tdep->cap_reg_base + 29;
      /* clr */
      aarch64_morello_register_aliases[3].regnum = tdep->cap_reg_base + 30;
      /* c31 */
      aarch64_morello_register_aliases[4].regnum = tdep->cap_reg_base + 31;


      for (i = 0; i < ARRAY_SIZE (aarch64_morello_register_aliases); i++)
	user_reg_add (gdbarch, aarch64_morello_register_aliases[i].name,
		      value_of_aarch64_user_reg,
		      &aarch64_morello_register_aliases[i].regnum);

      num_regs = gdbarch_num_regs (gdbarch);
      tdep->cap_pseudo_base
	= (first_cap_pseudo == -1)? -1 : num_regs + first_cap_pseudo;
      tdep->cap_pseudo_count
	= (first_cap_pseudo == -1)? 0 : AARCH64_C_PSEUDO_COUNT;
    }

  return gdbarch;
}

static void
aarch64_dump_tdep (struct gdbarch *gdbarch, struct ui_file *file)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (tdep == NULL)
    return;

  fprintf_unfiltered (file, _("%s: Lowest pc = 0x%s"),
		      __func__, paddress (gdbarch, tdep->lowest_pc));

  fprintf_unfiltered (file, _("%s: ABI is %s"),
		      __func__, aarch64_abi_strings[tdep->abi]);
}

#if GDB_SELF_TEST
namespace selftests
{
static void aarch64_process_record_test (void);



static void aarch64_capability_decoding_test (void);

static void aarch64_capability_decoding_test (void)
{
  capability c;

  test_bit_functions ();
  c.test_is_internal_exponent ();
  c.test_get_exponent ();
  c.test_get_effective_exponent ();
  c.test_get_bottom ();
  c.test_get_top ();
  c.test_bounds_address ();
  c.test_get_bounds ();
  c.test_set_bounds ();
  c.test_is_in_bounds ();
  c.test_flags ();
  c.test_object_types ();
  c.test_permissions ();
}

}
#endif

void _initialize_aarch64_tdep ();
void
_initialize_aarch64_tdep ()
{
  gdbarch_register (bfd_arch_aarch64, aarch64_gdbarch_init,
		    aarch64_dump_tdep);

  /* Add root prefix command for all set/show aarch64 commands.  */
  add_basic_prefix_cmd ("aarch64", no_class,
			_("Various AArch64-specific commands."),
			&set_aarch64_cmdlist, "set aarch64 ", 0, &setlist);

  add_show_prefix_cmd ("aarch64", no_class,
		       _("Various AArch64-specific commands."),
		       &show_aarch64_cmdlist, "show aarch64 ", 0, &showlist);

  /* Add a command to allow the user to force the ABI.  */
  add_setshow_enum_cmd ("abi", class_support, aarch64_abi_strings,
			&aarch64_current_abi_string,
			_("Set the ABI."),
			_("Show the ABI."),
			NULL, aarch64_set_abi, aarch64_show_abi,
			&set_aarch64_cmdlist, &show_aarch64_cmdlist);

  /* Debug this file's internals.  */
  add_setshow_boolean_cmd ("aarch64", class_maintenance, &aarch64_debug, _("\
Set AArch64 debugging."), _("\
Show AArch64 debugging."), _("\
When on, AArch64 specific debugging is enabled."),
			    NULL,
			    show_aarch64_debug,
			    &setdebuglist, &showdebuglist);

#if GDB_SELF_TEST
  selftests::register_test ("aarch64-analyze-prologue",
			    selftests::aarch64_analyze_prologue_test);
  selftests::register_test ("aarch64-process-record",
			    selftests::aarch64_process_record_test);

  selftests::register_test ("capability_decoding",
			    selftests::aarch64_capability_decoding_test);
#endif
}

/* AArch64 process record-replay related structures, defines etc.  */

#define REG_ALLOC(REGS, LENGTH, RECORD_BUF) \
        do  \
          { \
            unsigned int reg_len = LENGTH; \
            if (reg_len) \
              { \
                REGS = XNEWVEC (uint32_t, reg_len); \
                memcpy(&REGS[0], &RECORD_BUF[0], sizeof(uint32_t)*LENGTH); \
              } \
          } \
        while (0)

#define MEM_ALLOC(MEMS, LENGTH, RECORD_BUF) \
        do  \
          { \
            unsigned int mem_len = LENGTH; \
            if (mem_len) \
            { \
              MEMS =  XNEWVEC (struct aarch64_mem_r, mem_len);  \
              memcpy(&MEMS->len, &RECORD_BUF[0], \
                     sizeof(struct aarch64_mem_r) * LENGTH); \
            } \
          } \
          while (0)

/* AArch64 record/replay structures and enumerations.  */

struct aarch64_mem_r
{
  uint64_t len;    /* Record length.  */
  uint64_t addr;   /* Memory address.  */
};

enum aarch64_record_result
{
  AARCH64_RECORD_SUCCESS,
  AARCH64_RECORD_UNSUPPORTED,
  AARCH64_RECORD_UNKNOWN
};

typedef struct insn_decode_record_t
{
  struct gdbarch *gdbarch;
  struct regcache *regcache;
  CORE_ADDR this_addr;                 /* Address of insn to be recorded.  */
  uint32_t aarch64_insn;               /* Insn to be recorded.  */
  uint32_t mem_rec_count;              /* Count of memory records.  */
  uint32_t reg_rec_count;              /* Count of register records.  */
  uint32_t *aarch64_regs;              /* Registers to be recorded.  */
  struct aarch64_mem_r *aarch64_mems;  /* Memory locations to be recorded.  */
} insn_decode_record;

/* Record handler for data processing - register instructions.  */

static unsigned int
aarch64_record_data_proc_reg (insn_decode_record *aarch64_insn_r)
{
  uint8_t reg_rd, insn_bits24_27, insn_bits21_23;
  uint32_t record_buf[4];

  reg_rd = bits (aarch64_insn_r->aarch64_insn, 0, 4);
  insn_bits24_27 = bits (aarch64_insn_r->aarch64_insn, 24, 27);
  insn_bits21_23 = bits (aarch64_insn_r->aarch64_insn, 21, 23);

  if (!bit (aarch64_insn_r->aarch64_insn, 28))
    {
      uint8_t setflags;

      /* Logical (shifted register).  */
      if (insn_bits24_27 == 0x0a)
	setflags = (bits (aarch64_insn_r->aarch64_insn, 29, 30) == 0x03);
      /* Add/subtract.  */
      else if (insn_bits24_27 == 0x0b)
	setflags = bit (aarch64_insn_r->aarch64_insn, 29);
      else
	return AARCH64_RECORD_UNKNOWN;

      record_buf[0] = reg_rd;
      aarch64_insn_r->reg_rec_count = 1;
      if (setflags)
	record_buf[aarch64_insn_r->reg_rec_count++] = AARCH64_CPSR_REGNUM;
    }
  else
    {
      if (insn_bits24_27 == 0x0b)
	{
	  /* Data-processing (3 source).  */
	  record_buf[0] = reg_rd;
	  aarch64_insn_r->reg_rec_count = 1;
	}
      else if (insn_bits24_27 == 0x0a)
	{
	  if (insn_bits21_23 == 0x00)
	    {
	      /* Add/subtract (with carry).  */
	      record_buf[0] = reg_rd;
	      aarch64_insn_r->reg_rec_count = 1;
	      if (bit (aarch64_insn_r->aarch64_insn, 29))
		{
		  record_buf[1] = AARCH64_CPSR_REGNUM;
		  aarch64_insn_r->reg_rec_count = 2;
		}
	    }
	  else if (insn_bits21_23 == 0x02)
	    {
	      /* Conditional compare (register) and conditional compare
		 (immediate) instructions.  */
	      record_buf[0] = AARCH64_CPSR_REGNUM;
	      aarch64_insn_r->reg_rec_count = 1;
	    }
	  else if (insn_bits21_23 == 0x04 || insn_bits21_23 == 0x06)
	    {
	      /* Conditional select.  */
	      /* Data-processing (2 source).  */
	      /* Data-processing (1 source).  */
	      record_buf[0] = reg_rd;
	      aarch64_insn_r->reg_rec_count = 1;
	    }
	  else
	    return AARCH64_RECORD_UNKNOWN;
	}
    }

  REG_ALLOC (aarch64_insn_r->aarch64_regs, aarch64_insn_r->reg_rec_count,
	     record_buf);
  return AARCH64_RECORD_SUCCESS;
}

/* Record handler for data processing - immediate instructions.  */

static unsigned int
aarch64_record_data_proc_imm (insn_decode_record *aarch64_insn_r)
{
  uint8_t reg_rd, insn_bit23, insn_bits24_27, setflags;
  uint32_t record_buf[4];

  reg_rd = bits (aarch64_insn_r->aarch64_insn, 0, 4);
  insn_bit23 = bit (aarch64_insn_r->aarch64_insn, 23);
  insn_bits24_27 = bits (aarch64_insn_r->aarch64_insn, 24, 27);

  if (insn_bits24_27 == 0x00                     /* PC rel addressing.  */
     || insn_bits24_27 == 0x03                   /* Bitfield and Extract.  */
     || (insn_bits24_27 == 0x02 && insn_bit23))  /* Move wide (immediate).  */
    {
      record_buf[0] = reg_rd;
      aarch64_insn_r->reg_rec_count = 1;
    }
  else if (insn_bits24_27 == 0x01)
    {
      /* Add/Subtract (immediate).  */
      setflags = bit (aarch64_insn_r->aarch64_insn, 29);
      record_buf[0] = reg_rd;
      aarch64_insn_r->reg_rec_count = 1;
      if (setflags)
	record_buf[aarch64_insn_r->reg_rec_count++] = AARCH64_CPSR_REGNUM;
    }
  else if (insn_bits24_27 == 0x02 && !insn_bit23)
    {
      /* Logical (immediate).  */
      setflags = bits (aarch64_insn_r->aarch64_insn, 29, 30) == 0x03;
      record_buf[0] = reg_rd;
      aarch64_insn_r->reg_rec_count = 1;
      if (setflags)
	record_buf[aarch64_insn_r->reg_rec_count++] = AARCH64_CPSR_REGNUM;
    }
  else
    return AARCH64_RECORD_UNKNOWN;

  REG_ALLOC (aarch64_insn_r->aarch64_regs, aarch64_insn_r->reg_rec_count,
	     record_buf);
  return AARCH64_RECORD_SUCCESS;
}

/* Record handler for branch, exception generation and system instructions.  */

static unsigned int
aarch64_record_branch_except_sys (insn_decode_record *aarch64_insn_r)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (aarch64_insn_r->gdbarch);
  uint8_t insn_bits24_27, insn_bits28_31, insn_bits22_23;
  uint32_t record_buf[4];

  insn_bits24_27 = bits (aarch64_insn_r->aarch64_insn, 24, 27);
  insn_bits28_31 = bits (aarch64_insn_r->aarch64_insn, 28, 31);
  insn_bits22_23 = bits (aarch64_insn_r->aarch64_insn, 22, 23);

  if (insn_bits28_31 == 0x0d)
    {
      /* Exception generation instructions. */
      if (insn_bits24_27 == 0x04)
	{
	  if (!bits (aarch64_insn_r->aarch64_insn, 2, 4)
	      && !bits (aarch64_insn_r->aarch64_insn, 21, 23)
	      && bits (aarch64_insn_r->aarch64_insn, 0, 1) == 0x01)
	    {
	      ULONGEST svc_number;

	      regcache_raw_read_unsigned (aarch64_insn_r->regcache, 8,
					  &svc_number);
	      return tdep->aarch64_syscall_record (aarch64_insn_r->regcache,
						   svc_number);
	    }
	  else
	    return AARCH64_RECORD_UNSUPPORTED;
	}
      /* System instructions. */
      else if (insn_bits24_27 == 0x05 && insn_bits22_23 == 0x00)
	{
	  uint32_t reg_rt, reg_crn;

	  reg_rt = bits (aarch64_insn_r->aarch64_insn, 0, 4);
	  reg_crn = bits (aarch64_insn_r->aarch64_insn, 12, 15);

	  /* Record rt in case of sysl and mrs instructions.  */
	  if (bit (aarch64_insn_r->aarch64_insn, 21))
	    {
	      record_buf[0] = reg_rt;
	      aarch64_insn_r->reg_rec_count = 1;
	    }
	  /* Record cpsr for hint and msr(immediate) instructions.  */
	  else if (reg_crn == 0x02 || reg_crn == 0x04)
	    {
	      record_buf[0] = AARCH64_CPSR_REGNUM;
	      aarch64_insn_r->reg_rec_count = 1;
	    }
	}
      /* Unconditional branch (register).  */
      else if((insn_bits24_27 & 0x0e) == 0x06)
	{
	  record_buf[aarch64_insn_r->reg_rec_count++] = AARCH64_PC_REGNUM;
	  if (bits (aarch64_insn_r->aarch64_insn, 21, 22) == 0x01)
	    record_buf[aarch64_insn_r->reg_rec_count++] = AARCH64_LR_REGNUM;
	}
      else
	return AARCH64_RECORD_UNKNOWN;
    }
  /* Unconditional branch (immediate).  */
  else if ((insn_bits28_31 & 0x07) == 0x01 && (insn_bits24_27 & 0x0c) == 0x04)
    {
      record_buf[aarch64_insn_r->reg_rec_count++] = AARCH64_PC_REGNUM;
      if (bit (aarch64_insn_r->aarch64_insn, 31))
	record_buf[aarch64_insn_r->reg_rec_count++] = AARCH64_LR_REGNUM;
    }
  else
    /* Compare & branch (immediate), Test & branch (immediate) and
       Conditional branch (immediate).  */
    record_buf[aarch64_insn_r->reg_rec_count++] = AARCH64_PC_REGNUM;

  REG_ALLOC (aarch64_insn_r->aarch64_regs, aarch64_insn_r->reg_rec_count,
	     record_buf);
  return AARCH64_RECORD_SUCCESS;
}

/* Record handler for advanced SIMD load and store instructions.  */

static unsigned int
aarch64_record_asimd_load_store (insn_decode_record *aarch64_insn_r)
{
  CORE_ADDR address;
  uint64_t addr_offset = 0;
  uint32_t record_buf[24];
  uint64_t record_buf_mem[24];
  uint32_t reg_rn, reg_rt;
  uint32_t reg_index = 0, mem_index = 0;
  uint8_t opcode_bits, size_bits;

  reg_rt = bits (aarch64_insn_r->aarch64_insn, 0, 4);
  reg_rn = bits (aarch64_insn_r->aarch64_insn, 5, 9);
  size_bits = bits (aarch64_insn_r->aarch64_insn, 10, 11);
  opcode_bits = bits (aarch64_insn_r->aarch64_insn, 12, 15);
  regcache_raw_read_unsigned (aarch64_insn_r->regcache, reg_rn, &address);

  if (record_debug)
    debug_printf ("Process record: Advanced SIMD load/store\n");

  /* Load/store single structure.  */
  if (bit (aarch64_insn_r->aarch64_insn, 24))
    {
      uint8_t sindex, scale, selem, esize, replicate = 0;
      scale = opcode_bits >> 2;
      selem = ((opcode_bits & 0x02) |
              bit (aarch64_insn_r->aarch64_insn, 21)) + 1;
      switch (scale)
        {
        case 1:
          if (size_bits & 0x01)
            return AARCH64_RECORD_UNKNOWN;
          break;
        case 2:
          if ((size_bits >> 1) & 0x01)
            return AARCH64_RECORD_UNKNOWN;
          if (size_bits & 0x01)
            {
              if (!((opcode_bits >> 1) & 0x01))
                scale = 3;
              else
                return AARCH64_RECORD_UNKNOWN;
            }
          break;
        case 3:
          if (bit (aarch64_insn_r->aarch64_insn, 22) && !(opcode_bits & 0x01))
            {
              scale = size_bits;
              replicate = 1;
              break;
            }
          else
            return AARCH64_RECORD_UNKNOWN;
        default:
          break;
        }
      esize = 8 << scale;
      if (replicate)
        for (sindex = 0; sindex < selem; sindex++)
          {
            record_buf[reg_index++] = reg_rt + AARCH64_V0_REGNUM;
            reg_rt = (reg_rt + 1) % 32;
          }
      else
        {
          for (sindex = 0; sindex < selem; sindex++)
	    {
	      if (bit (aarch64_insn_r->aarch64_insn, 22))
		record_buf[reg_index++] = reg_rt + AARCH64_V0_REGNUM;
	      else
		{
		  record_buf_mem[mem_index++] = esize / 8;
		  record_buf_mem[mem_index++] = address + addr_offset;
		}
	      addr_offset = addr_offset + (esize / 8);
	      reg_rt = (reg_rt + 1) % 32;
	    }
        }
    }
  /* Load/store multiple structure.  */
  else
    {
      uint8_t selem, esize, rpt, elements;
      uint8_t eindex, rindex;

      esize = 8 << size_bits;
      if (bit (aarch64_insn_r->aarch64_insn, 30))
        elements = 128 / esize;
      else
        elements = 64 / esize;

      switch (opcode_bits)
        {
        /*LD/ST4 (4 Registers).  */
        case 0:
          rpt = 1;
          selem = 4;
          break;
        /*LD/ST1 (4 Registers).  */
        case 2:
          rpt = 4;
          selem = 1;
          break;
        /*LD/ST3 (3 Registers).  */
        case 4:
          rpt = 1;
          selem = 3;
          break;
        /*LD/ST1 (3 Registers).  */
        case 6:
          rpt = 3;
          selem = 1;
          break;
        /*LD/ST1 (1 Register).  */
        case 7:
          rpt = 1;
          selem = 1;
          break;
        /*LD/ST2 (2 Registers).  */
        case 8:
          rpt = 1;
          selem = 2;
          break;
        /*LD/ST1 (2 Registers).  */
        case 10:
          rpt = 2;
          selem = 1;
          break;
        default:
          return AARCH64_RECORD_UNSUPPORTED;
          break;
        }
      for (rindex = 0; rindex < rpt; rindex++)
        for (eindex = 0; eindex < elements; eindex++)
          {
            uint8_t reg_tt, sindex;
            reg_tt = (reg_rt + rindex) % 32;
            for (sindex = 0; sindex < selem; sindex++)
              {
                if (bit (aarch64_insn_r->aarch64_insn, 22))
                  record_buf[reg_index++] = reg_tt + AARCH64_V0_REGNUM;
                else
                  {
                    record_buf_mem[mem_index++] = esize / 8;
                    record_buf_mem[mem_index++] = address + addr_offset;
                  }
                addr_offset = addr_offset + (esize / 8);
                reg_tt = (reg_tt + 1) % 32;
              }
          }
    }

  if (bit (aarch64_insn_r->aarch64_insn, 23))
    record_buf[reg_index++] = reg_rn;

  aarch64_insn_r->reg_rec_count = reg_index;
  aarch64_insn_r->mem_rec_count = mem_index / 2;
  MEM_ALLOC (aarch64_insn_r->aarch64_mems, aarch64_insn_r->mem_rec_count,
             record_buf_mem);
  REG_ALLOC (aarch64_insn_r->aarch64_regs, aarch64_insn_r->reg_rec_count,
             record_buf);
  return AARCH64_RECORD_SUCCESS;
}

/* Record handler for load and store instructions.  */

static unsigned int
aarch64_record_load_store (insn_decode_record *aarch64_insn_r)
{
  uint8_t insn_bits24_27, insn_bits28_29, insn_bits10_11;
  uint8_t insn_bit23, insn_bit21;
  uint8_t opc, size_bits, ld_flag, vector_flag;
  uint32_t reg_rn, reg_rt, reg_rt2;
  uint64_t datasize, offset;
  uint32_t record_buf[8];
  uint64_t record_buf_mem[8];
  CORE_ADDR address;

  insn_bits10_11 = bits (aarch64_insn_r->aarch64_insn, 10, 11);
  insn_bits24_27 = bits (aarch64_insn_r->aarch64_insn, 24, 27);
  insn_bits28_29 = bits (aarch64_insn_r->aarch64_insn, 28, 29);
  insn_bit21 = bit (aarch64_insn_r->aarch64_insn, 21);
  insn_bit23 = bit (aarch64_insn_r->aarch64_insn, 23);
  ld_flag = bit (aarch64_insn_r->aarch64_insn, 22);
  vector_flag = bit (aarch64_insn_r->aarch64_insn, 26);
  reg_rt = bits (aarch64_insn_r->aarch64_insn, 0, 4);
  reg_rn = bits (aarch64_insn_r->aarch64_insn, 5, 9);
  reg_rt2 = bits (aarch64_insn_r->aarch64_insn, 10, 14);
  size_bits = bits (aarch64_insn_r->aarch64_insn, 30, 31);

  /* Load/store exclusive.  */
  if (insn_bits24_27 == 0x08 && insn_bits28_29 == 0x00)
    {
      if (record_debug)
	debug_printf ("Process record: load/store exclusive\n");

      if (ld_flag)
	{
	  record_buf[0] = reg_rt;
	  aarch64_insn_r->reg_rec_count = 1;
	  if (insn_bit21)
	    {
	      record_buf[1] = reg_rt2;
	      aarch64_insn_r->reg_rec_count = 2;
	    }
	}
      else
	{
	  if (insn_bit21)
	    datasize = (8 << size_bits) * 2;
	  else
	    datasize = (8 << size_bits);
	  regcache_raw_read_unsigned (aarch64_insn_r->regcache, reg_rn,
				      &address);
	  record_buf_mem[0] = datasize / 8;
	  record_buf_mem[1] = address;
	  aarch64_insn_r->mem_rec_count = 1;
	  if (!insn_bit23)
	    {
	      /* Save register rs.  */
	      record_buf[0] = bits (aarch64_insn_r->aarch64_insn, 16, 20);
	      aarch64_insn_r->reg_rec_count = 1;
	    }
	}
    }
  /* Load register (literal) instructions decoding.  */
  else if ((insn_bits24_27 & 0x0b) == 0x08 && insn_bits28_29 == 0x01)
    {
      if (record_debug)
	debug_printf ("Process record: load register (literal)\n");
      if (vector_flag)
        record_buf[0] = reg_rt + AARCH64_V0_REGNUM;
      else
        record_buf[0] = reg_rt;
      aarch64_insn_r->reg_rec_count = 1;
    }
  /* All types of load/store pair instructions decoding.  */
  else if ((insn_bits24_27 & 0x0a) == 0x08 && insn_bits28_29 == 0x02)
    {
      if (record_debug)
	debug_printf ("Process record: load/store pair\n");

      if (ld_flag)
        {
          if (vector_flag)
            {
              record_buf[0] = reg_rt + AARCH64_V0_REGNUM;
              record_buf[1] = reg_rt2 + AARCH64_V0_REGNUM;
            }
          else
            {
              record_buf[0] = reg_rt;
              record_buf[1] = reg_rt2;
            }
          aarch64_insn_r->reg_rec_count = 2;
        }
      else
        {
          uint16_t imm7_off;
          imm7_off = bits (aarch64_insn_r->aarch64_insn, 15, 21);
          if (!vector_flag)
            size_bits = size_bits >> 1;
          datasize = 8 << (2 + size_bits);
          offset = (imm7_off & 0x40) ? (~imm7_off & 0x007f) + 1 : imm7_off;
          offset = offset << (2 + size_bits);
          regcache_raw_read_unsigned (aarch64_insn_r->regcache, reg_rn,
                                      &address);
          if (!((insn_bits24_27 & 0x0b) == 0x08 && insn_bit23))
            {
              if (imm7_off & 0x40)
                address = address - offset;
              else
                address = address + offset;
            }

          record_buf_mem[0] = datasize / 8;
          record_buf_mem[1] = address;
          record_buf_mem[2] = datasize / 8;
          record_buf_mem[3] = address + (datasize / 8);
          aarch64_insn_r->mem_rec_count = 2;
        }
      if (bit (aarch64_insn_r->aarch64_insn, 23))
        record_buf[aarch64_insn_r->reg_rec_count++] = reg_rn;
    }
  /* Load/store register (unsigned immediate) instructions.  */
  else if ((insn_bits24_27 & 0x0b) == 0x09 && insn_bits28_29 == 0x03)
    {
      opc = bits (aarch64_insn_r->aarch64_insn, 22, 23);
      if (!(opc >> 1))
	{
	  if (opc & 0x01)
	    ld_flag = 0x01;
	  else
	    ld_flag = 0x0;
	}
      else
	{
	  if (size_bits == 0x3 && vector_flag == 0x0 && opc == 0x2)
	    {
	      /* PRFM (immediate) */
	      return AARCH64_RECORD_SUCCESS;
	    }
	  else if (size_bits == 0x2 && vector_flag == 0x0 && opc == 0x2)
	    {
	      /* LDRSW (immediate) */
	      ld_flag = 0x1;
	    }
	  else
	    {
	      if (opc & 0x01)
		ld_flag = 0x01;
	      else
		ld_flag = 0x0;
	    }
	}

      if (record_debug)
	{
	  debug_printf ("Process record: load/store (unsigned immediate):"
			" size %x V %d opc %x\n", size_bits, vector_flag,
			opc);
	}

      if (!ld_flag)
        {
          offset = bits (aarch64_insn_r->aarch64_insn, 10, 21);
          datasize = 8 << size_bits;
          regcache_raw_read_unsigned (aarch64_insn_r->regcache, reg_rn,
                                      &address);
          offset = offset << size_bits;
          address = address + offset;

          record_buf_mem[0] = datasize >> 3;
          record_buf_mem[1] = address;
          aarch64_insn_r->mem_rec_count = 1;
        }
      else
        {
          if (vector_flag)
            record_buf[0] = reg_rt + AARCH64_V0_REGNUM;
          else
            record_buf[0] = reg_rt;
          aarch64_insn_r->reg_rec_count = 1;
        }
    }
  /* Load/store register (register offset) instructions.  */
  else if ((insn_bits24_27 & 0x0b) == 0x08 && insn_bits28_29 == 0x03
	   && insn_bits10_11 == 0x02 && insn_bit21)
    {
      if (record_debug)
	debug_printf ("Process record: load/store (register offset)\n");
      opc = bits (aarch64_insn_r->aarch64_insn, 22, 23);
      if (!(opc >> 1))
        if (opc & 0x01)
          ld_flag = 0x01;
        else
          ld_flag = 0x0;
      else
        if (size_bits != 0x03)
          ld_flag = 0x01;
        else
          return AARCH64_RECORD_UNKNOWN;

      if (!ld_flag)
        {
          ULONGEST reg_rm_val;

          regcache_raw_read_unsigned (aarch64_insn_r->regcache,
                     bits (aarch64_insn_r->aarch64_insn, 16, 20), &reg_rm_val);
          if (bit (aarch64_insn_r->aarch64_insn, 12))
            offset = reg_rm_val << size_bits;
          else
            offset = reg_rm_val;
          datasize = 8 << size_bits;
          regcache_raw_read_unsigned (aarch64_insn_r->regcache, reg_rn,
                                      &address);
          address = address + offset;
          record_buf_mem[0] = datasize >> 3;
          record_buf_mem[1] = address;
          aarch64_insn_r->mem_rec_count = 1;
        }
      else
        {
          if (vector_flag)
            record_buf[0] = reg_rt + AARCH64_V0_REGNUM;
          else
            record_buf[0] = reg_rt;
          aarch64_insn_r->reg_rec_count = 1;
        }
    }
  /* Load/store register (immediate and unprivileged) instructions.  */
  else if ((insn_bits24_27 & 0x0b) == 0x08 && insn_bits28_29 == 0x03
	   && !insn_bit21)
    {
      if (record_debug)
	{
	  debug_printf ("Process record: load/store "
			"(immediate and unprivileged)\n");
	}
      opc = bits (aarch64_insn_r->aarch64_insn, 22, 23);
      if (!(opc >> 1))
        if (opc & 0x01)
          ld_flag = 0x01;
        else
          ld_flag = 0x0;
      else
        if (size_bits != 0x03)
          ld_flag = 0x01;
        else
          return AARCH64_RECORD_UNKNOWN;

      if (!ld_flag)
        {
          uint16_t imm9_off;
          imm9_off = bits (aarch64_insn_r->aarch64_insn, 12, 20);
          offset = (imm9_off & 0x0100) ? (((~imm9_off) & 0x01ff) + 1) : imm9_off;
          datasize = 8 << size_bits;
          regcache_raw_read_unsigned (aarch64_insn_r->regcache, reg_rn,
                                      &address);
          if (insn_bits10_11 != 0x01)
            {
              if (imm9_off & 0x0100)
                address = address - offset;
              else
                address = address + offset;
            }
          record_buf_mem[0] = datasize >> 3;
          record_buf_mem[1] = address;
          aarch64_insn_r->mem_rec_count = 1;
        }
      else
        {
          if (vector_flag)
            record_buf[0] = reg_rt + AARCH64_V0_REGNUM;
          else
            record_buf[0] = reg_rt;
          aarch64_insn_r->reg_rec_count = 1;
        }
      if (insn_bits10_11 == 0x01 || insn_bits10_11 == 0x03)
        record_buf[aarch64_insn_r->reg_rec_count++] = reg_rn;
    }
  /* Advanced SIMD load/store instructions.  */
  else
    return aarch64_record_asimd_load_store (aarch64_insn_r);

  MEM_ALLOC (aarch64_insn_r->aarch64_mems, aarch64_insn_r->mem_rec_count,
             record_buf_mem);
  REG_ALLOC (aarch64_insn_r->aarch64_regs, aarch64_insn_r->reg_rec_count,
             record_buf);
  return AARCH64_RECORD_SUCCESS;
}

/* Record handler for data processing SIMD and floating point instructions.  */

static unsigned int
aarch64_record_data_proc_simd_fp (insn_decode_record *aarch64_insn_r)
{
  uint8_t insn_bit21, opcode, rmode, reg_rd;
  uint8_t insn_bits24_27, insn_bits28_31, insn_bits10_11, insn_bits12_15;
  uint8_t insn_bits11_14;
  uint32_t record_buf[2];

  insn_bits24_27 = bits (aarch64_insn_r->aarch64_insn, 24, 27);
  insn_bits28_31 = bits (aarch64_insn_r->aarch64_insn, 28, 31);
  insn_bits10_11 = bits (aarch64_insn_r->aarch64_insn, 10, 11);
  insn_bits12_15 = bits (aarch64_insn_r->aarch64_insn, 12, 15);
  insn_bits11_14 = bits (aarch64_insn_r->aarch64_insn, 11, 14);
  opcode = bits (aarch64_insn_r->aarch64_insn, 16, 18);
  rmode = bits (aarch64_insn_r->aarch64_insn, 19, 20);
  reg_rd = bits (aarch64_insn_r->aarch64_insn, 0, 4);
  insn_bit21 = bit (aarch64_insn_r->aarch64_insn, 21);

  if (record_debug)
    debug_printf ("Process record: data processing SIMD/FP: ");

  if ((insn_bits28_31 & 0x05) == 0x01 && insn_bits24_27 == 0x0e)
    {
      /* Floating point - fixed point conversion instructions.  */
      if (!insn_bit21)
	{
	  if (record_debug)
	    debug_printf ("FP - fixed point conversion");

	  if ((opcode >> 1) == 0x0 && rmode == 0x03)
	    record_buf[0] = reg_rd;
	  else
	    record_buf[0] = reg_rd + AARCH64_V0_REGNUM;
	}
      /* Floating point - conditional compare instructions.  */
      else if (insn_bits10_11 == 0x01)
	{
	  if (record_debug)
	    debug_printf ("FP - conditional compare");

	  record_buf[0] = AARCH64_CPSR_REGNUM;
	}
      /* Floating point - data processing (2-source) and
         conditional select instructions.  */
      else if (insn_bits10_11 == 0x02 || insn_bits10_11 == 0x03)
	{
	  if (record_debug)
	    debug_printf ("FP - DP (2-source)");

	  record_buf[0] = reg_rd + AARCH64_V0_REGNUM;
	}
      else if (insn_bits10_11 == 0x00)
	{
	  /* Floating point - immediate instructions.  */
	  if ((insn_bits12_15 & 0x01) == 0x01
	      || (insn_bits12_15 & 0x07) == 0x04)
	    {
	      if (record_debug)
		debug_printf ("FP - immediate");
	      record_buf[0] = reg_rd + AARCH64_V0_REGNUM;
	    }
	  /* Floating point - compare instructions.  */
	  else if ((insn_bits12_15 & 0x03) == 0x02)
	    {
	      if (record_debug)
		debug_printf ("FP - immediate");
	      record_buf[0] = AARCH64_CPSR_REGNUM;
	    }
	  /* Floating point - integer conversions instructions.  */
	  else if (insn_bits12_15 == 0x00)
	    {
	      /* Convert float to integer instruction.  */
	      if (!(opcode >> 1) || ((opcode >> 1) == 0x02 && !rmode))
		{
		  if (record_debug)
		    debug_printf ("float to int conversion");

		  record_buf[0] = reg_rd + AARCH64_X0_REGNUM;
		}
	      /* Convert integer to float instruction.  */
	      else if ((opcode >> 1) == 0x01 && !rmode)
		{
		  if (record_debug)
		    debug_printf ("int to float conversion");

		  record_buf[0] = reg_rd + AARCH64_V0_REGNUM;
		}
	      /* Move float to integer instruction.  */
	      else if ((opcode >> 1) == 0x03)
		{
		  if (record_debug)
		    debug_printf ("move float to int");

		  if (!(opcode & 0x01))
		    record_buf[0] = reg_rd + AARCH64_X0_REGNUM;
		  else
		    record_buf[0] = reg_rd + AARCH64_V0_REGNUM;
		}
	      else
		return AARCH64_RECORD_UNKNOWN;
            }
	  else
	    return AARCH64_RECORD_UNKNOWN;
        }
      else
	return AARCH64_RECORD_UNKNOWN;
    }
  else if ((insn_bits28_31 & 0x09) == 0x00 && insn_bits24_27 == 0x0e)
    {
      if (record_debug)
	debug_printf ("SIMD copy");

      /* Advanced SIMD copy instructions.  */
      if (!bits (aarch64_insn_r->aarch64_insn, 21, 23)
	  && !bit (aarch64_insn_r->aarch64_insn, 15)
	  && bit (aarch64_insn_r->aarch64_insn, 10))
	{
	  if (insn_bits11_14 == 0x05 || insn_bits11_14 == 0x07)
	    record_buf[0] = reg_rd + AARCH64_X0_REGNUM;
	  else
	    record_buf[0] = reg_rd + AARCH64_V0_REGNUM;
	}
      else
	record_buf[0] = reg_rd + AARCH64_V0_REGNUM;
    }
  /* All remaining floating point or advanced SIMD instructions.  */
  else
    {
      if (record_debug)
	debug_printf ("all remain");

      record_buf[0] = reg_rd + AARCH64_V0_REGNUM;
    }

  if (record_debug)
    debug_printf ("\n");

  aarch64_insn_r->reg_rec_count++;
  gdb_assert (aarch64_insn_r->reg_rec_count == 1);
  REG_ALLOC (aarch64_insn_r->aarch64_regs, aarch64_insn_r->reg_rec_count,
	     record_buf);
  return AARCH64_RECORD_SUCCESS;
}

/* Decodes insns type and invokes its record handler.  */

static unsigned int
aarch64_record_decode_insn_handler (insn_decode_record *aarch64_insn_r)
{
  uint32_t ins_bit25, ins_bit26, ins_bit27, ins_bit28;

  ins_bit25 = bit (aarch64_insn_r->aarch64_insn, 25);
  ins_bit26 = bit (aarch64_insn_r->aarch64_insn, 26);
  ins_bit27 = bit (aarch64_insn_r->aarch64_insn, 27);
  ins_bit28 = bit (aarch64_insn_r->aarch64_insn, 28);

  /* Data processing - immediate instructions.  */
  if (!ins_bit26 && !ins_bit27 && ins_bit28)
    return aarch64_record_data_proc_imm (aarch64_insn_r);

  /* Branch, exception generation and system instructions.  */
  if (ins_bit26 && !ins_bit27 && ins_bit28)
    return aarch64_record_branch_except_sys (aarch64_insn_r);

  /* Load and store instructions.  */
  if (!ins_bit25 && ins_bit27)
    return aarch64_record_load_store (aarch64_insn_r);

  /* Data processing - register instructions.  */
  if (ins_bit25 && !ins_bit26 && ins_bit27)
    return aarch64_record_data_proc_reg (aarch64_insn_r);

  /* Data processing - SIMD and floating point instructions.  */
  if (ins_bit25 && ins_bit26 && ins_bit27)
    return aarch64_record_data_proc_simd_fp (aarch64_insn_r);

  return AARCH64_RECORD_UNSUPPORTED;
}

/* Cleans up local record registers and memory allocations.  */

static void
deallocate_reg_mem (insn_decode_record *record)
{
  xfree (record->aarch64_regs);
  xfree (record->aarch64_mems);
}

#if GDB_SELF_TEST
namespace selftests {

static void
aarch64_process_record_test (void)
{
  struct gdbarch_info info;
  uint32_t ret;

  gdbarch_info_init (&info);
  info.bfd_arch_info = bfd_scan_arch ("aarch64");

  struct gdbarch *gdbarch = gdbarch_find_by_info (info);
  SELF_CHECK (gdbarch != NULL);

  insn_decode_record aarch64_record;

  memset (&aarch64_record, 0, sizeof (insn_decode_record));
  aarch64_record.regcache = NULL;
  aarch64_record.this_addr = 0;
  aarch64_record.gdbarch = gdbarch;

  /* 20 00 80 f9	prfm	pldl1keep, [x1] */
  aarch64_record.aarch64_insn = 0xf9800020;
  ret = aarch64_record_decode_insn_handler (&aarch64_record);
  SELF_CHECK (ret == AARCH64_RECORD_SUCCESS);
  SELF_CHECK (aarch64_record.reg_rec_count == 0);
  SELF_CHECK (aarch64_record.mem_rec_count == 0);

  deallocate_reg_mem (&aarch64_record);
}

} // namespace selftests
#endif /* GDB_SELF_TEST */

/* Parse the current instruction and record the values of the registers and
   memory that will be changed in current instruction to record_arch_list
   return -1 if something is wrong.  */

int
aarch64_process_record (struct gdbarch *gdbarch, struct regcache *regcache,
			CORE_ADDR insn_addr)
{
  uint32_t rec_no = 0;
  uint8_t insn_size = 4;
  uint32_t ret = 0;
  gdb_byte buf[insn_size];
  insn_decode_record aarch64_record;

  memset (&buf[0], 0, insn_size);
  memset (&aarch64_record, 0, sizeof (insn_decode_record));
  target_read_memory (insn_addr, &buf[0], insn_size);
  aarch64_record.aarch64_insn
    = (uint32_t) extract_unsigned_integer (&buf[0],
					   insn_size,
					   gdbarch_byte_order (gdbarch));
  aarch64_record.regcache = regcache;
  aarch64_record.this_addr = insn_addr;
  aarch64_record.gdbarch = gdbarch;

  ret = aarch64_record_decode_insn_handler (&aarch64_record);
  if (ret == AARCH64_RECORD_UNSUPPORTED)
    {
      printf_unfiltered (_("Process record does not support instruction "
			   "0x%0x at address %s.\n"),
			 aarch64_record.aarch64_insn,
			 paddress (gdbarch, insn_addr));
      ret = -1;
    }

  if (0 == ret)
    {
      /* Record registers.  */
      record_full_arch_list_add_reg (aarch64_record.regcache,
				     AARCH64_PC_REGNUM);
      /* Always record register CPSR.  */
      record_full_arch_list_add_reg (aarch64_record.regcache,
				     AARCH64_CPSR_REGNUM);
      if (aarch64_record.aarch64_regs)
	for (rec_no = 0; rec_no < aarch64_record.reg_rec_count; rec_no++)
	  if (record_full_arch_list_add_reg (aarch64_record.regcache,
					     aarch64_record.aarch64_regs[rec_no]))
	    ret = -1;

      /* Record memories.  */
      if (aarch64_record.aarch64_mems)
	for (rec_no = 0; rec_no < aarch64_record.mem_rec_count; rec_no++)
	  if (record_full_arch_list_add_mem
	      ((CORE_ADDR)aarch64_record.aarch64_mems[rec_no].addr,
	       aarch64_record.aarch64_mems[rec_no].len))
	    ret = -1;

      if (record_full_arch_list_add_end ())
	ret = -1;
    }

  deallocate_reg_mem (&aarch64_record);
  return ret;
}
