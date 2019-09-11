/* SystemTap probe support for GDB.

   Copyright (C) 2012-2019 Free Software Foundation, Inc.

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
#include "stap-probe.h"
#include "probe.h"
#include "common/vec.h"
#include "ui-out.h"
#include "objfiles.h"
#include "arch-utils.h"
#include "command.h"
#include "gdbcmd.h"
#include "filenames.h"
#include "value.h"
#include "ax.h"
#include "ax-gdb.h"
#include "complaints.h"
#include "cli/cli-utils.h"
#include "linespec.h"
#include "user-regs.h"
#include "parser-defs.h"
#include "language.h"
#include "elf-bfd.h"

#include <ctype.h>

/* The name of the SystemTap section where we will find information about
   the probes.  */

#define STAP_BASE_SECTION_NAME ".stapsdt.base"

/* Should we display debug information for the probe's argument expression
   parsing?  */

static unsigned int stap_expression_debug = 0;

/* The various possibilities of bitness defined for a probe's argument.

   The relationship is:

   - STAP_ARG_BITNESS_UNDEFINED:  The user hasn't specified the bitness.
   - STAP_ARG_BITNESS_8BIT_UNSIGNED:  argument string starts with `1@'.
   - STAP_ARG_BITNESS_8BIT_SIGNED:  argument string starts with `-1@'.
   - STAP_ARG_BITNESS_16BIT_UNSIGNED:  argument string starts with `2@'.
   - STAP_ARG_BITNESS_16BIT_SIGNED:  argument string starts with `-2@'.
   - STAP_ARG_BITNESS_32BIT_UNSIGNED:  argument string starts with `4@'.
   - STAP_ARG_BITNESS_32BIT_SIGNED:  argument string starts with `-4@'.
   - STAP_ARG_BITNESS_64BIT_UNSIGNED:  argument string starts with `8@'.
   - STAP_ARG_BITNESS_64BIT_SIGNED:  argument string starts with `-8@'.  */

enum stap_arg_bitness
{
  STAP_ARG_BITNESS_UNDEFINED,
  STAP_ARG_BITNESS_8BIT_UNSIGNED,
  STAP_ARG_BITNESS_8BIT_SIGNED,
  STAP_ARG_BITNESS_16BIT_UNSIGNED,
  STAP_ARG_BITNESS_16BIT_SIGNED,
  STAP_ARG_BITNESS_32BIT_UNSIGNED,
  STAP_ARG_BITNESS_32BIT_SIGNED,
  STAP_ARG_BITNESS_64BIT_UNSIGNED,
  STAP_ARG_BITNESS_64BIT_SIGNED,
};

/* The following structure represents a single argument for the probe.  */

struct stap_probe_arg
{
  /* Constructor for stap_probe_arg.  */
  stap_probe_arg (enum stap_arg_bitness bitness_, struct type *atype_,
		  expression_up &&aexpr_)
  : bitness (bitness_), atype (atype_), aexpr (std::move (aexpr_))
  {}

  /* The bitness of this argument.  */
  enum stap_arg_bitness bitness;

  /* The corresponding `struct type *' to the bitness.  */
  struct type *atype;

  /* The argument converted to an internal GDB expression.  */
  expression_up aexpr;
};

/* Class that implements the static probe methods for "stap" probes.  */

class stap_static_probe_ops : public static_probe_ops
{
public:
  /* See probe.h.  */
  bool is_linespec (const char **linespecp) const override;

  /* See probe.h.  */
  void get_probes (std::vector<probe *> *probesp,
		   struct objfile *objfile) const override;

  /* See probe.h.  */
  const char *type_name () const override;

  /* See probe.h.  */
  std::vector<struct info_probe_column> gen_info_probes_table_header
    () const override;
};

/* SystemTap static_probe_ops.  */

const stap_static_probe_ops stap_static_probe_ops {};

class stap_probe : public probe
{
public:
  /* Constructor for stap_probe.  */
  stap_probe (std::string &&name_, std::string &&provider_, CORE_ADDR address_,
	      struct gdbarch *arch_, CORE_ADDR sem_addr, const char *args_text)
    : probe (std::move (name_), std::move (provider_), address_, arch_),
      m_sem_addr (sem_addr),
      m_have_parsed_args (false), m_unparsed_args_text (args_text)
  {}

  /* See probe.h.  */
  CORE_ADDR get_relocated_address (struct objfile *objfile) override;

  /* See probe.h.  */
  unsigned get_argument_count (struct frame_info *frame) override;

  /* See probe.h.  */
  bool can_evaluate_arguments () const override;

  /* See probe.h.  */
  struct value *evaluate_argument (unsigned n,
				   struct frame_info *frame) override;

  /* See probe.h.  */
  void compile_to_ax (struct agent_expr *aexpr,
		      struct axs_value *axs_value,
		      unsigned n) override;

  /* See probe.h.  */
  void set_semaphore (struct objfile *objfile,
		      struct gdbarch *gdbarch) override;

  /* See probe.h.  */
  void clear_semaphore (struct objfile *objfile,
			struct gdbarch *gdbarch) override;

  /* See probe.h.  */
  const static_probe_ops *get_static_ops () const override;

  /* See probe.h.  */
  std::vector<const char *> gen_info_probes_table_values () const override;

  /* Return argument N of probe.

     If the probe's arguments have not been parsed yet, parse them.  If
     there are no arguments, throw an exception (error).  Otherwise,
     return the requested argument.  */
  struct stap_probe_arg *get_arg_by_number (unsigned n,
					    struct gdbarch *gdbarch)
  {
    if (!m_have_parsed_args)
      this->parse_arguments (gdbarch);

    gdb_assert (m_have_parsed_args);
    if (m_parsed_args.empty ())
      internal_error (__FILE__, __LINE__,
		      _("Probe '%s' apparently does not have arguments, but \n"
			"GDB is requesting its argument number %u anyway.  "
			"This should not happen.  Please report this bug."),
		      this->get_name ().c_str (), n);

    if (n > m_parsed_args.size ())
      internal_error (__FILE__, __LINE__,
		      _("Probe '%s' has %d arguments, but GDB is requesting\n"
			"argument %u.  This should not happen.  Please\n"
			"report this bug."),
		      this->get_name ().c_str (),
		      (int) m_parsed_args.size (), n);

    return &m_parsed_args[n];
  }

  /* Function which parses an argument string from the probe,
     correctly splitting the arguments and storing their information
     in properly ways.

     Consider the following argument string (x86 syntax):

     `4@%eax 4@$10'

     We have two arguments, `%eax' and `$10', both with 32-bit
     unsigned bitness.  This function basically handles them, properly
     filling some structures with this information.  */
  void parse_arguments (struct gdbarch *gdbarch);

private:
  /* If the probe has a semaphore associated, then this is the value of
     it, relative to SECT_OFF_DATA.  */
  CORE_ADDR m_sem_addr;

  /* True if the arguments have been parsed.  */
  bool m_have_parsed_args;

  /* The text version of the probe's arguments, unparsed.  */
  const char *m_unparsed_args_text;

  /* Information about each argument.  This is an array of `stap_probe_arg',
     with each entry representing one argument.  This is only valid if
     M_ARGS_PARSED is true.  */
  std::vector<struct stap_probe_arg> m_parsed_args;
};

/* When parsing the arguments, we have to establish different precedences
   for the various kinds of asm operators.  This enumeration represents those
   precedences.

   This logic behind this is available at
   <http://sourceware.org/binutils/docs/as/Infix-Ops.html#Infix-Ops>, or using
   the command "info '(as)Infix Ops'".  */

enum stap_operand_prec
{
  /* Lowest precedence, used for non-recognized operands or for the beginning
     of the parsing process.  */
  STAP_OPERAND_PREC_NONE = 0,

  /* Precedence of logical OR.  */
  STAP_OPERAND_PREC_LOGICAL_OR,

  /* Precedence of logical AND.  */
  STAP_OPERAND_PREC_LOGICAL_AND,

  /* Precedence of additive (plus, minus) and comparative (equal, less,
     greater-than, etc) operands.  */
  STAP_OPERAND_PREC_ADD_CMP,

  /* Precedence of bitwise operands (bitwise OR, XOR, bitwise AND,
     logical NOT).  */
  STAP_OPERAND_PREC_BITWISE,

  /* Precedence of multiplicative operands (multiplication, division,
     remainder, left shift and right shift).  */
  STAP_OPERAND_PREC_MUL
};

static void stap_parse_argument_1 (struct stap_parse_info *p, int has_lhs,
				   enum stap_operand_prec prec);

static void stap_parse_argument_conditionally (struct stap_parse_info *p);

/* Returns 1 if *S is an operator, zero otherwise.  */

static int stap_is_operator (const char *op);

static void
show_stapexpressiondebug (struct ui_file *file, int from_tty,
			  struct cmd_list_element *c, const char *value)
{
  fprintf_filtered (file, _("SystemTap Probe expression debugging is %s.\n"),
		    value);
}

/* Returns the operator precedence level of OP, or STAP_OPERAND_PREC_NONE
   if the operator code was not recognized.  */

static enum stap_operand_prec
stap_get_operator_prec (enum exp_opcode op)
{
  switch (op)
    {
    case BINOP_LOGICAL_OR:
      return STAP_OPERAND_PREC_LOGICAL_OR;

    case BINOP_LOGICAL_AND:
      return STAP_OPERAND_PREC_LOGICAL_AND;

    case BINOP_ADD:
    case BINOP_SUB:
    case BINOP_EQUAL:
    case BINOP_NOTEQUAL:
    case BINOP_LESS:
    case BINOP_LEQ:
    case BINOP_GTR:
    case BINOP_GEQ:
      return STAP_OPERAND_PREC_ADD_CMP;

    case BINOP_BITWISE_IOR:
    case BINOP_BITWISE_AND:
    case BINOP_BITWISE_XOR:
    case UNOP_LOGICAL_NOT:
      return STAP_OPERAND_PREC_BITWISE;

    case BINOP_MUL:
    case BINOP_DIV:
    case BINOP_REM:
    case BINOP_LSH:
    case BINOP_RSH:
      return STAP_OPERAND_PREC_MUL;

    default:
      return STAP_OPERAND_PREC_NONE;
    }
}

/* Given S, read the operator in it and fills the OP pointer with its code.
   Return 1 on success, zero if the operator was not recognized.  */

static enum exp_opcode
stap_get_opcode (const char **s)
{
  const char c = **s;
  enum exp_opcode op;

  *s += 1;

  switch (c)
    {
    case '*':
      op = BINOP_MUL;
      break;

    case '/':
      op = BINOP_DIV;
      break;

    case '%':
      op = BINOP_REM;
    break;

    case '<':
      op = BINOP_LESS;
      if (**s == '<')
	{
	  *s += 1;
	  op = BINOP_LSH;
	}
      else if (**s == '=')
	{
	  *s += 1;
	  op = BINOP_LEQ;
	}
      else if (**s == '>')
	{
	  *s += 1;
	  op = BINOP_NOTEQUAL;
	}
    break;

    case '>':
      op = BINOP_GTR;
      if (**s == '>')
	{
	  *s += 1;
	  op = BINOP_RSH;
	}
      else if (**s == '=')
	{
	  *s += 1;
	  op = BINOP_GEQ;
	}
    break;

    case '|':
      op = BINOP_BITWISE_IOR;
      if (**s == '|')
	{
	  *s += 1;
	  op = BINOP_LOGICAL_OR;
	}
    break;

    case '&':
      op = BINOP_BITWISE_AND;
      if (**s == '&')
	{
	  *s += 1;
	  op = BINOP_LOGICAL_AND;
	}
    break;

    case '^':
      op = BINOP_BITWISE_XOR;
      break;

    case '!':
      op = UNOP_LOGICAL_NOT;
      break;

    case '+':
      op = BINOP_ADD;
      break;

    case '-':
      op = BINOP_SUB;
      break;

    case '=':
      gdb_assert (**s == '=');
      op = BINOP_EQUAL;
      break;

    default:
      error (_("Invalid opcode in expression `%s' for SystemTap"
	       "probe"), *s);
    }

  return op;
}

/* Given the bitness of the argument, represented by B, return the
   corresponding `struct type *'.  */

static struct type *
stap_get_expected_argument_type (struct gdbarch *gdbarch,
				 enum stap_arg_bitness b,
				 const char *probe_name)
{
  switch (b)
    {
    case STAP_ARG_BITNESS_UNDEFINED:
      if (gdbarch_addr_bit (gdbarch) == 32)
	return builtin_type (gdbarch)->builtin_uint32;
      else
	return builtin_type (gdbarch)->builtin_uint64;

    case STAP_ARG_BITNESS_8BIT_UNSIGNED:
      return builtin_type (gdbarch)->builtin_uint8;

    case STAP_ARG_BITNESS_8BIT_SIGNED:
      return builtin_type (gdbarch)->builtin_int8;

    case STAP_ARG_BITNESS_16BIT_UNSIGNED:
      return builtin_type (gdbarch)->builtin_uint16;

    case STAP_ARG_BITNESS_16BIT_SIGNED:
      return builtin_type (gdbarch)->builtin_int16;

    case STAP_ARG_BITNESS_32BIT_SIGNED:
      return builtin_type (gdbarch)->builtin_int32;

    case STAP_ARG_BITNESS_32BIT_UNSIGNED:
      return builtin_type (gdbarch)->builtin_uint32;

    case STAP_ARG_BITNESS_64BIT_SIGNED:
      return builtin_type (gdbarch)->builtin_int64;

    case STAP_ARG_BITNESS_64BIT_UNSIGNED:
      return builtin_type (gdbarch)->builtin_uint64;

    default:
      error (_("Undefined bitness for probe '%s'."), probe_name);
      break;
    }
}

/* Helper function to check for a generic list of prefixes.  GDBARCH
   is the current gdbarch being used.  S is the expression being
   analyzed.  If R is not NULL, it will be used to return the found
   prefix.  PREFIXES is the list of expected prefixes.

   This function does a case-insensitive match.

   Return 1 if any prefix has been found, zero otherwise.  */

static int
stap_is_generic_prefix (struct gdbarch *gdbarch, const char *s,
			const char **r, const char *const *prefixes)
{
  const char *const *p;

  if (prefixes == NULL)
    {
      if (r != NULL)
	*r = "";

      return 1;
    }

  for (p = prefixes; *p != NULL; ++p)
    if (strncasecmp (s, *p, strlen (*p)) == 0)
      {
	if (r != NULL)
	  *r = *p;

	return 1;
      }

  return 0;
}

/* Return 1 if S points to a register prefix, zero otherwise.  For a
   description of the arguments, look at stap_is_generic_prefix.  */

static int
stap_is_register_prefix (struct gdbarch *gdbarch, const char *s,
			 const char **r)
{
  const char *const *t = gdbarch_stap_register_prefixes (gdbarch);

  return stap_is_generic_prefix (gdbarch, s, r, t);
}

/* Return 1 if S points to a register indirection prefix, zero
   otherwise.  For a description of the arguments, look at
   stap_is_generic_prefix.  */

static int
stap_is_register_indirection_prefix (struct gdbarch *gdbarch, const char *s,
				     const char **r)
{
  const char *const *t = gdbarch_stap_register_indirection_prefixes (gdbarch);

  return stap_is_generic_prefix (gdbarch, s, r, t);
}

/* Return 1 if S points to an integer prefix, zero otherwise.  For a
   description of the arguments, look at stap_is_generic_prefix.

   This function takes care of analyzing whether we are dealing with
   an expected integer prefix, or, if there is no integer prefix to be
   expected, whether we are dealing with a digit.  It does a
   case-insensitive match.  */

static int
stap_is_integer_prefix (struct gdbarch *gdbarch, const char *s,
			const char **r)
{
  const char *const *t = gdbarch_stap_integer_prefixes (gdbarch);
  const char *const *p;

  if (t == NULL)
    {
      /* A NULL value here means that integers do not have a prefix.
	 We just check for a digit then.  */
      if (r != NULL)
	*r = "";

      return isdigit (*s);
    }

  for (p = t; *p != NULL; ++p)
    {
      size_t len = strlen (*p);

      if ((len == 0 && isdigit (*s))
	  || (len > 0 && strncasecmp (s, *p, len) == 0))
	{
	  /* Integers may or may not have a prefix.  The "len == 0"
	     check covers the case when integers do not have a prefix
	     (therefore, we just check if we have a digit).  The call
	     to "strncasecmp" covers the case when they have a
	     prefix.  */
	  if (r != NULL)
	    *r = *p;

	  return 1;
	}
    }

  return 0;
}

/* Helper function to check for a generic list of suffixes.  If we are
   not expecting any suffixes, then it just returns 1.  If we are
   expecting at least one suffix, then it returns 1 if a suffix has
   been found, zero otherwise.  GDBARCH is the current gdbarch being
   used.  S is the expression being analyzed.  If R is not NULL, it
   will be used to return the found suffix.  SUFFIXES is the list of
   expected suffixes.  This function does a case-insensitive
   match.  */

static int
stap_generic_check_suffix (struct gdbarch *gdbarch, const char *s,
			   const char **r, const char *const *suffixes)
{
  const char *const *p;
  int found = 0;

  if (suffixes == NULL)
    {
      if (r != NULL)
	*r = "";

      return 1;
    }

  for (p = suffixes; *p != NULL; ++p)
    if (strncasecmp (s, *p, strlen (*p)) == 0)
      {
	if (r != NULL)
	  *r = *p;

	found = 1;
	break;
      }

  return found;
}

/* Return 1 if S points to an integer suffix, zero otherwise.  For a
   description of the arguments, look at
   stap_generic_check_suffix.  */

static int
stap_check_integer_suffix (struct gdbarch *gdbarch, const char *s,
			   const char **r)
{
  const char *const *p = gdbarch_stap_integer_suffixes (gdbarch);

  return stap_generic_check_suffix (gdbarch, s, r, p);
}

/* Return 1 if S points to a register suffix, zero otherwise.  For a
   description of the arguments, look at
   stap_generic_check_suffix.  */

static int
stap_check_register_suffix (struct gdbarch *gdbarch, const char *s,
			    const char **r)
{
  const char *const *p = gdbarch_stap_register_suffixes (gdbarch);

  return stap_generic_check_suffix (gdbarch, s, r, p);
}

/* Return 1 if S points to a register indirection suffix, zero
   otherwise.  For a description of the arguments, look at
   stap_generic_check_suffix.  */

static int
stap_check_register_indirection_suffix (struct gdbarch *gdbarch, const char *s,
					const char **r)
{
  const char *const *p = gdbarch_stap_register_indirection_suffixes (gdbarch);

  return stap_generic_check_suffix (gdbarch, s, r, p);
}

/* Function responsible for parsing a register operand according to
   SystemTap parlance.  Assuming:

   RP  = register prefix
   RS  = register suffix
   RIP = register indirection prefix
   RIS = register indirection suffix
   
   Then a register operand can be:
   
   [RIP] [RP] REGISTER [RS] [RIS]

   This function takes care of a register's indirection, displacement and
   direct access.  It also takes into consideration the fact that some
   registers are named differently inside and outside GDB, e.g., PPC's
   general-purpose registers are represented by integers in the assembly
   language (e.g., `15' is the 15th general-purpose register), but inside
   GDB they have a prefix (the letter `r') appended.  */

static void
stap_parse_register_operand (struct stap_parse_info *p)
{
  /* Simple flag to indicate whether we have seen a minus signal before
     certain number.  */
  int got_minus = 0;
  /* Flags to indicate whether this register access is being displaced and/or
     indirected.  */
  int disp_p = 0, indirect_p = 0;
  struct gdbarch *gdbarch = p->gdbarch;
  /* Needed to generate the register name as a part of an expression.  */
  struct stoken str;
  /* Variables used to extract the register name from the probe's
     argument.  */
  const char *start;
  const char *gdb_reg_prefix = gdbarch_stap_gdb_register_prefix (gdbarch);
  const char *gdb_reg_suffix = gdbarch_stap_gdb_register_suffix (gdbarch);
  const char *reg_prefix;
  const char *reg_ind_prefix;
  const char *reg_suffix;
  const char *reg_ind_suffix;

  /* Checking for a displacement argument.  */
  if (*p->arg == '+')
    {
      /* If it's a plus sign, we don't need to do anything, just advance the
	 pointer.  */
      ++p->arg;
    }

  if (*p->arg == '-')
    {
      got_minus = 1;
      ++p->arg;
    }

  if (isdigit (*p->arg))
    {
      /* The value of the displacement.  */
      long displacement;
      char *endp;

      disp_p = 1;
      displacement = strtol (p->arg, &endp, 10);
      p->arg = endp;

      /* Generating the expression for the displacement.  */
      write_exp_elt_opcode (&p->pstate, OP_LONG);
      write_exp_elt_type (&p->pstate, builtin_type (gdbarch)->builtin_long);
      write_exp_elt_longcst (&p->pstate, displacement);
      write_exp_elt_opcode (&p->pstate, OP_LONG);
      if (got_minus)
	write_exp_elt_opcode (&p->pstate, UNOP_NEG);
    }

  /* Getting rid of register indirection prefix.  */
  if (stap_is_register_indirection_prefix (gdbarch, p->arg, &reg_ind_prefix))
    {
      indirect_p = 1;
      p->arg += strlen (reg_ind_prefix);
    }

  if (disp_p && !indirect_p)
    error (_("Invalid register displacement syntax on expression `%s'."),
	   p->saved_arg);

  /* Getting rid of register prefix.  */
  if (stap_is_register_prefix (gdbarch, p->arg, &reg_prefix))
    p->arg += strlen (reg_prefix);

  /* Now we should have only the register name.  Let's extract it and get
     the associated number.  */
  start = p->arg;

  /* We assume the register name is composed by letters and numbers.  */
  while (isalnum (*p->arg))
    ++p->arg;

  std::string regname (start, p->arg - start);

  /* We only add the GDB's register prefix/suffix if we are dealing with
     a numeric register.  */
  if (isdigit (*start))
    {
      if (gdb_reg_prefix != NULL)
	regname = gdb_reg_prefix + regname;

      if (gdb_reg_suffix != NULL)
	regname += gdb_reg_suffix;
    }

  int regnum = user_reg_map_name_to_regnum (gdbarch, regname.c_str (),
					    regname.size ());

  /* Is this a valid register name?  */
  if (regnum == -1)
    error (_("Invalid register name `%s' on expression `%s'."),
	   regname.c_str (), p->saved_arg);

  /* Check if there's any special treatment that the arch-specific
     code would like to perform on the register name.  */
  if (gdbarch_stap_adjust_register_p (gdbarch))
    {
      std::string oldregname = regname;

      gdbarch_stap_adjust_register (gdbarch, p, regname, regnum);

      if (regname != oldregname)
	{
	  /* This is just a check we perform to make sure that the
	     arch-dependent code has provided us with a valid
	     register name.  */
	  regnum = user_reg_map_name_to_regnum (gdbarch, regname.c_str (),
						regname.size ());

	  if (regnum == -1)
	    internal_error (__FILE__, __LINE__,
			    _("Invalid register name '%s' after replacing it"
			      " (previous name was '%s')"),
			    regname.c_str (), oldregname.c_str ());
	}
    }

  write_exp_elt_opcode (&p->pstate, OP_REGISTER);
  str.ptr = regname.c_str ();
  str.length = regname.size ();
  write_exp_string (&p->pstate, str);
  write_exp_elt_opcode (&p->pstate, OP_REGISTER);

  if (indirect_p)
    {
      if (disp_p)
	write_exp_elt_opcode (&p->pstate, BINOP_ADD);

      /* Casting to the expected type.  */
      write_exp_elt_opcode (&p->pstate, UNOP_CAST);
      write_exp_elt_type (&p->pstate, lookup_pointer_type (p->arg_type));
      write_exp_elt_opcode (&p->pstate, UNOP_CAST);

      write_exp_elt_opcode (&p->pstate, UNOP_IND);
    }

  /* Getting rid of the register name suffix.  */
  if (stap_check_register_suffix (gdbarch, p->arg, &reg_suffix))
    p->arg += strlen (reg_suffix);
  else
    error (_("Missing register name suffix on expression `%s'."),
	   p->saved_arg);

  /* Getting rid of the register indirection suffix.  */
  if (indirect_p)
    {
      if (stap_check_register_indirection_suffix (gdbarch, p->arg,
						  &reg_ind_suffix))
	p->arg += strlen (reg_ind_suffix);
      else
	error (_("Missing indirection suffix on expression `%s'."),
	       p->saved_arg);
    }
}

/* This function is responsible for parsing a single operand.

   A single operand can be:

      - an unary operation (e.g., `-5', `~2', or even with subexpressions
        like `-(2 + 1)')
      - a register displacement, which will be treated as a register
        operand (e.g., `-4(%eax)' on x86)
      - a numeric constant, or
      - a register operand (see function `stap_parse_register_operand')

   The function also calls special-handling functions to deal with
   unrecognized operands, allowing arch-specific parsers to be
   created.  */

static void
stap_parse_single_operand (struct stap_parse_info *p)
{
  struct gdbarch *gdbarch = p->gdbarch;
  const char *int_prefix = NULL;

  /* We first try to parse this token as a "special token".  */
  if (gdbarch_stap_parse_special_token_p (gdbarch))
    if (gdbarch_stap_parse_special_token (gdbarch, p) != 0)
      {
	/* If the return value of the above function is not zero,
	   it means it successfully parsed the special token.

	   If it is NULL, we try to parse it using our method.  */
	return;
      }

  if (*p->arg == '-' || *p->arg == '~' || *p->arg == '+')
    {
      char c = *p->arg;
      /* We use this variable to do a lookahead.  */
      const char *tmp = p->arg;
      int has_digit = 0;

      /* Skipping signal.  */
      ++tmp;

      /* This is an unary operation.  Here is a list of allowed tokens
	 here:

	 - numeric literal;
	 - number (from register displacement)
	 - subexpression (beginning with `(')

	 We handle the register displacement here, and the other cases
	 recursively.  */
      if (p->inside_paren_p)
	tmp = skip_spaces (tmp);

      while (isdigit (*tmp))
	{
	  /* We skip the digit here because we are only interested in
	     knowing what kind of unary operation this is.  The digit
	     will be handled by one of the functions that will be
	     called below ('stap_parse_argument_conditionally' or
	     'stap_parse_register_operand').  */
	  ++tmp;
	  has_digit = 1;
	}

      if (has_digit && stap_is_register_indirection_prefix (gdbarch, tmp,
							    NULL))
	{
	  /* If we are here, it means it is a displacement.  The only
	     operations allowed here are `-' and `+'.  */
	  if (c == '~')
	    error (_("Invalid operator `%c' for register displacement "
		     "on expression `%s'."), c, p->saved_arg);

	  stap_parse_register_operand (p);
	}
      else
	{
	  /* This is not a displacement.  We skip the operator, and
	     deal with it when the recursion returns.  */
	  ++p->arg;
	  stap_parse_argument_conditionally (p);
	  if (c == '-')
	    write_exp_elt_opcode (&p->pstate, UNOP_NEG);
	  else if (c == '~')
	    write_exp_elt_opcode (&p->pstate, UNOP_COMPLEMENT);
	}
    }
  else if (isdigit (*p->arg))
    {
      /* A temporary variable, needed for lookahead.  */
      const char *tmp = p->arg;
      char *endp;
      long number;

      /* We can be dealing with a numeric constant, or with a register
	 displacement.  */
      number = strtol (tmp, &endp, 10);
      tmp = endp;

      if (p->inside_paren_p)
	tmp = skip_spaces (tmp);

      /* If "stap_is_integer_prefix" returns true, it means we can
	 accept integers without a prefix here.  But we also need to
	 check whether the next token (i.e., "tmp") is not a register
	 indirection prefix.  */
      if (stap_is_integer_prefix (gdbarch, p->arg, NULL)
	  && !stap_is_register_indirection_prefix (gdbarch, tmp, NULL))
	{
	  const char *int_suffix;

	  /* We are dealing with a numeric constant.  */
	  write_exp_elt_opcode (&p->pstate, OP_LONG);
	  write_exp_elt_type (&p->pstate,
			      builtin_type (gdbarch)->builtin_long);
	  write_exp_elt_longcst (&p->pstate, number);
	  write_exp_elt_opcode (&p->pstate, OP_LONG);

	  p->arg = tmp;

	  if (stap_check_integer_suffix (gdbarch, p->arg, &int_suffix))
	    p->arg += strlen (int_suffix);
	  else
	    error (_("Invalid constant suffix on expression `%s'."),
		   p->saved_arg);
	}
      else if (stap_is_register_indirection_prefix (gdbarch, tmp, NULL))
	stap_parse_register_operand (p);
      else
	error (_("Unknown numeric token on expression `%s'."),
	       p->saved_arg);
    }
  else if (stap_is_integer_prefix (gdbarch, p->arg, &int_prefix))
    {
      /* We are dealing with a numeric constant.  */
      long number;
      char *endp;
      const char *int_suffix;

      p->arg += strlen (int_prefix);
      number = strtol (p->arg, &endp, 10);
      p->arg = endp;

      write_exp_elt_opcode (&p->pstate, OP_LONG);
      write_exp_elt_type (&p->pstate, builtin_type (gdbarch)->builtin_long);
      write_exp_elt_longcst (&p->pstate, number);
      write_exp_elt_opcode (&p->pstate, OP_LONG);

      if (stap_check_integer_suffix (gdbarch, p->arg, &int_suffix))
	p->arg += strlen (int_suffix);
      else
	error (_("Invalid constant suffix on expression `%s'."),
	       p->saved_arg);
    }
  else if (stap_is_register_prefix (gdbarch, p->arg, NULL)
	   || stap_is_register_indirection_prefix (gdbarch, p->arg, NULL))
    stap_parse_register_operand (p);
  else
    error (_("Operator `%c' not recognized on expression `%s'."),
	   *p->arg, p->saved_arg);
}

/* This function parses an argument conditionally, based on single or
   non-single operands.  A non-single operand would be a parenthesized
   expression (e.g., `(2 + 1)'), and a single operand is anything that
   starts with `-', `~', `+' (i.e., unary operators), a digit, or
   something recognized by `gdbarch_stap_is_single_operand'.  */

static void
stap_parse_argument_conditionally (struct stap_parse_info *p)
{
  gdb_assert (gdbarch_stap_is_single_operand_p (p->gdbarch));

  if (*p->arg == '-' || *p->arg == '~' || *p->arg == '+' /* Unary.  */
      || isdigit (*p->arg)
      || gdbarch_stap_is_single_operand (p->gdbarch, p->arg))
    stap_parse_single_operand (p);
  else if (*p->arg == '(')
    {
      /* We are dealing with a parenthesized operand.  It means we
	 have to parse it as it was a separate expression, without
	 left-side or precedence.  */
      ++p->arg;
      p->arg = skip_spaces (p->arg);
      ++p->inside_paren_p;

      stap_parse_argument_1 (p, 0, STAP_OPERAND_PREC_NONE);

      --p->inside_paren_p;
      if (*p->arg != ')')
	error (_("Missign close-paren on expression `%s'."),
	       p->saved_arg);

      ++p->arg;
      if (p->inside_paren_p)
	p->arg = skip_spaces (p->arg);
    }
  else
    error (_("Cannot parse expression `%s'."), p->saved_arg);
}

/* Helper function for `stap_parse_argument'.  Please, see its comments to
   better understand what this function does.  */

static void
stap_parse_argument_1 (struct stap_parse_info *p, int has_lhs,
		       enum stap_operand_prec prec)
{
  /* This is an operator-precedence parser.

     We work with left- and right-sides of expressions, and
     parse them depending on the precedence of the operators
     we find.  */

  gdb_assert (p->arg != NULL);

  if (p->inside_paren_p)
    p->arg = skip_spaces (p->arg);

  if (!has_lhs)
    {
      /* We were called without a left-side, either because this is the
	 first call, or because we were called to parse a parenthesized
	 expression.  It doesn't really matter; we have to parse the
	 left-side in order to continue the process.  */
      stap_parse_argument_conditionally (p);
    }

  /* Start to parse the right-side, and to "join" left and right sides
     depending on the operation specified.

     This loop shall continue until we run out of characters in the input,
     or until we find a close-parenthesis, which means that we've reached
     the end of a sub-expression.  */
  while (*p->arg != '\0' && *p->arg != ')' && !isspace (*p->arg))
    {
      const char *tmp_exp_buf;
      enum exp_opcode opcode;
      enum stap_operand_prec cur_prec;

      if (!stap_is_operator (p->arg))
	error (_("Invalid operator `%c' on expression `%s'."), *p->arg,
	       p->saved_arg);

      /* We have to save the current value of the expression buffer because
	 the `stap_get_opcode' modifies it in order to get the current
	 operator.  If this operator's precedence is lower than PREC, we
	 should return and not advance the expression buffer pointer.  */
      tmp_exp_buf = p->arg;
      opcode = stap_get_opcode (&tmp_exp_buf);

      cur_prec = stap_get_operator_prec (opcode);
      if (cur_prec < prec)
	{
	  /* If the precedence of the operator that we are seeing now is
	     lower than the precedence of the first operator seen before
	     this parsing process began, it means we should stop parsing
	     and return.  */
	  break;
	}

      p->arg = tmp_exp_buf;
      if (p->inside_paren_p)
	p->arg = skip_spaces (p->arg);

      /* Parse the right-side of the expression.  */
      stap_parse_argument_conditionally (p);

      /* While we still have operators, try to parse another
	 right-side, but using the current right-side as a left-side.  */
      while (*p->arg != '\0' && stap_is_operator (p->arg))
	{
	  enum exp_opcode lookahead_opcode;
	  enum stap_operand_prec lookahead_prec;

	  /* Saving the current expression buffer position.  The explanation
	     is the same as above.  */
	  tmp_exp_buf = p->arg;
	  lookahead_opcode = stap_get_opcode (&tmp_exp_buf);
	  lookahead_prec = stap_get_operator_prec (lookahead_opcode);

	  if (lookahead_prec <= prec)
	    {
	      /* If we are dealing with an operator whose precedence is lower
		 than the first one, just abandon the attempt.  */
	      break;
	    }

	  /* Parse the right-side of the expression, but since we already
	     have a left-side at this point, set `has_lhs' to 1.  */
	  stap_parse_argument_1 (p, 1, lookahead_prec);
	}

      write_exp_elt_opcode (&p->pstate, opcode);
    }
}

/* Parse a probe's argument.

   Assuming that:

   LP = literal integer prefix
   LS = literal integer suffix

   RP = register prefix
   RS = register suffix

   RIP = register indirection prefix
   RIS = register indirection suffix

   This routine assumes that arguments' tokens are of the form:

   - [LP] NUMBER [LS]
   - [RP] REGISTER [RS]
   - [RIP] [RP] REGISTER [RS] [RIS]
   - If we find a number without LP, we try to parse it as a literal integer
   constant (if LP == NULL), or as a register displacement.
   - We count parenthesis, and only skip whitespaces if we are inside them.
   - If we find an operator, we skip it.

   This function can also call a special function that will try to match
   unknown tokens.  It will return the expression_up generated from
   parsing the argument.  */

static expression_up
stap_parse_argument (const char **arg, struct type *atype,
		     struct gdbarch *gdbarch)
{
  /* We need to initialize the expression buffer, in order to begin
     our parsing efforts.  We use language_c here because we may need
     to do pointer arithmetics.  */
  struct stap_parse_info p (*arg, atype, 10, language_def (language_c),
			    gdbarch);

  stap_parse_argument_1 (&p, 0, STAP_OPERAND_PREC_NONE);

  gdb_assert (p.inside_paren_p == 0);

  /* Casting the final expression to the appropriate type.  */
  write_exp_elt_opcode (&p.pstate, UNOP_CAST);
  write_exp_elt_type (&p.pstate, atype);
  write_exp_elt_opcode (&p.pstate, UNOP_CAST);

  p.arg = skip_spaces (p.arg);
  *arg = p.arg;

  return p.pstate.release ();
}

/* Implementation of 'parse_arguments' method.  */

void
stap_probe::parse_arguments (struct gdbarch *gdbarch)
{
  const char *cur;

  gdb_assert (!m_have_parsed_args);
  cur = m_unparsed_args_text;
  m_have_parsed_args = true;

  if (cur == NULL || *cur == '\0' || *cur == ':')
    return;

  while (*cur != '\0')
    {
      enum stap_arg_bitness bitness;
      bool got_minus = false;

      /* We expect to find something like:

	 N@OP

	 Where `N' can be [+,-][1,2,4,8].  This is not mandatory, so
	 we check it here.  If we don't find it, go to the next
	 state.  */
      if ((cur[0] == '-' && isdigit (cur[1]) && cur[2] == '@')
	  || (isdigit (cur[0]) && cur[1] == '@'))
	{
	  if (*cur == '-')
	    {
	      /* Discard the `-'.  */
	      ++cur;
	      got_minus = true;
	    }

	  /* Defining the bitness.  */
	  switch (*cur)
	    {
	    case '1':
	      bitness = (got_minus ? STAP_ARG_BITNESS_8BIT_SIGNED
			 : STAP_ARG_BITNESS_8BIT_UNSIGNED);
	      break;

	    case '2':
	      bitness = (got_minus ? STAP_ARG_BITNESS_16BIT_SIGNED
			 : STAP_ARG_BITNESS_16BIT_UNSIGNED);
	      break;

	    case '4':
	      bitness = (got_minus ? STAP_ARG_BITNESS_32BIT_SIGNED
			 : STAP_ARG_BITNESS_32BIT_UNSIGNED);
	      break;

	    case '8':
	      bitness = (got_minus ? STAP_ARG_BITNESS_64BIT_SIGNED
			 : STAP_ARG_BITNESS_64BIT_UNSIGNED);
	      break;

	    default:
	      {
		/* We have an error, because we don't expect anything
		   except 1, 2, 4 and 8.  */
		warning (_("unrecognized bitness %s%c' for probe `%s'"),
			 got_minus ? "`-" : "`", *cur,
			 this->get_name ().c_str ());
		return;
	      }
	    }
	  /* Discard the number and the `@' sign.  */
	  cur += 2;
	}
      else
	bitness = STAP_ARG_BITNESS_UNDEFINED;

      struct type *atype
	= stap_get_expected_argument_type (gdbarch, bitness,
					   this->get_name ().c_str ());

      expression_up expr = stap_parse_argument (&cur, atype, gdbarch);

      if (stap_expression_debug)
	dump_raw_expression (expr.get (), gdb_stdlog,
			     "before conversion to prefix form");

      prefixify_expression (expr.get ());

      if (stap_expression_debug)
	dump_prefix_expression (expr.get (), gdb_stdlog);

      m_parsed_args.emplace_back (bitness, atype, std::move (expr));

      /* Start it over again.  */
      cur = skip_spaces (cur);
    }
}

/* Helper function to relocate an address.  */

static CORE_ADDR
relocate_address (CORE_ADDR address, struct objfile *objfile)
{
  return address + ANOFFSET (objfile->section_offsets,
			     SECT_OFF_DATA (objfile));
}

/* Implementation of the get_relocated_address method.  */

CORE_ADDR
stap_probe::get_relocated_address (struct objfile *objfile)
{
  return relocate_address (this->get_address (), objfile);
}

/* Given PROBE, returns the number of arguments present in that probe's
   argument string.  */

unsigned
stap_probe::get_argument_count (struct frame_info *frame)
{
  struct gdbarch *gdbarch = get_frame_arch (frame);

  if (!m_have_parsed_args)
    {
      if (this->can_evaluate_arguments ())
	this->parse_arguments (gdbarch);
      else
	{
	  static int have_warned_stap_incomplete = 0;

	  if (!have_warned_stap_incomplete)
	    {
	      warning (_(
"The SystemTap SDT probe support is not fully implemented on this target;\n"
"you will not be able to inspect the arguments of the probes.\n"
"Please report a bug against GDB requesting a port to this target."));
	      have_warned_stap_incomplete = 1;
	    }

	  /* Marking the arguments as "already parsed".  */
	  m_have_parsed_args = true;
	}
    }

  gdb_assert (m_have_parsed_args);
  return m_parsed_args.size ();
}

/* Return 1 if OP is a valid operator inside a probe argument, or zero
   otherwise.  */

static int
stap_is_operator (const char *op)
{
  int ret = 1;

  switch (*op)
    {
    case '*':
    case '/':
    case '%':
    case '^':
    case '!':
    case '+':
    case '-':
    case '<':
    case '>':
    case '|':
    case '&':
      break;

    case '=':
      if (op[1] != '=')
	ret = 0;
      break;

    default:
      /* We didn't find any operator.  */
      ret = 0;
    }

  return ret;
}

/* Implement the `can_evaluate_arguments' method.  */

bool
stap_probe::can_evaluate_arguments () const
{
  struct gdbarch *gdbarch = this->get_gdbarch ();

  /* For SystemTap probes, we have to guarantee that the method
     stap_is_single_operand is defined on gdbarch.  If it is not, then it
     means that argument evaluation is not implemented on this target.  */
  return gdbarch_stap_is_single_operand_p (gdbarch);
}

/* Evaluate the probe's argument N (indexed from 0), returning a value
   corresponding to it.  Assertion is thrown if N does not exist.  */

struct value *
stap_probe::evaluate_argument (unsigned n, struct frame_info *frame)
{
  struct stap_probe_arg *arg;
  int pos = 0;
  struct gdbarch *gdbarch = get_frame_arch (frame);

  arg = this->get_arg_by_number (n, gdbarch);
  return evaluate_subexp_standard (arg->atype, arg->aexpr.get (), &pos,
				   EVAL_NORMAL);
}

/* Compile the probe's argument N (indexed from 0) to agent expression.
   Assertion is thrown if N does not exist.  */

void
stap_probe::compile_to_ax (struct agent_expr *expr, struct axs_value *value,
			   unsigned n)
{
  struct stap_probe_arg *arg;
  union exp_element *pc;

  arg = this->get_arg_by_number (n, expr->gdbarch);

  pc = arg->aexpr->elts;
  gen_expr (arg->aexpr.get (), &pc, expr, value);

  require_rvalue (expr, value);
  value->type = arg->atype;
}


/* Set or clear a SystemTap semaphore.  ADDRESS is the semaphore's
   address.  SET is zero if the semaphore should be cleared, or one if
   it should be set.  This is a helper function for
   'stap_probe::set_semaphore' and 'stap_probe::clear_semaphore'.  */

static void
stap_modify_semaphore (CORE_ADDR address, int set, struct gdbarch *gdbarch)
{
  gdb_byte bytes[sizeof (LONGEST)];
  /* The ABI specifies "unsigned short".  */
  struct type *type = builtin_type (gdbarch)->builtin_unsigned_short;
  ULONGEST value;

  if (address == 0)
    return;

  /* Swallow errors.  */
  if (target_read_memory (address, bytes, TYPE_LENGTH (type)) != 0)
    {
      warning (_("Could not read the value of a SystemTap semaphore."));
      return;
    }

  value = extract_unsigned_integer (bytes, TYPE_LENGTH (type),
				    gdbarch_byte_order (gdbarch));
  /* Note that we explicitly don't worry about overflow or
     underflow.  */
  if (set)
    ++value;
  else
    --value;

  store_unsigned_integer (bytes, TYPE_LENGTH (type),
			  gdbarch_byte_order (gdbarch), value);

  if (target_write_memory (address, bytes, TYPE_LENGTH (type)) != 0)
    warning (_("Could not write the value of a SystemTap semaphore."));
}

/* Implementation of the 'set_semaphore' method.

   SystemTap semaphores act as reference counters, so calls to this
   function must be paired with calls to 'clear_semaphore'.

   This function and 'clear_semaphore' race with another tool
   changing the probes, but that is too rare to care.  */

void
stap_probe::set_semaphore (struct objfile *objfile, struct gdbarch *gdbarch)
{
  stap_modify_semaphore (relocate_address (m_sem_addr, objfile), 1, gdbarch);
}

/* Implementation of the 'clear_semaphore' method.  */

void
stap_probe::clear_semaphore (struct objfile *objfile, struct gdbarch *gdbarch)
{
  stap_modify_semaphore (relocate_address (m_sem_addr, objfile), 0, gdbarch);
}

/* Implementation of the 'get_static_ops' method.  */

const static_probe_ops *
stap_probe::get_static_ops () const
{
  return &stap_static_probe_ops;
}

/* Implementation of the 'gen_info_probes_table_values' method.  */

std::vector<const char *>
stap_probe::gen_info_probes_table_values () const
{
  const char *val = NULL;

  if (m_sem_addr != 0)
    val = print_core_address (this->get_gdbarch (), m_sem_addr);

  return std::vector<const char *> { val };
}

/* Helper function that parses the information contained in a
   SystemTap's probe.  Basically, the information consists in:

   - Probe's PC address;
   - Link-time section address of `.stapsdt.base' section;
   - Link-time address of the semaphore variable, or ZERO if the
     probe doesn't have an associated semaphore;
   - Probe's provider name;
   - Probe's name;
   - Probe's argument format
   
   This function returns 1 if the handling was successful, and zero
   otherwise.  */

static void
handle_stap_probe (struct objfile *objfile, struct sdt_note *el,
		   std::vector<probe *> *probesp, CORE_ADDR base)
{
  bfd *abfd = objfile->obfd;
  int size = bfd_get_arch_size (abfd) / 8;
  struct gdbarch *gdbarch = get_objfile_arch (objfile);
  struct type *ptr_type = builtin_type (gdbarch)->builtin_data_ptr;

  /* Provider and the name of the probe.  */
  const char *provider = (const char *) &el->data[3 * size];
  const char *name = ((const char *)
		      memchr (provider, '\0',
			      (char *) el->data + el->size - provider));
  /* Making sure there is a name.  */
  if (name == NULL)
    {
      complaint (_("corrupt probe name when "
					"reading `%s'"),
		 objfile_name (objfile));

      /* There is no way to use a probe without a name or a provider, so
	 returning zero here makes sense.  */
      return;
    }
  else
    ++name;

  /* Retrieving the probe's address.  */
  CORE_ADDR address = extract_typed_address (&el->data[0], ptr_type);

  /* Link-time sh_addr of `.stapsdt.base' section.  */
  CORE_ADDR base_ref = extract_typed_address (&el->data[size], ptr_type);

  /* Semaphore address.  */
  CORE_ADDR sem_addr = extract_typed_address (&el->data[2 * size], ptr_type);

  address += base - base_ref;
  if (sem_addr != 0)
    sem_addr += base - base_ref;

  /* Arguments.  We can only extract the argument format if there is a valid
     name for this probe.  */
  const char *probe_args = ((const char*)
			    memchr (name, '\0',
				    (char *) el->data + el->size - name));

  if (probe_args != NULL)
    ++probe_args;

  if (probe_args == NULL
      || (memchr (probe_args, '\0', (char *) el->data + el->size - name)
	  != el->data + el->size - 1))
    {
      complaint (_("corrupt probe argument when "
					"reading `%s'"),
		 objfile_name (objfile));
      /* If the argument string is NULL, it means some problem happened with
	 it.  So we return 0.  */
      return;
    }

  stap_probe *ret = new stap_probe (std::string (name), std::string (provider),
				    address, gdbarch, sem_addr, probe_args);

  /* Successfully created probe.  */
  probesp->push_back (ret);
}

/* Helper function which tries to find the base address of the SystemTap
   base section named STAP_BASE_SECTION_NAME.  */

static void
get_stap_base_address_1 (bfd *abfd, asection *sect, void *obj)
{
  asection **ret = (asection **) obj;

  if ((sect->flags & (SEC_DATA | SEC_ALLOC | SEC_HAS_CONTENTS))
      && sect->name && !strcmp (sect->name, STAP_BASE_SECTION_NAME))
    *ret = sect;
}

/* Helper function which iterates over every section in the BFD file,
   trying to find the base address of the SystemTap base section.
   Returns 1 if found (setting BASE to the proper value), zero otherwise.  */

static int
get_stap_base_address (bfd *obfd, bfd_vma *base)
{
  asection *ret = NULL;

  bfd_map_over_sections (obfd, get_stap_base_address_1, (void *) &ret);

  if (ret == NULL)
    {
      complaint (_("could not obtain base address for "
					"SystemTap section on objfile `%s'."),
		 obfd->filename);
      return 0;
    }

  if (base != NULL)
    *base = ret->vma;

  return 1;
}

/* Implementation of the 'is_linespec' method.  */

bool
stap_static_probe_ops::is_linespec (const char **linespecp) const
{
  static const char *const keywords[] = { "-pstap", "-probe-stap", NULL };

  return probe_is_linespec_by_keyword (linespecp, keywords);
}

/* Implementation of the 'get_probes' method.  */

void
stap_static_probe_ops::get_probes (std::vector<probe *> *probesp,
				   struct objfile *objfile) const
{
  /* If we are here, then this is the first time we are parsing the
     SystemTap probe's information.  We basically have to count how many
     probes the objfile has, and then fill in the necessary information
     for each one.  */
  bfd *obfd = objfile->obfd;
  bfd_vma base;
  struct sdt_note *iter;
  unsigned save_probesp_len = probesp->size ();

  if (objfile->separate_debug_objfile_backlink != NULL)
    {
      /* This is a .debug file, not the objfile itself.  */
      return;
    }

  if (elf_tdata (obfd)->sdt_note_head == NULL)
    {
      /* There isn't any probe here.  */
      return;
    }

  if (!get_stap_base_address (obfd, &base))
    {
      /* There was an error finding the base address for the section.
	 Just return NULL.  */
      return;
    }

  /* Parsing each probe's information.  */
  for (iter = elf_tdata (obfd)->sdt_note_head;
       iter != NULL;
       iter = iter->next)
    {
      /* We first have to handle all the information about the
	 probe which is present in the section.  */
      handle_stap_probe (objfile, iter, probesp, base);
    }

  if (save_probesp_len == probesp->size ())
    {
      /* If we are here, it means we have failed to parse every known
	 probe.  */
      complaint (_("could not parse SystemTap probe(s) "
					"from inferior"));
      return;
    }
}

/* Implementation of the type_name method.  */

const char *
stap_static_probe_ops::type_name () const
{
  return "stap";
}

/* Implementation of the 'gen_info_probes_table_header' method.  */

std::vector<struct info_probe_column>
stap_static_probe_ops::gen_info_probes_table_header () const
{
  struct info_probe_column stap_probe_column;

  stap_probe_column.field_name = "semaphore";
  stap_probe_column.print_name = _("Semaphore");

  return std::vector<struct info_probe_column> { stap_probe_column };
}

/* Implementation of the `info probes stap' command.  */

static void
info_probes_stap_command (const char *arg, int from_tty)
{
  info_probes_for_spops (arg, from_tty, &stap_static_probe_ops);
}

void
_initialize_stap_probe (void)
{
  all_static_probe_ops.push_back (&stap_static_probe_ops);

  add_setshow_zuinteger_cmd ("stap-expression", class_maintenance,
			     &stap_expression_debug,
			     _("Set SystemTap expression debugging."),
			     _("Show SystemTap expression debugging."),
			     _("When non-zero, the internal representation "
			       "of SystemTap expressions will be printed."),
			     NULL,
			     show_stapexpressiondebug,
			     &setdebuglist, &showdebuglist);

  add_cmd ("stap", class_info, info_probes_stap_command,
	   _("\
Show information about SystemTap static probes.\n\
Usage: info probes stap [PROVIDER [NAME [OBJECT]]]\n\
Each argument is a regular expression, used to select probes.\n\
PROVIDER matches probe provider names.\n\
NAME matches the probe names.\n\
OBJECT matches the executable or shared library name."),
	   info_probes_cmdlist_get ());

}
