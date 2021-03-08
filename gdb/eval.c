/* Evaluate expressions for GDB.

   Copyright (C) 1986-2021 Free Software Foundation, Inc.

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
#include "symtab.h"
#include "gdbtypes.h"
#include "value.h"
#include "expression.h"
#include "target.h"
#include "frame.h"
#include "gdbthread.h"
#include "language.h"		/* For CAST_IS_CONVERSION.  */
#include "cp-abi.h"
#include "infcall.h"
#include "objc-lang.h"
#include "block.h"
#include "parser-defs.h"
#include "cp-support.h"
#include "ui-out.h"
#include "regcache.h"
#include "user-regs.h"
#include "valprint.h"
#include "gdb_obstack.h"
#include "objfiles.h"
#include "typeprint.h"
#include <ctype.h>
#include "expop.h"
#include "c-exp.h"

/* Prototypes for local functions.  */

static struct value *evaluate_subexp_for_sizeof (struct expression *, int *,
						 enum noside);

static struct value *evaluate_subexp_for_address (struct expression *,
						  int *, enum noside);

static value *evaluate_subexp_for_cast (expression *exp, int *pos,
					enum noside noside,
					struct type *type);

static struct value *evaluate_struct_tuple (struct value *,
					    struct expression *, int *,
					    enum noside, int);

struct value *
evaluate_subexp (struct type *expect_type, struct expression *exp,
		 int *pos, enum noside noside)
{
  return ((*exp->language_defn->expression_ops ()->evaluate_exp)
	  (expect_type, exp, pos, noside));
}

/* Parse the string EXP as a C expression, evaluate it,
   and return the result as a number.  */

CORE_ADDR
parse_and_eval_address (const char *exp)
{
  expression_up expr = parse_expression (exp);

  return value_as_address (evaluate_expression (expr.get ()));
}

/* Like parse_and_eval_address, but treats the value of the expression
   as an integer, not an address, returns a LONGEST, not a CORE_ADDR.  */
LONGEST
parse_and_eval_long (const char *exp)
{
  expression_up expr = parse_expression (exp);

  return value_as_long (evaluate_expression (expr.get ()));
}

struct value *
parse_and_eval (const char *exp)
{
  expression_up expr = parse_expression (exp);

  return evaluate_expression (expr.get ());
}

/* Parse up to a comma (or to a closeparen)
   in the string EXPP as an expression, evaluate it, and return the value.
   EXPP is advanced to point to the comma.  */

struct value *
parse_to_comma_and_eval (const char **expp)
{
  expression_up expr = parse_exp_1 (expp, 0, nullptr, 1);

  return evaluate_expression (expr.get ());
}


/* See expression.h.  */

struct value *
expression::evaluate (struct type *expect_type, enum noside noside)
{
  gdb::optional<enable_thread_stack_temporaries> stack_temporaries;
  if (target_has_execution ()
      && language_defn->la_language == language_cplus
      && !thread_stack_temporaries_enabled_p (inferior_thread ()))
    stack_temporaries.emplace (inferior_thread ());

  int pos = 0;
  struct value *retval = evaluate_subexp (expect_type, this, &pos, noside);

  if (stack_temporaries.has_value ()
      && value_in_thread_stack_temporaries (retval, inferior_thread ()))
    retval = value_non_lval (retval);

  return retval;
}

/* See value.h.  */

struct value *
evaluate_expression (struct expression *exp, struct type *expect_type)
{
  return exp->evaluate (expect_type, EVAL_NORMAL);
}

/* Evaluate an expression, avoiding all memory references
   and getting a value whose type alone is correct.  */

struct value *
evaluate_type (struct expression *exp)
{
  return exp->evaluate (nullptr, EVAL_AVOID_SIDE_EFFECTS);
}

/* Evaluate a subexpression, avoiding all memory references and
   getting a value whose type alone is correct.  */

struct value *
evaluate_subexpression_type (struct expression *exp, int subexp)
{
  return evaluate_subexp (nullptr, exp, &subexp, EVAL_AVOID_SIDE_EFFECTS);
}

/* Find the current value of a watchpoint on EXP.  Return the value in
   *VALP and *RESULTP and the chain of intermediate and final values
   in *VAL_CHAIN.  RESULTP and VAL_CHAIN may be NULL if the caller does
   not need them.

   If PRESERVE_ERRORS is true, then exceptions are passed through.
   Otherwise, if PRESERVE_ERRORS is false, then if a memory error
   occurs while evaluating the expression, *RESULTP will be set to
   NULL.  *RESULTP may be a lazy value, if the result could not be
   read from memory.  It is used to determine whether a value is
   user-specified (we should watch the whole value) or intermediate
   (we should watch only the bit used to locate the final value).

   If the final value, or any intermediate value, could not be read
   from memory, *VALP will be set to NULL.  *VAL_CHAIN will still be
   set to any referenced values.  *VALP will never be a lazy value.
   This is the value which we store in struct breakpoint.

   If VAL_CHAIN is non-NULL, the values put into *VAL_CHAIN will be
   released from the value chain.  If VAL_CHAIN is NULL, all generated
   values will be left on the value chain.  */

void
fetch_subexp_value (struct expression *exp, int *pc, struct value **valp,
		    struct value **resultp,
		    std::vector<value_ref_ptr> *val_chain,
		    bool preserve_errors)
{
  struct value *mark, *new_mark, *result;

  *valp = NULL;
  if (resultp)
    *resultp = NULL;
  if (val_chain)
    val_chain->clear ();

  /* Evaluate the expression.  */
  mark = value_mark ();
  result = NULL;

  try
    {
      result = evaluate_subexp (nullptr, exp, pc, EVAL_NORMAL);
    }
  catch (const gdb_exception &ex)
    {
      /* Ignore memory errors if we want watchpoints pointing at
	 inaccessible memory to still be created; otherwise, throw the
	 error to some higher catcher.  */
      switch (ex.error)
	{
	case MEMORY_ERROR:
	  if (!preserve_errors)
	    break;
	  /* Fall through.  */
	default:
	  throw;
	  break;
	}
    }

  new_mark = value_mark ();
  if (mark == new_mark)
    return;
  if (resultp)
    *resultp = result;

  /* Make sure it's not lazy, so that after the target stops again we
     have a non-lazy previous value to compare with.  */
  if (result != NULL)
    {
      if (!value_lazy (result))
	*valp = result;
      else
	{

	  try
	    {
	      value_fetch_lazy (result);
	      *valp = result;
	    }
	  catch (const gdb_exception_error &except)
	    {
	    }
	}
    }

  if (val_chain)
    {
      /* Return the chain of intermediate values.  We use this to
	 decide which addresses to watch.  */
      *val_chain = value_release_to_mark (mark);
    }
}

/* Extract a field operation from an expression.  If the subexpression
   of EXP starting at *SUBEXP is not a structure dereference
   operation, return NULL.  Otherwise, return the name of the
   dereferenced field, and advance *SUBEXP to point to the
   subexpression of the left-hand-side of the dereference.  This is
   used when completing field names.  */

const char *
extract_field_op (struct expression *exp, int *subexp)
{
  int tem;
  char *result;

  if (exp->elts[*subexp].opcode != STRUCTOP_STRUCT
      && exp->elts[*subexp].opcode != STRUCTOP_PTR)
    return NULL;
  tem = longest_to_int (exp->elts[*subexp + 1].longconst);
  result = &exp->elts[*subexp + 2].string;
  (*subexp) += 1 + 3 + BYTES_TO_EXP_ELEM (tem + 1);
  return result;
}

/* This function evaluates brace-initializers (in C/C++) for
   structure types.  */

static struct value *
evaluate_struct_tuple (struct value *struct_val,
		       struct expression *exp,
		       int *pos, enum noside noside, int nargs)
{
  struct type *struct_type = check_typedef (value_type (struct_val));
  struct type *field_type;
  int fieldno = -1;

  while (--nargs >= 0)
    {
      struct value *val = NULL;
      int bitpos, bitsize;
      bfd_byte *addr;

      fieldno++;
      /* Skip static fields.  */
      while (fieldno < struct_type->num_fields ()
	     && field_is_static (&struct_type->field (fieldno)))
	fieldno++;
      if (fieldno >= struct_type->num_fields ())
	error (_("too many initializers"));
      field_type = struct_type->field (fieldno).type ();
      if (field_type->code () == TYPE_CODE_UNION
	  && TYPE_FIELD_NAME (struct_type, fieldno)[0] == '0')
	error (_("don't know which variant you want to set"));

      /* Here, struct_type is the type of the inner struct,
	 while substruct_type is the type of the inner struct.
	 These are the same for normal structures, but a variant struct
	 contains anonymous union fields that contain substruct fields.
	 The value fieldno is the index of the top-level (normal or
	 anonymous union) field in struct_field, while the value
	 subfieldno is the index of the actual real (named inner) field
	 in substruct_type.  */

      field_type = struct_type->field (fieldno).type ();
      if (val == 0)
	val = evaluate_subexp (field_type, exp, pos, noside);

      /* Now actually set the field in struct_val.  */

      /* Assign val to field fieldno.  */
      if (value_type (val) != field_type)
	val = value_cast (field_type, val);

      bitsize = TYPE_FIELD_BITSIZE (struct_type, fieldno);
      bitpos = TYPE_FIELD_BITPOS (struct_type, fieldno);
      addr = value_contents_writeable (struct_val) + bitpos / 8;
      if (bitsize)
	modify_field (struct_type, addr,
		      value_as_long (val), bitpos % 8, bitsize);
      else
	memcpy (addr, value_contents (val),
		TYPE_LENGTH (value_type (val)));

    }
  return struct_val;
}

/* Promote value ARG1 as appropriate before performing a unary operation
   on this argument.
   If the result is not appropriate for any particular language then it
   needs to patch this function.  */

void
unop_promote (const struct language_defn *language, struct gdbarch *gdbarch,
	      struct value **arg1)
{
  struct type *type1;

  *arg1 = coerce_ref (*arg1);
  type1 = check_typedef (value_type (*arg1));

  if (is_integral_type (type1))
    {
      switch (language->la_language)
	{
	default:
	  /* Perform integral promotion for ANSI C/C++.
	     If not appropriate for any particular language
	     it needs to modify this function.  */
	  {
	    struct type *builtin_int = builtin_type (gdbarch)->builtin_int;

	    if (TYPE_LENGTH (type1) < TYPE_LENGTH (builtin_int))
	      *arg1 = value_cast (builtin_int, *arg1);
	  }
	  break;
	}
    }
}

/* Promote values ARG1 and ARG2 as appropriate before performing a binary
   operation on those two operands.
   If the result is not appropriate for any particular language then it
   needs to patch this function.  */

void
binop_promote (const struct language_defn *language, struct gdbarch *gdbarch,
	       struct value **arg1, struct value **arg2)
{
  struct type *promoted_type = NULL;
  struct type *type1;
  struct type *type2;

  *arg1 = coerce_ref (*arg1);
  *arg2 = coerce_ref (*arg2);

  type1 = check_typedef (value_type (*arg1));
  type2 = check_typedef (value_type (*arg2));

  if ((type1->code () != TYPE_CODE_FLT
       && type1->code () != TYPE_CODE_DECFLOAT
       && !is_integral_type (type1))
      || (type2->code () != TYPE_CODE_FLT
	  && type2->code () != TYPE_CODE_DECFLOAT
	  && !is_integral_type (type2)))
    return;

  if (is_fixed_point_type (type1) || is_fixed_point_type (type2))
        return;

  if (type1->code () == TYPE_CODE_DECFLOAT
      || type2->code () == TYPE_CODE_DECFLOAT)
    {
      /* No promotion required.  */
    }
  else if (type1->code () == TYPE_CODE_FLT
	   || type2->code () == TYPE_CODE_FLT)
    {
      switch (language->la_language)
	{
	case language_c:
	case language_cplus:
	case language_asm:
	case language_objc:
	case language_opencl:
	  /* No promotion required.  */
	  break;

	default:
	  /* For other languages the result type is unchanged from gdb
	     version 6.7 for backward compatibility.
	     If either arg was long double, make sure that value is also long
	     double.  Otherwise use double.  */
	  if (TYPE_LENGTH (type1) * 8 > gdbarch_double_bit (gdbarch)
	      || TYPE_LENGTH (type2) * 8 > gdbarch_double_bit (gdbarch))
	    promoted_type = builtin_type (gdbarch)->builtin_long_double;
	  else
	    promoted_type = builtin_type (gdbarch)->builtin_double;
	  break;
	}
    }
  else if (type1->code () == TYPE_CODE_BOOL
	   && type2->code () == TYPE_CODE_BOOL)
    {
      /* No promotion required.  */
    }
  else
    /* Integral operations here.  */
    /* FIXME: Also mixed integral/booleans, with result an integer.  */
    {
      const struct builtin_type *builtin = builtin_type (gdbarch);
      unsigned int promoted_len1 = TYPE_LENGTH (type1);
      unsigned int promoted_len2 = TYPE_LENGTH (type2);
      int is_unsigned1 = type1->is_unsigned ();
      int is_unsigned2 = type2->is_unsigned ();
      unsigned int result_len;
      int unsigned_operation;

      /* Determine type length and signedness after promotion for
	 both operands.  */
      if (promoted_len1 < TYPE_LENGTH (builtin->builtin_int))
	{
	  is_unsigned1 = 0;
	  promoted_len1 = TYPE_LENGTH (builtin->builtin_int);
	}
      if (promoted_len2 < TYPE_LENGTH (builtin->builtin_int))
	{
	  is_unsigned2 = 0;
	  promoted_len2 = TYPE_LENGTH (builtin->builtin_int);
	}

      if (promoted_len1 > promoted_len2)
	{
	  unsigned_operation = is_unsigned1;
	  result_len = promoted_len1;
	}
      else if (promoted_len2 > promoted_len1)
	{
	  unsigned_operation = is_unsigned2;
	  result_len = promoted_len2;
	}
      else
	{
	  unsigned_operation = is_unsigned1 || is_unsigned2;
	  result_len = promoted_len1;
	}

      switch (language->la_language)
	{
	case language_c:
	case language_cplus:
	case language_asm:
	case language_objc:
	  if (result_len <= TYPE_LENGTH (builtin->builtin_int))
	    {
	      promoted_type = (unsigned_operation
			       ? builtin->builtin_unsigned_int
			       : builtin->builtin_int);
	    }
	  else if (result_len <= TYPE_LENGTH (builtin->builtin_long))
	    {
	      promoted_type = (unsigned_operation
			       ? builtin->builtin_unsigned_long
			       : builtin->builtin_long);
	    }
	  else
	    {
	      promoted_type = (unsigned_operation
			       ? builtin->builtin_unsigned_long_long
			       : builtin->builtin_long_long);
	    }
	  break;
	case language_opencl:
	  if (result_len <= TYPE_LENGTH (lookup_signed_typename
					 (language, "int")))
	    {
	      promoted_type =
		(unsigned_operation
		 ? lookup_unsigned_typename (language, "int")
		 : lookup_signed_typename (language, "int"));
	    }
	  else if (result_len <= TYPE_LENGTH (lookup_signed_typename
					      (language, "long")))
	    {
	      promoted_type =
		(unsigned_operation
		 ? lookup_unsigned_typename (language, "long")
		 : lookup_signed_typename (language,"long"));
	    }
	  break;
	default:
	  /* For other languages the result type is unchanged from gdb
	     version 6.7 for backward compatibility.
	     If either arg was long long, make sure that value is also long
	     long.  Otherwise use long.  */
	  if (unsigned_operation)
	    {
	      if (result_len > gdbarch_long_bit (gdbarch) / HOST_CHAR_BIT)
		promoted_type = builtin->builtin_unsigned_long_long;
	      else
		promoted_type = builtin->builtin_unsigned_long;
	    }
	  else
	    {
	      if (result_len > gdbarch_long_bit (gdbarch) / HOST_CHAR_BIT)
		promoted_type = builtin->builtin_long_long;
	      else
		promoted_type = builtin->builtin_long;
	    }
	  break;
	}
    }

  if (promoted_type)
    {
      /* Promote both operands to common type.  */
      *arg1 = value_cast (promoted_type, *arg1);
      *arg2 = value_cast (promoted_type, *arg2);
    }
}

static int
ptrmath_type_p (const struct language_defn *lang, struct type *type)
{
  type = check_typedef (type);
  if (TYPE_IS_REFERENCE (type))
    type = TYPE_TARGET_TYPE (type);

  switch (type->code ())
    {
    case TYPE_CODE_PTR:
    case TYPE_CODE_FUNC:
      return 1;

    case TYPE_CODE_ARRAY:
      return type->is_vector () ? 0 : lang->c_style_arrays_p ();

    default:
      return 0;
    }
}

/* Represents a fake method with the given parameter types.  This is
   used by the parser to construct a temporary "expected" type for
   method overload resolution.  FLAGS is used as instance flags of the
   new type, in order to be able to make the new type represent a
   const/volatile overload.  */

class fake_method
{
public:
  fake_method (type_instance_flags flags,
	       int num_types, struct type **param_types);
  ~fake_method ();

  /* The constructed type.  */
  struct type *type () { return &m_type; }

private:
  struct type m_type {};
  main_type m_main_type {};
};

fake_method::fake_method (type_instance_flags flags,
			  int num_types, struct type **param_types)
{
  struct type *type = &m_type;

  TYPE_MAIN_TYPE (type) = &m_main_type;
  TYPE_LENGTH (type) = 1;
  type->set_code (TYPE_CODE_METHOD);
  TYPE_CHAIN (type) = type;
  type->set_instance_flags (flags);
  if (num_types > 0)
    {
      if (param_types[num_types - 1] == NULL)
	{
	  --num_types;
	  type->set_has_varargs (true);
	}
      else if (check_typedef (param_types[num_types - 1])->code ()
	       == TYPE_CODE_VOID)
	{
	  --num_types;
	  /* Caller should have ensured this.  */
	  gdb_assert (num_types == 0);
	  type->set_is_prototyped (true);
	}
    }

  /* We don't use TYPE_ZALLOC here to allocate space as TYPE is owned by
     neither an objfile nor a gdbarch.  As a result we must manually
     allocate memory for auxiliary fields, and free the memory ourselves
     when we are done with it.  */
  type->set_num_fields (num_types);
  type->set_fields
    ((struct field *) xzalloc (sizeof (struct field) * num_types));

  while (num_types-- > 0)
    type->field (num_types).set_type (param_types[num_types]);
}

fake_method::~fake_method ()
{
  xfree (m_type.fields ());
}

namespace expr
{

value *
type_instance_operation::evaluate (struct type *expect_type,
				   struct expression *exp,
				   enum noside noside)
{
  type_instance_flags flags = std::get<0> (m_storage);
  std::vector<type *> &types = std::get<1> (m_storage);

  fake_method fake_expect_type (flags, types.size (), types.data ());
  return std::get<2> (m_storage)->evaluate (fake_expect_type.type (),
					    exp, noside);
}

}

/* Helper for evaluating an OP_VAR_VALUE.  */

value *
evaluate_var_value (enum noside noside, const block *blk, symbol *var)
{
  /* JYG: We used to just return value_zero of the symbol type if
     we're asked to avoid side effects.  Otherwise we return
     value_of_variable (...).  However I'm not sure if
     value_of_variable () has any side effect.  We need a full value
     object returned here for whatis_exp () to call evaluate_type ()
     and then pass the full value to value_rtti_target_type () if we
     are dealing with a pointer or reference to a base class and print
     object is on.  */

  struct value *ret = NULL;

  try
    {
      ret = value_of_variable (var, blk);
    }

  catch (const gdb_exception_error &except)
    {
      if (noside != EVAL_AVOID_SIDE_EFFECTS)
	throw;

      ret = value_zero (SYMBOL_TYPE (var), not_lval);
    }

  return ret;
}

namespace expr

{

value *
var_value_operation::evaluate (struct type *expect_type,
			       struct expression *exp,
			       enum noside noside)
{
  symbol *var = std::get<0> (m_storage);
  if (SYMBOL_TYPE (var)->code () == TYPE_CODE_ERROR)
    error_unknown_type (var->print_name ());
  return evaluate_var_value (noside, std::get<1> (m_storage), var);
}

} /* namespace expr */

/* Helper for evaluating an OP_VAR_MSYM_VALUE.  */

value *
evaluate_var_msym_value (enum noside noside,
			 struct objfile *objfile, minimal_symbol *msymbol)
{
  CORE_ADDR address;
  type *the_type = find_minsym_type_and_address (msymbol, objfile, &address);

  if (noside == EVAL_AVOID_SIDE_EFFECTS && !the_type->is_gnu_ifunc ())
    return value_zero (the_type, not_lval);
  else
    return value_at_lazy (the_type, address);
}

/* Helper for returning a value when handling EVAL_SKIP.  */

value *
eval_skip_value (expression *exp)
{
  return value_from_longest (builtin_type (exp->gdbarch)->builtin_int, 1);
}

/* See expression.h.  */

value *
evaluate_subexp_do_call (expression *exp, enum noside noside,
			 value *callee,
			 gdb::array_view<value *> argvec,
			 const char *function_name,
			 type *default_return_type)
{
  if (callee == NULL)
    error (_("Cannot evaluate function -- may be inlined"));
  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    {
      /* If the return type doesn't look like a function type,
	 call an error.  This can happen if somebody tries to turn
	 a variable into a function call.  */

      type *ftype = value_type (callee);

      if (ftype->code () == TYPE_CODE_INTERNAL_FUNCTION)
	{
	  /* We don't know anything about what the internal
	     function might return, but we have to return
	     something.  */
	  return value_zero (builtin_type (exp->gdbarch)->builtin_int,
			     not_lval);
	}
      else if (ftype->code () == TYPE_CODE_XMETHOD)
	{
	  type *return_type = result_type_of_xmethod (callee, argvec);

	  if (return_type == NULL)
	    error (_("Xmethod is missing return type."));
	  return value_zero (return_type, not_lval);
	}
      else if (ftype->code () == TYPE_CODE_FUNC
	       || ftype->code () == TYPE_CODE_METHOD)
	{
	  if (ftype->is_gnu_ifunc ())
	    {
	      CORE_ADDR address = value_address (callee);
	      type *resolved_type = find_gnu_ifunc_target_type (address);

	      if (resolved_type != NULL)
		ftype = resolved_type;
	    }

	  type *return_type = TYPE_TARGET_TYPE (ftype);

	  if (return_type == NULL)
	    return_type = default_return_type;

	  if (return_type == NULL)
	    error_call_unknown_return_type (function_name);

	  return allocate_value (return_type);
	}
      else
	error (_("Expression of type other than "
		 "\"Function returning ...\" used as function"));
    }
  switch (value_type (callee)->code ())
    {
    case TYPE_CODE_INTERNAL_FUNCTION:
      return call_internal_function (exp->gdbarch, exp->language_defn,
				     callee, argvec.size (), argvec.data ());
    case TYPE_CODE_XMETHOD:
      return call_xmethod (callee, argvec);
    default:
      return call_function_by_hand (callee, default_return_type, argvec);
    }
}

/* Helper for evaluating an OP_FUNCALL.  */

static value *
evaluate_funcall (type *expect_type, expression *exp, int *pos,
		  enum noside noside)
{
  int tem;
  int pc2 = 0;
  value *arg1 = NULL;
  value *arg2 = NULL;
  int save_pos1;
  symbol *function = NULL;
  char *function_name = NULL;
  const char *var_func_name = NULL;

  int pc = (*pos);
  (*pos) += 2;

  exp_opcode op = exp->elts[*pos].opcode;
  int nargs = longest_to_int (exp->elts[pc].longconst);
  /* Allocate arg vector, including space for the function to be
     called in argvec[0], a potential `this', and a terminating
     NULL.  */
  value **argvec = (value **) alloca (sizeof (value *) * (nargs + 3));
  if (op == STRUCTOP_MEMBER || op == STRUCTOP_MPTR)
    {
      /* First, evaluate the structure into arg2.  */
      pc2 = (*pos)++;

      if (op == STRUCTOP_MEMBER)
	{
	  arg2 = evaluate_subexp_for_address (exp, pos, noside);
	}
      else
	{
	  arg2 = evaluate_subexp (nullptr, exp, pos, noside);
	}

      /* If the function is a virtual function, then the aggregate
	 value (providing the structure) plays its part by providing
	 the vtable.  Otherwise, it is just along for the ride: call
	 the function directly.  */

      arg1 = evaluate_subexp (nullptr, exp, pos, noside);

      type *a1_type = check_typedef (value_type (arg1));
      if (noside == EVAL_SKIP)
	tem = 1;  /* Set it to the right arg index so that all
		     arguments can also be skipped.  */
      else if (a1_type->code () == TYPE_CODE_METHODPTR)
	{
	  if (noside == EVAL_AVOID_SIDE_EFFECTS)
	    arg1 = value_zero (TYPE_TARGET_TYPE (a1_type), not_lval);
	  else
	    arg1 = cplus_method_ptr_to_value (&arg2, arg1);

	  /* Now, say which argument to start evaluating from.  */
	  nargs++;
	  tem = 2;
	  argvec[1] = arg2;
	}
      else if (a1_type->code () == TYPE_CODE_MEMBERPTR)
	{
	  struct type *type_ptr
	    = lookup_pointer_type (TYPE_SELF_TYPE (a1_type));
	  struct type *target_type_ptr
	    = lookup_pointer_type (TYPE_TARGET_TYPE (a1_type));

	  /* Now, convert these values to an address.  */
	  arg2 = value_cast (type_ptr, arg2);

	  long mem_offset = value_as_long (arg1);

	  arg1 = value_from_pointer (target_type_ptr,
				     value_as_long (arg2) + mem_offset);
	  arg1 = value_ind (arg1);
	  tem = 1;
	}
      else
	error (_("Non-pointer-to-member value used in pointer-to-member "
		 "construct"));
    }
  else if (op == STRUCTOP_STRUCT || op == STRUCTOP_PTR)
    {
      /* Hair for method invocations.  */
      int tem2;

      nargs++;
      /* First, evaluate the structure into arg2.  */
      pc2 = (*pos)++;
      tem2 = longest_to_int (exp->elts[pc2 + 1].longconst);
      *pos += 3 + BYTES_TO_EXP_ELEM (tem2 + 1);

      if (op == STRUCTOP_STRUCT)
	{
	  /* If v is a variable in a register, and the user types
	     v.method (), this will produce an error, because v has no
	     address.

	     A possible way around this would be to allocate a copy of
	     the variable on the stack, copy in the contents, call the
	     function, and copy out the contents.  I.e. convert this
	     from call by reference to call by copy-return (or
	     whatever it's called).  However, this does not work
	     because it is not the same: the method being called could
	     stash a copy of the address, and then future uses through
	     that address (after the method returns) would be expected
	     to use the variable itself, not some copy of it.  */
	  arg2 = evaluate_subexp_for_address (exp, pos, noside);
	}
      else
	{
	  arg2 = evaluate_subexp (nullptr, exp, pos, noside);

	  /* Check to see if the operator '->' has been overloaded.
	     If the operator has been overloaded replace arg2 with the
	     value returned by the custom operator and continue
	     evaluation.  */
	  while (unop_user_defined_p (op, arg2))
	    {
	      struct value *value = NULL;
	      try
		{
		  value = value_x_unop (arg2, op, noside);
		}

	      catch (const gdb_exception_error &except)
		{
		  if (except.error == NOT_FOUND_ERROR)
		    break;
		  else
		    throw;
		}

		arg2 = value;
	    }
	}
      /* Now, say which argument to start evaluating from.  */
      tem = 2;
    }
  else if (op == OP_SCOPE
	   && overload_resolution
	   && (exp->language_defn->la_language == language_cplus))
    {
      /* Unpack it locally so we can properly handle overload
	 resolution.  */
      char *name;
      int local_tem;

      pc2 = (*pos)++;
      local_tem = longest_to_int (exp->elts[pc2 + 2].longconst);
      (*pos) += 4 + BYTES_TO_EXP_ELEM (local_tem + 1);
      struct type *type = exp->elts[pc2 + 1].type;
      name = &exp->elts[pc2 + 3].string;

      function = NULL;
      function_name = NULL;
      if (type->code () == TYPE_CODE_NAMESPACE)
	{
	  function = cp_lookup_symbol_namespace (type->name (),
						 name,
						 get_selected_block (0),
						 VAR_DOMAIN).symbol;
	  if (function == NULL)
	    error (_("No symbol \"%s\" in namespace \"%s\"."),
		   name, type->name ());

	  tem = 1;
	  /* arg2 is left as NULL on purpose.  */
	}
      else
	{
	  gdb_assert (type->code () == TYPE_CODE_STRUCT
		      || type->code () == TYPE_CODE_UNION);
	  function_name = name;

	  /* We need a properly typed value for method lookup.  For
	     static methods arg2 is otherwise unused.  */
	  arg2 = value_zero (type, lval_memory);
	  ++nargs;
	  tem = 2;
	}
    }
  else if (op == OP_ADL_FUNC)
    {
      /* Save the function position and move pos so that the arguments
	 can be evaluated.  */
      int func_name_len;

      save_pos1 = *pos;
      tem = 1;

      func_name_len = longest_to_int (exp->elts[save_pos1 + 3].longconst);
      (*pos) += 6 + BYTES_TO_EXP_ELEM (func_name_len + 1);
    }
  else
    {
      /* Non-method function call.  */
      save_pos1 = *pos;
      tem = 1;

      /* If this is a C++ function wait until overload resolution.  */
      if (op == OP_VAR_VALUE
	  && overload_resolution
	  && (exp->language_defn->la_language == language_cplus))
	{
	  (*pos) += 4; /* Skip the evaluation of the symbol.  */
	  argvec[0] = NULL;
	}
      else
	{
	  if (op == OP_VAR_MSYM_VALUE)
	    {
	      minimal_symbol *msym = exp->elts[*pos + 2].msymbol;
	      var_func_name = msym->print_name ();
	    }
	  else if (op == OP_VAR_VALUE)
	    {
	      symbol *sym = exp->elts[*pos + 2].symbol;
	      var_func_name = sym->print_name ();
	    }

	  argvec[0] = evaluate_subexp_with_coercion (exp, pos, noside);
	  type *type = value_type (argvec[0]);
	  if (type && type->code () == TYPE_CODE_PTR)
	    type = TYPE_TARGET_TYPE (type);
	  if (type && type->code () == TYPE_CODE_FUNC)
	    {
	      for (; tem <= nargs && tem <= type->num_fields (); tem++)
		{
		  argvec[tem] = evaluate_subexp (type->field (tem - 1).type (),
						 exp, pos, noside);
		}
	    }
	}
    }

  /* Evaluate arguments (if not already done, e.g., namespace::func()
     and overload-resolution is off).  */
  for (; tem <= nargs; tem++)
    {
      /* Ensure that array expressions are coerced into pointer
	 objects.  */
      argvec[tem] = evaluate_subexp_with_coercion (exp, pos, noside);
    }

  /* Signal end of arglist.  */
  argvec[tem] = 0;

  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);

  if (op == OP_ADL_FUNC)
    {
      struct symbol *symp;
      char *func_name;
      int  name_len;
      int string_pc = save_pos1 + 3;

      /* Extract the function name.  */
      name_len = longest_to_int (exp->elts[string_pc].longconst);
      func_name = (char *) alloca (name_len + 1);
      strcpy (func_name, &exp->elts[string_pc + 1].string);

      find_overload_match (gdb::make_array_view (&argvec[1], nargs),
			   func_name,
			   NON_METHOD, /* not method */
			   NULL, NULL, /* pass NULL symbol since
					  symbol is unknown */
			   NULL, &symp, NULL, 0, noside);

      /* Now fix the expression being evaluated.  */
      exp->elts[save_pos1 + 2].symbol = symp;
      argvec[0] = evaluate_subexp_with_coercion (exp, &save_pos1, noside);
    }

  if (op == STRUCTOP_STRUCT || op == STRUCTOP_PTR
      || (op == OP_SCOPE && function_name != NULL))
    {
      int static_memfuncp;
      char *tstr;

      /* Method invocation: stuff "this" as first parameter.  If the
	 method turns out to be static we undo this below.  */
      argvec[1] = arg2;

      if (op != OP_SCOPE)
	{
	  /* Name of method from expression.  */
	  tstr = &exp->elts[pc2 + 2].string;
	}
      else
	tstr = function_name;

      if (overload_resolution && (exp->language_defn->la_language
				  == language_cplus))
	{
	  /* Language is C++, do some overload resolution before
	     evaluation.  */
	  struct value *valp = NULL;

	  (void) find_overload_match (gdb::make_array_view (&argvec[1], nargs),
				      tstr,
				      METHOD, /* method */
				      &arg2,  /* the object */
				      NULL, &valp, NULL,
				      &static_memfuncp, 0, noside);

	  if (op == OP_SCOPE && !static_memfuncp)
	    {
	      /* For the time being, we don't handle this.  */
	      error (_("Call to overloaded function %s requires "
		       "`this' pointer"),
		     function_name);
	    }
	  argvec[1] = arg2;	/* the ``this'' pointer */
	  argvec[0] = valp;	/* Use the method found after overload
				   resolution.  */
	}
      else
	/* Non-C++ case -- or no overload resolution.  */
	{
	  struct value *temp = arg2;

	  argvec[0] = value_struct_elt (&temp, argvec + 1, tstr,
					&static_memfuncp,
					op == STRUCTOP_STRUCT
					? "structure" : "structure pointer");
	  /* value_struct_elt updates temp with the correct value of
	     the ``this'' pointer if necessary, so modify argvec[1] to
	     reflect any ``this'' changes.  */
	  arg2
	    = value_from_longest (lookup_pointer_type(value_type (temp)),
				  value_address (temp)
				  + value_embedded_offset (temp));
	  argvec[1] = arg2;	/* the ``this'' pointer */
	}

      /* Take out `this' if needed.  */
      if (static_memfuncp)
	{
	  argvec[1] = argvec[0];
	  nargs--;
	  argvec++;
	}
    }
  else if (op == STRUCTOP_MEMBER || op == STRUCTOP_MPTR)
    {
      /* Pointer to member.  argvec[1] is already set up.  */
      argvec[0] = arg1;
    }
  else if (op == OP_VAR_VALUE || (op == OP_SCOPE && function != NULL))
    {
      /* Non-member function being called.  */
      /* fn: This can only be done for C++ functions.  A C-style
	 function in a C++ program, for instance, does not have the
	 fields that are expected here.  */

      if (overload_resolution && (exp->language_defn->la_language
				  == language_cplus))
	{
	  /* Language is C++, do some overload resolution before
	     evaluation.  */
	  struct symbol *symp;
	  int no_adl = 0;

	  /* If a scope has been specified disable ADL.  */
	  if (op == OP_SCOPE)
	    no_adl = 1;

	  if (op == OP_VAR_VALUE)
	    function = exp->elts[save_pos1+2].symbol;

	  (void) find_overload_match (gdb::make_array_view (&argvec[1], nargs),
				      NULL,        /* no need for name */
				      NON_METHOD,  /* not method */
				      NULL, function, /* the function */
				      NULL, &symp, NULL, no_adl, noside);

	  if (op == OP_VAR_VALUE)
	    {
	      /* Now fix the expression being evaluated.  */
	      exp->elts[save_pos1+2].symbol = symp;
	      argvec[0] = evaluate_subexp_with_coercion (exp, &save_pos1,
							 noside);
	    }
	  else
	    argvec[0] = value_of_variable (symp, get_selected_block (0));
	}
      else
	{
	  /* Not C++, or no overload resolution allowed.  */
	  /* Nothing to be done; argvec already correctly set up.  */
	}
    }
  else
    {
      /* It is probably a C-style function.  */
      /* Nothing to be done; argvec already correctly set up.  */
    }

  return evaluate_subexp_do_call (exp, noside, argvec[0],
				  gdb::make_array_view (argvec + 1, nargs),
				  var_func_name, expect_type);
}

/* Return true if type is integral or reference to integral */

static bool
is_integral_or_integral_reference (struct type *type)
{
  if (is_integral_type (type))
    return true;

  type = check_typedef (type);
  return (type != nullptr
	  && TYPE_IS_REFERENCE (type)
	  && is_integral_type (TYPE_TARGET_TYPE (type)));
}

/* Helper function that implements the body of OP_SCOPE.  */

struct value *
eval_op_scope (struct type *expect_type, struct expression *exp,
	       enum noside noside,
	       struct type *type, const char *string)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  struct value *arg1 = value_aggregate_elt (type, string, expect_type,
					    0, noside);
  if (arg1 == NULL)
    error (_("There is no field named %s"), string);
  return arg1;
}

/* Helper function that implements the body of OP_VAR_ENTRY_VALUE.  */

struct value *
eval_op_var_entry_value (struct type *expect_type, struct expression *exp,
			 enum noside noside, symbol *sym)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    return value_zero (SYMBOL_TYPE (sym), not_lval);

  if (SYMBOL_COMPUTED_OPS (sym) == NULL
      || SYMBOL_COMPUTED_OPS (sym)->read_variable_at_entry == NULL)
    error (_("Symbol \"%s\" does not have any specific entry value"),
	   sym->print_name ());

  struct frame_info *frame = get_selected_frame (NULL);
  return SYMBOL_COMPUTED_OPS (sym)->read_variable_at_entry (sym, frame);
}

/* Helper function that implements the body of OP_VAR_MSYM_VALUE.  */

struct value *
eval_op_var_msym_value (struct type *expect_type, struct expression *exp,
			enum noside noside, bool outermost_p,
			minimal_symbol *msymbol, struct objfile *objfile)
{
  value *val = evaluate_var_msym_value (noside, objfile, msymbol);

  struct type *type = value_type (val);
  if (type->code () == TYPE_CODE_ERROR
      && (noside != EVAL_AVOID_SIDE_EFFECTS || !outermost_p))
    error_unknown_type (msymbol->print_name ());
  return val;
}

/* Helper function that implements the body of OP_FUNC_STATIC_VAR.  */

struct value *
eval_op_func_static_var (struct type *expect_type, struct expression *exp,
			 enum noside noside,
			 value *func, const char *var)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  CORE_ADDR addr = value_address (func);
  const block *blk = block_for_pc (addr);
  struct block_symbol sym = lookup_symbol (var, blk, VAR_DOMAIN, NULL);
  if (sym.symbol == NULL)
    error (_("No symbol \"%s\" in specified context."), var);
  return evaluate_var_value (noside, sym.block, sym.symbol);
}

/* Helper function that implements the body of OP_REGISTER.  */

struct value *
eval_op_register (struct type *expect_type, struct expression *exp,
		  enum noside noside, const char *name)
{
  int regno;
  struct value *val;

  regno = user_reg_map_name_to_regnum (exp->gdbarch,
				       name, strlen (name));
  if (regno == -1)
    error (_("Register $%s not available."), name);

  /* In EVAL_AVOID_SIDE_EFFECTS mode, we only need to return
     a value with the appropriate register type.  Unfortunately,
     we don't have easy access to the type of user registers.
     So for these registers, we fetch the register value regardless
     of the evaluation mode.  */
  if (noside == EVAL_AVOID_SIDE_EFFECTS
      && regno < gdbarch_num_cooked_regs (exp->gdbarch))
    val = value_zero (register_type (exp->gdbarch, regno), not_lval);
  else
    val = value_of_register (regno, get_selected_frame (NULL));
  if (val == NULL)
    error (_("Value of register %s not available."), name);
  else
    return val;
}

/* Helper function that implements the body of OP_STRING.  */

struct value *
eval_op_string (struct type *expect_type, struct expression *exp,
		enum noside noside, int len, const char *string)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  struct type *type = language_string_char_type (exp->language_defn,
						 exp->gdbarch);
  return value_string (string, len, type);
}

/* Helper function that implements the body of OP_OBJC_SELECTOR.  */

struct value *
eval_op_objc_selector (struct type *expect_type, struct expression *exp,
		       enum noside noside,
		       const char *sel)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);

  struct type *selector_type = builtin_type (exp->gdbarch)->builtin_data_ptr;
  return value_from_longest (selector_type,
			     lookup_child_selector (exp->gdbarch, sel));
}

/* Helper function that implements the body of BINOP_CONCAT.  */

struct value *
eval_op_concat (struct type *expect_type, struct expression *exp,
		enum noside noside, struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (BINOP_CONCAT, arg1, arg2))
    return value_x_binop (arg1, arg2, BINOP_CONCAT, OP_NULL, noside);
  else
    return value_concat (arg1, arg2);
}

/* A helper function for TERNOP_SLICE.  */

struct value *
eval_op_ternop (struct type *expect_type, struct expression *exp,
		enum noside noside,
		struct value *array, struct value *low, struct value *upper)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  int lowbound = value_as_long (low);
  int upperbound = value_as_long (upper);
  return value_slice (array, lowbound, upperbound - lowbound + 1);
}

/* A helper function for STRUCTOP_STRUCT.  */

struct value *
eval_op_structop_struct (struct type *expect_type, struct expression *exp,
			 enum noside noside,
			 struct value *arg1, const char *string)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  struct value *arg3 = value_struct_elt (&arg1, NULL, string,
					 NULL, "structure");
  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    arg3 = value_zero (value_type (arg3), VALUE_LVAL (arg3));
  return arg3;
}

/* A helper function for STRUCTOP_PTR.  */

struct value *
eval_op_structop_ptr (struct type *expect_type, struct expression *exp,
		      enum noside noside,
		      struct value *arg1, const char *string)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);

  /* Check to see if operator '->' has been overloaded.  If so replace
     arg1 with the value returned by evaluating operator->().  */
  while (unop_user_defined_p (STRUCTOP_PTR, arg1))
    {
      struct value *value = NULL;
      try
	{
	  value = value_x_unop (arg1, STRUCTOP_PTR, noside);
	}

      catch (const gdb_exception_error &except)
	{
	  if (except.error == NOT_FOUND_ERROR)
	    break;
	  else
	    throw;
	}

      arg1 = value;
    }

  /* JYG: if print object is on we need to replace the base type
     with rtti type in order to continue on with successful
     lookup of member / method only available in the rtti type.  */
  {
    struct type *arg_type = value_type (arg1);
    struct type *real_type;
    int full, using_enc;
    LONGEST top;
    struct value_print_options opts;

    get_user_print_options (&opts);
    if (opts.objectprint && TYPE_TARGET_TYPE (arg_type)
	&& (TYPE_TARGET_TYPE (arg_type)->code () == TYPE_CODE_STRUCT))
      {
	real_type = value_rtti_indirect_type (arg1, &full, &top,
					      &using_enc);
	if (real_type)
	  arg1 = value_cast (real_type, arg1);
      }
  }

  struct value *arg3 = value_struct_elt (&arg1, NULL, string,
					 NULL, "structure pointer");
  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    arg3 = value_zero (value_type (arg3), VALUE_LVAL (arg3));
  return arg3;
}

/* A helper function for STRUCTOP_MEMBER.  */

struct value *
eval_op_member (struct type *expect_type, struct expression *exp,
		enum noside noside,
		struct value *arg1, struct value *arg2)
{
  long mem_offset;

  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);

  struct value *arg3;
  struct type *type = check_typedef (value_type (arg2));
  switch (type->code ())
    {
    case TYPE_CODE_METHODPTR:
      if (noside == EVAL_AVOID_SIDE_EFFECTS)
	return value_zero (TYPE_TARGET_TYPE (type), not_lval);
      else
	{
	  arg2 = cplus_method_ptr_to_value (&arg1, arg2);
	  gdb_assert (value_type (arg2)->code () == TYPE_CODE_PTR);
	  return value_ind (arg2);
	}

    case TYPE_CODE_MEMBERPTR:
      /* Now, convert these values to an address.  */
      arg1 = value_cast_pointers (lookup_pointer_type (TYPE_SELF_TYPE (type)),
				  arg1, 1);

      mem_offset = value_as_long (arg2);

      arg3 = value_from_pointer (lookup_pointer_type (TYPE_TARGET_TYPE (type)),
				 value_as_long (arg1) + mem_offset);
      return value_ind (arg3);

    default:
      error (_("non-pointer-to-member value used "
	       "in pointer-to-member construct"));
    }
}

/* A helper function for BINOP_ADD.  */

struct value *
eval_op_add (struct type *expect_type, struct expression *exp,
	     enum noside noside,
	     struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (BINOP_ADD, arg1, arg2))
    return value_x_binop (arg1, arg2, BINOP_ADD, OP_NULL, noside);
  else if (ptrmath_type_p (exp->language_defn, value_type (arg1))
	   && is_integral_or_integral_reference (value_type (arg2)))
    return value_ptradd (arg1, value_as_long (arg2));
  else if (ptrmath_type_p (exp->language_defn, value_type (arg2))
	   && is_integral_or_integral_reference (value_type (arg1)))
    return value_ptradd (arg2, value_as_long (arg1));
  else
    {
      binop_promote (exp->language_defn, exp->gdbarch, &arg1, &arg2);
      return value_binop (arg1, arg2, BINOP_ADD);
    }
}

/* A helper function for BINOP_SUB.  */

struct value *
eval_op_sub (struct type *expect_type, struct expression *exp,
	     enum noside noside,
	     struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (BINOP_SUB, arg1, arg2))
    return value_x_binop (arg1, arg2, BINOP_SUB, OP_NULL, noside);
  else if (ptrmath_type_p (exp->language_defn, value_type (arg1))
	   && ptrmath_type_p (exp->language_defn, value_type (arg2)))
    {
      /* FIXME -- should be ptrdiff_t */
      struct type *type = builtin_type (exp->gdbarch)->builtin_long;
      return value_from_longest (type, value_ptrdiff (arg1, arg2));
    }
  else if (ptrmath_type_p (exp->language_defn, value_type (arg1))
	   && is_integral_or_integral_reference (value_type (arg2)))
    return value_ptradd (arg1, - value_as_long (arg2));
  else
    {
      binop_promote (exp->language_defn, exp->gdbarch, &arg1, &arg2);
      return value_binop (arg1, arg2, BINOP_SUB);
    }
}

/* Helper function for several different binary operations.  */

struct value *
eval_op_binary (struct type *expect_type, struct expression *exp,
		enum noside noside, enum exp_opcode op,
		struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (op, arg1, arg2))
    return value_x_binop (arg1, arg2, op, OP_NULL, noside);
  else
    {
      /* If EVAL_AVOID_SIDE_EFFECTS and we're dividing by zero,
	 fudge arg2 to avoid division-by-zero, the caller is
	 (theoretically) only looking for the type of the result.  */
      if (noside == EVAL_AVOID_SIDE_EFFECTS
	  /* ??? Do we really want to test for BINOP_MOD here?
	     The implementation of value_binop gives it a well-defined
	     value.  */
	  && (op == BINOP_DIV
	      || op == BINOP_INTDIV
	      || op == BINOP_REM
	      || op == BINOP_MOD)
	  && value_logical_not (arg2))
	{
	  struct value *v_one;

	  v_one = value_one (value_type (arg2));
	  binop_promote (exp->language_defn, exp->gdbarch, &arg1, &v_one);
	  return value_binop (arg1, v_one, op);
	}
      else
	{
	  /* For shift and integer exponentiation operations,
	     only promote the first argument.  */
	  if ((op == BINOP_LSH || op == BINOP_RSH || op == BINOP_EXP)
	      && is_integral_type (value_type (arg2)))
	    unop_promote (exp->language_defn, exp->gdbarch, &arg1);
	  else
	    binop_promote (exp->language_defn, exp->gdbarch, &arg1, &arg2);

	  return value_binop (arg1, arg2, op);
	}
    }
}

/* A helper function for BINOP_SUBSCRIPT.  */

struct value *
eval_op_subscript (struct type *expect_type, struct expression *exp,
		   enum noside noside, enum exp_opcode op,
		   struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (op, arg1, arg2))
    return value_x_binop (arg1, arg2, op, OP_NULL, noside);
  else
    {
      /* If the user attempts to subscript something that is not an
	 array or pointer type (like a plain int variable for example),
	 then report this as an error.  */

      arg1 = coerce_ref (arg1);
      struct type *type = check_typedef (value_type (arg1));
      if (type->code () != TYPE_CODE_ARRAY
	  && type->code () != TYPE_CODE_PTR)
	{
	  if (type->name ())
	    error (_("cannot subscript something of type `%s'"),
		   type->name ());
	  else
	    error (_("cannot subscript requested type"));
	}

      if (noside == EVAL_AVOID_SIDE_EFFECTS)
	return value_zero (TYPE_TARGET_TYPE (type), VALUE_LVAL (arg1));
      else
	return value_subscript (arg1, value_as_long (arg2));
    }
}

/* A helper function for BINOP_EQUAL.  */

struct value *
eval_op_equal (struct type *expect_type, struct expression *exp,
	       enum noside noside, enum exp_opcode op,
	       struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (op, arg1, arg2))
    {
      return value_x_binop (arg1, arg2, op, OP_NULL, noside);
    }
  else
    {
      binop_promote (exp->language_defn, exp->gdbarch, &arg1, &arg2);
      int tem = value_equal (arg1, arg2);
      struct type *type = language_bool_type (exp->language_defn,
					      exp->gdbarch);
      return value_from_longest (type, (LONGEST) tem);
    }
}

/* A helper function for BINOP_NOTEQUAL.  */

struct value *
eval_op_notequal (struct type *expect_type, struct expression *exp,
		  enum noside noside, enum exp_opcode op,
		  struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (op, arg1, arg2))
    {
      return value_x_binop (arg1, arg2, op, OP_NULL, noside);
    }
  else
    {
      binop_promote (exp->language_defn, exp->gdbarch, &arg1, &arg2);
      int tem = value_equal (arg1, arg2);
      struct type *type = language_bool_type (exp->language_defn,
					      exp->gdbarch);
      return value_from_longest (type, (LONGEST) ! tem);
    }
}

/* A helper function for BINOP_LESS.  */

struct value *
eval_op_less (struct type *expect_type, struct expression *exp,
	      enum noside noside, enum exp_opcode op,
	      struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (op, arg1, arg2))
    {
      return value_x_binop (arg1, arg2, op, OP_NULL, noside);
    }
  else
    {
      binop_promote (exp->language_defn, exp->gdbarch, &arg1, &arg2);
      int tem = value_less (arg1, arg2);
      struct type *type = language_bool_type (exp->language_defn,
					      exp->gdbarch);
      return value_from_longest (type, (LONGEST) tem);
    }
}

/* A helper function for BINOP_GTR.  */

struct value *
eval_op_gtr (struct type *expect_type, struct expression *exp,
	     enum noside noside, enum exp_opcode op,
	     struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (op, arg1, arg2))
    {
      return value_x_binop (arg1, arg2, op, OP_NULL, noside);
    }
  else
    {
      binop_promote (exp->language_defn, exp->gdbarch, &arg1, &arg2);
      int tem = value_less (arg2, arg1);
      struct type *type = language_bool_type (exp->language_defn,
					      exp->gdbarch);
      return value_from_longest (type, (LONGEST) tem);
    }
}

/* A helper function for BINOP_GEQ.  */

struct value *
eval_op_geq (struct type *expect_type, struct expression *exp,
	     enum noside noside, enum exp_opcode op,
	     struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (op, arg1, arg2))
    {
      return value_x_binop (arg1, arg2, op, OP_NULL, noside);
    }
  else
    {
      binop_promote (exp->language_defn, exp->gdbarch, &arg1, &arg2);
      int tem = value_less (arg2, arg1) || value_equal (arg1, arg2);
      struct type *type = language_bool_type (exp->language_defn,
					      exp->gdbarch);
      return value_from_longest (type, (LONGEST) tem);
    }
}

/* A helper function for BINOP_LEQ.  */

struct value *
eval_op_leq (struct type *expect_type, struct expression *exp,
	     enum noside noside, enum exp_opcode op,
	     struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (binop_user_defined_p (op, arg1, arg2))
    {
      return value_x_binop (arg1, arg2, op, OP_NULL, noside);
    }
  else
    {
      binop_promote (exp->language_defn, exp->gdbarch, &arg1, &arg2);
      int tem = value_less (arg1, arg2) || value_equal (arg1, arg2);
      struct type *type = language_bool_type (exp->language_defn,
					      exp->gdbarch);
      return value_from_longest (type, (LONGEST) tem);
    }
}

/* A helper function for BINOP_REPEAT.  */

struct value *
eval_op_repeat (struct type *expect_type, struct expression *exp,
		enum noside noside, enum exp_opcode op,
		struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  struct type *type = check_typedef (value_type (arg2));
  if (type->code () != TYPE_CODE_INT
      && type->code () != TYPE_CODE_ENUM)
    error (_("Non-integral right operand for \"@\" operator."));
  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    {
      return allocate_repeat_value (value_type (arg1),
				    longest_to_int (value_as_long (arg2)));
    }
  else
    return value_repeat (arg1, longest_to_int (value_as_long (arg2)));
}

/* A helper function for UNOP_PLUS.  */

struct value *
eval_op_plus (struct type *expect_type, struct expression *exp,
	      enum noside noside, enum exp_opcode op,
	      struct value *arg1)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (unop_user_defined_p (op, arg1))
    return value_x_unop (arg1, op, noside);
  else
    {
      unop_promote (exp->language_defn, exp->gdbarch, &arg1);
      return value_pos (arg1);
    }
}

/* A helper function for UNOP_NEG.  */

struct value *
eval_op_neg (struct type *expect_type, struct expression *exp,
	     enum noside noside, enum exp_opcode op,
	     struct value *arg1)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (unop_user_defined_p (op, arg1))
    return value_x_unop (arg1, op, noside);
  else
    {
      unop_promote (exp->language_defn, exp->gdbarch, &arg1);
      return value_neg (arg1);
    }
}

/* A helper function for UNOP_COMPLEMENT.  */

struct value *
eval_op_complement (struct type *expect_type, struct expression *exp,
		    enum noside noside, enum exp_opcode op,
		    struct value *arg1)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (unop_user_defined_p (UNOP_COMPLEMENT, arg1))
    return value_x_unop (arg1, UNOP_COMPLEMENT, noside);
  else
    {
      unop_promote (exp->language_defn, exp->gdbarch, &arg1);
      return value_complement (arg1);
    }
}

/* A helper function for UNOP_LOGICAL_NOT.  */

struct value *
eval_op_lognot (struct type *expect_type, struct expression *exp,
		enum noside noside, enum exp_opcode op,
		struct value *arg1)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (unop_user_defined_p (op, arg1))
    return value_x_unop (arg1, op, noside);
  else
    {
      struct type *type = language_bool_type (exp->language_defn,
					      exp->gdbarch);
      return value_from_longest (type, (LONGEST) value_logical_not (arg1));
    }
}

/* A helper function for UNOP_IND.  */

struct value *
eval_op_ind (struct type *expect_type, struct expression *exp,
	     enum noside noside,
	     struct value *arg1)
{
  struct type *type = check_typedef (value_type (arg1));
  if (type->code () == TYPE_CODE_METHODPTR
      || type->code () == TYPE_CODE_MEMBERPTR)
    error (_("Attempt to dereference pointer "
	     "to member without an object"));
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (unop_user_defined_p (UNOP_IND, arg1))
    return value_x_unop (arg1, UNOP_IND, noside);
  else if (noside == EVAL_AVOID_SIDE_EFFECTS)
    {
      type = check_typedef (value_type (arg1));

      /* If the type pointed to is dynamic then in order to resolve the
	 dynamic properties we must actually dereference the pointer.
	 There is a risk that this dereference will have side-effects
	 in the inferior, but being able to print accurate type
	 information seems worth the risk. */
      if ((type->code () != TYPE_CODE_PTR
	   && !TYPE_IS_REFERENCE (type))
	  || !is_dynamic_type (TYPE_TARGET_TYPE (type)))
	{
	  if (type->code () == TYPE_CODE_PTR
	      || TYPE_IS_REFERENCE (type)
	      /* In C you can dereference an array to get the 1st elt.  */
	      || type->code () == TYPE_CODE_ARRAY)
	    return value_zero (TYPE_TARGET_TYPE (type),
			       lval_memory);
	  else if (type->code () == TYPE_CODE_INT)
	    /* GDB allows dereferencing an int.  */
	    return value_zero (builtin_type (exp->gdbarch)->builtin_int,
			       lval_memory);
	  else
	    error (_("Attempt to take contents of a non-pointer value."));
	}
    }

  /* Allow * on an integer so we can cast it to whatever we want.
     This returns an int, which seems like the most C-like thing to
     do.  "long long" variables are rare enough that
     BUILTIN_TYPE_LONGEST would seem to be a mistake.  */
  if (type->code () == TYPE_CODE_INT)
    return value_at_lazy (builtin_type (exp->gdbarch)->builtin_int,
			  (CORE_ADDR) value_as_address (arg1));
  return value_ind (arg1);
}

/* A helper function for UNOP_ALIGNOF.  */

struct value *
eval_op_alignof (struct type *expect_type, struct expression *exp,
		 enum noside noside,
		 struct value *arg1)
{
  struct type *type = value_type (arg1);
  /* FIXME: This should be size_t.  */
  struct type *size_type = builtin_type (exp->gdbarch)->builtin_int;
  ULONGEST align = type_align (type);
  if (align == 0)
    error (_("could not determine alignment of type"));
  return value_from_longest (size_type, align);
}

/* A helper function for UNOP_MEMVAL.  */

struct value *
eval_op_memval (struct type *expect_type, struct expression *exp,
		enum noside noside,
		struct value *arg1, struct type *type)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    return value_zero (type, lval_memory);
  else
    return value_at_lazy (type, value_as_address (arg1));
}

/* A helper function for UNOP_PREINCREMENT.  */

struct value *
eval_op_preinc (struct type *expect_type, struct expression *exp,
		enum noside noside, enum exp_opcode op,
		struct value *arg1)
{
  if (noside == EVAL_SKIP || noside == EVAL_AVOID_SIDE_EFFECTS)
    return arg1;
  else if (unop_user_defined_p (op, arg1))
    {
      return value_x_unop (arg1, op, noside);
    }
  else
    {
      struct value *arg2;
      if (ptrmath_type_p (exp->language_defn, value_type (arg1)))
	arg2 = value_ptradd (arg1, 1);
      else
	{
	  struct value *tmp = arg1;

	  arg2 = value_one (value_type (arg1));
	  binop_promote (exp->language_defn, exp->gdbarch, &tmp, &arg2);
	  arg2 = value_binop (tmp, arg2, BINOP_ADD);
	}

      return value_assign (arg1, arg2);
    }
}

/* A helper function for UNOP_PREDECREMENT.  */

struct value *
eval_op_predec (struct type *expect_type, struct expression *exp,
		enum noside noside, enum exp_opcode op,
		struct value *arg1)
{
  if (noside == EVAL_SKIP || noside == EVAL_AVOID_SIDE_EFFECTS)
    return arg1;
  else if (unop_user_defined_p (op, arg1))
    {
      return value_x_unop (arg1, op, noside);
    }
  else
    {
      struct value *arg2;
      if (ptrmath_type_p (exp->language_defn, value_type (arg1)))
	arg2 = value_ptradd (arg1, -1);
      else
	{
	  struct value *tmp = arg1;

	  arg2 = value_one (value_type (arg1));
	  binop_promote (exp->language_defn, exp->gdbarch, &tmp, &arg2);
	  arg2 = value_binop (tmp, arg2, BINOP_SUB);
	}

      return value_assign (arg1, arg2);
    }
}

/* A helper function for UNOP_POSTINCREMENT.  */

struct value *
eval_op_postinc (struct type *expect_type, struct expression *exp,
		 enum noside noside, enum exp_opcode op,
		 struct value *arg1)
{
  if (noside == EVAL_SKIP || noside == EVAL_AVOID_SIDE_EFFECTS)
    return arg1;
  else if (unop_user_defined_p (op, arg1))
    {
      return value_x_unop (arg1, op, noside);
    }
  else
    {
      struct value *arg3 = value_non_lval (arg1);
      struct value *arg2;

      if (ptrmath_type_p (exp->language_defn, value_type (arg1)))
	arg2 = value_ptradd (arg1, 1);
      else
	{
	  struct value *tmp = arg1;

	  arg2 = value_one (value_type (arg1));
	  binop_promote (exp->language_defn, exp->gdbarch, &tmp, &arg2);
	  arg2 = value_binop (tmp, arg2, BINOP_ADD);
	}

      value_assign (arg1, arg2);
      return arg3;
    }
}

/* A helper function for UNOP_POSTDECREMENT.  */

struct value *
eval_op_postdec (struct type *expect_type, struct expression *exp,
		 enum noside noside, enum exp_opcode op,
		 struct value *arg1)
{
  if (noside == EVAL_SKIP || noside == EVAL_AVOID_SIDE_EFFECTS)
    return arg1;
  else if (unop_user_defined_p (op, arg1))
    {
      return value_x_unop (arg1, op, noside);
    }
  else
    {
      struct value *arg3 = value_non_lval (arg1);
      struct value *arg2;

      if (ptrmath_type_p (exp->language_defn, value_type (arg1)))
	arg2 = value_ptradd (arg1, -1);
      else
	{
	  struct value *tmp = arg1;

	  arg2 = value_one (value_type (arg1));
	  binop_promote (exp->language_defn, exp->gdbarch, &tmp, &arg2);
	  arg2 = value_binop (tmp, arg2, BINOP_SUB);
	}

      value_assign (arg1, arg2);
      return arg3;
    }
}

/* A helper function for OP_TYPE.  */

struct value *
eval_op_type (struct type *expect_type, struct expression *exp,
	      enum noside noside, struct type *type)
{
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  else if (noside == EVAL_AVOID_SIDE_EFFECTS)
    return allocate_value (type);
  else
    error (_("Attempt to use a type name as an expression"));
}

/* A helper function for BINOP_ASSIGN_MODIFY.  */

struct value *
eval_binop_assign_modify (struct type *expect_type, struct expression *exp,
			  enum noside noside, enum exp_opcode op,
			  struct value *arg1, struct value *arg2)
{
  if (noside == EVAL_SKIP || noside == EVAL_AVOID_SIDE_EFFECTS)
    return arg1;
  if (binop_user_defined_p (op, arg1, arg2))
    return value_x_binop (arg1, arg2, BINOP_ASSIGN_MODIFY, op, noside);
  else if (op == BINOP_ADD && ptrmath_type_p (exp->language_defn,
					      value_type (arg1))
	   && is_integral_type (value_type (arg2)))
    arg2 = value_ptradd (arg1, value_as_long (arg2));
  else if (op == BINOP_SUB && ptrmath_type_p (exp->language_defn,
					      value_type (arg1))
	   && is_integral_type (value_type (arg2)))
    arg2 = value_ptradd (arg1, - value_as_long (arg2));
  else
    {
      struct value *tmp = arg1;

      /* For shift and integer exponentiation operations,
	 only promote the first argument.  */
      if ((op == BINOP_LSH || op == BINOP_RSH || op == BINOP_EXP)
	  && is_integral_type (value_type (arg2)))
	unop_promote (exp->language_defn, exp->gdbarch, &tmp);
      else
	binop_promote (exp->language_defn, exp->gdbarch, &tmp, &arg2);

      arg2 = value_binop (tmp, arg2, op);
    }
  return value_assign (arg1, arg2);
}

/* Note that ARGS needs 2 empty slots up front and must end with a
   null pointer.  */
static struct value *
eval_op_objc_msgcall (struct type *expect_type, struct expression *exp,
		      enum noside noside, CORE_ADDR selector,
		      value *target, gdb::array_view<value *> args)
{
  CORE_ADDR responds_selector = 0;
  CORE_ADDR method_selector = 0;

  int struct_return = 0;

  struct value *msg_send = NULL;
  struct value *msg_send_stret = NULL;
  int gnu_runtime = 0;

  struct value *method = NULL;
  struct value *called_method = NULL;

  struct type *selector_type = NULL;
  struct type *long_type;
  struct type *type;

  struct value *ret = NULL;
  CORE_ADDR addr = 0;

  value *argvec[5];

  long_type = builtin_type (exp->gdbarch)->builtin_long;
  selector_type = builtin_type (exp->gdbarch)->builtin_data_ptr;

  if (value_as_long (target) == 0)
    return value_from_longest (long_type, 0);

  if (lookup_minimal_symbol ("objc_msg_lookup", 0, 0).minsym)
    gnu_runtime = 1;

  /* Find the method dispatch (Apple runtime) or method lookup
     (GNU runtime) function for Objective-C.  These will be used
     to lookup the symbol information for the method.  If we
     can't find any symbol information, then we'll use these to
     call the method, otherwise we can call the method
     directly.  The msg_send_stret function is used in the special
     case of a method that returns a structure (Apple runtime
     only).  */
  if (gnu_runtime)
    {
      type = selector_type;

      type = lookup_function_type (type);
      type = lookup_pointer_type (type);
      type = lookup_function_type (type);
      type = lookup_pointer_type (type);

      msg_send = find_function_in_inferior ("objc_msg_lookup", NULL);
      msg_send_stret
	= find_function_in_inferior ("objc_msg_lookup", NULL);

      msg_send = value_from_pointer (type, value_as_address (msg_send));
      msg_send_stret = value_from_pointer (type,
					   value_as_address (msg_send_stret));
    }
  else
    {
      msg_send = find_function_in_inferior ("objc_msgSend", NULL);
      /* Special dispatcher for methods returning structs.  */
      msg_send_stret
	= find_function_in_inferior ("objc_msgSend_stret", NULL);
    }

  /* Verify the target object responds to this method.  The
     standard top-level 'Object' class uses a different name for
     the verification method than the non-standard, but more
     often used, 'NSObject' class.  Make sure we check for both.  */

  responds_selector
    = lookup_child_selector (exp->gdbarch, "respondsToSelector:");
  if (responds_selector == 0)
    responds_selector
      = lookup_child_selector (exp->gdbarch, "respondsTo:");

  if (responds_selector == 0)
    error (_("no 'respondsTo:' or 'respondsToSelector:' method"));

  method_selector
    = lookup_child_selector (exp->gdbarch, "methodForSelector:");
  if (method_selector == 0)
    method_selector
      = lookup_child_selector (exp->gdbarch, "methodFor:");

  if (method_selector == 0)
    error (_("no 'methodFor:' or 'methodForSelector:' method"));

  /* Call the verification method, to make sure that the target
     class implements the desired method.  */

  argvec[0] = msg_send;
  argvec[1] = target;
  argvec[2] = value_from_longest (long_type, responds_selector);
  argvec[3] = value_from_longest (long_type, selector);
  argvec[4] = 0;

  ret = call_function_by_hand (argvec[0], NULL, {argvec + 1, 3});
  if (gnu_runtime)
    {
      /* Function objc_msg_lookup returns a pointer.  */
      argvec[0] = ret;
      ret = call_function_by_hand (argvec[0], NULL, {argvec + 1, 3});
    }
  if (value_as_long (ret) == 0)
    error (_("Target does not respond to this message selector."));

  /* Call "methodForSelector:" method, to get the address of a
     function method that implements this selector for this
     class.  If we can find a symbol at that address, then we
     know the return type, parameter types etc.  (that's a good
     thing).  */

  argvec[0] = msg_send;
  argvec[1] = target;
  argvec[2] = value_from_longest (long_type, method_selector);
  argvec[3] = value_from_longest (long_type, selector);
  argvec[4] = 0;

  ret = call_function_by_hand (argvec[0], NULL, {argvec + 1, 3});
  if (gnu_runtime)
    {
      argvec[0] = ret;
      ret = call_function_by_hand (argvec[0], NULL, {argvec + 1, 3});
    }

  /* ret should now be the selector.  */

  addr = value_as_long (ret);
  if (addr)
    {
      struct symbol *sym = NULL;

      /* The address might point to a function descriptor;
	 resolve it to the actual code address instead.  */
      addr = gdbarch_convert_from_func_ptr_addr (exp->gdbarch, addr,
						 current_top_target ());

      /* Is it a high_level symbol?  */
      sym = find_pc_function (addr);
      if (sym != NULL)
	method = value_of_variable (sym, 0);
    }

  /* If we found a method with symbol information, check to see
     if it returns a struct.  Otherwise assume it doesn't.  */

  if (method)
    {
      CORE_ADDR funaddr;
      struct type *val_type;

      funaddr = find_function_addr (method, &val_type);

      block_for_pc (funaddr);

      val_type = check_typedef (val_type);

      if ((val_type == NULL)
	  || (val_type->code () == TYPE_CODE_ERROR))
	{
	  if (expect_type != NULL)
	    val_type = expect_type;
	}

      struct_return = using_struct_return (exp->gdbarch, method,
					   val_type);
    }
  else if (expect_type != NULL)
    {
      struct_return = using_struct_return (exp->gdbarch, NULL,
					   check_typedef (expect_type));
    }

  /* Found a function symbol.  Now we will substitute its
     value in place of the message dispatcher (obj_msgSend),
     so that we call the method directly instead of thru
     the dispatcher.  The main reason for doing this is that
     we can now evaluate the return value and parameter values
     according to their known data types, in case we need to
     do things like promotion, dereferencing, special handling
     of structs and doubles, etc.

     We want to use the type signature of 'method', but still
     jump to objc_msgSend() or objc_msgSend_stret() to better
     mimic the behavior of the runtime.  */

  if (method)
    {
      if (value_type (method)->code () != TYPE_CODE_FUNC)
	error (_("method address has symbol information "
		 "with non-function type; skipping"));

      /* Create a function pointer of the appropriate type, and
	 replace its value with the value of msg_send or
	 msg_send_stret.  We must use a pointer here, as
	 msg_send and msg_send_stret are of pointer type, and
	 the representation may be different on systems that use
	 function descriptors.  */
      if (struct_return)
	called_method
	  = value_from_pointer (lookup_pointer_type (value_type (method)),
				value_as_address (msg_send_stret));
      else
	called_method
	  = value_from_pointer (lookup_pointer_type (value_type (method)),
				value_as_address (msg_send));
    }
  else
    {
      if (struct_return)
	called_method = msg_send_stret;
      else
	called_method = msg_send;
    }

  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);

  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    {
      /* If the return type doesn't look like a function type,
	 call an error.  This can happen if somebody tries to
	 turn a variable into a function call.  This is here
	 because people often want to call, eg, strcmp, which
	 gdb doesn't know is a function.  If gdb isn't asked for
	 it's opinion (ie. through "whatis"), it won't offer
	 it.  */

      struct type *callee_type = value_type (called_method);

      if (callee_type && callee_type->code () == TYPE_CODE_PTR)
	callee_type = TYPE_TARGET_TYPE (callee_type);
      callee_type = TYPE_TARGET_TYPE (callee_type);

      if (callee_type)
	{
	  if ((callee_type->code () == TYPE_CODE_ERROR) && expect_type)
	    return allocate_value (expect_type);
	  else
	    return allocate_value (callee_type);
	}
      else
	error (_("Expression of type other than "
		 "\"method returning ...\" used as a method"));
    }

  /* Now depending on whether we found a symbol for the method,
     we will either call the runtime dispatcher or the method
     directly.  */

  args[0] = target;
  args[1] = value_from_longest (long_type, selector);

  if (gnu_runtime && (method != NULL))
    {
      /* Function objc_msg_lookup returns a pointer.  */
      struct type *tem_type = value_type (called_method);
      tem_type = lookup_pointer_type (lookup_function_type (tem_type));
      deprecated_set_value_type (called_method, tem_type);
      called_method = call_function_by_hand (called_method, NULL, args);
    }

  return call_function_by_hand (called_method, NULL, args);
}

/* Helper function for MULTI_SUBSCRIPT.  */

static struct value *
eval_multi_subscript (struct type *expect_type, struct expression *exp,
		      enum noside noside, value *arg1,
		      gdb::array_view<value *> args)
{
  if (noside == EVAL_SKIP)
    return arg1;
  for (value *arg2 : args)
    {
      if (binop_user_defined_p (MULTI_SUBSCRIPT, arg1, arg2))
	{
	  arg1 = value_x_binop (arg1, arg2, MULTI_SUBSCRIPT, OP_NULL, noside);
	}
      else
	{
	  arg1 = coerce_ref (arg1);
	  struct type *type = check_typedef (value_type (arg1));

	  switch (type->code ())
	    {
	    case TYPE_CODE_PTR:
	    case TYPE_CODE_ARRAY:
	    case TYPE_CODE_STRING:
	      arg1 = value_subscript (arg1, value_as_long (arg2));
	      break;

	    default:
	      if (type->name ())
		error (_("cannot subscript something of type `%s'"),
		       type->name ());
	      else
		error (_("cannot subscript requested type"));
	    }
	}
    }
  return (arg1);
}

namespace expr
{

value *
objc_msgcall_operation::evaluate (struct type *expect_type,
				  struct expression *exp,
				  enum noside noside)
{
  enum noside sub_no_side = EVAL_NORMAL;
  struct type *selector_type = builtin_type (exp->gdbarch)->builtin_data_ptr;

  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    sub_no_side = EVAL_NORMAL;
  else
    sub_no_side = noside;
  value *target
    = std::get<1> (m_storage)->evaluate (selector_type, exp, sub_no_side);

  if (value_as_long (target) == 0)
    sub_no_side = EVAL_AVOID_SIDE_EFFECTS;
  else
    sub_no_side = noside;
  std::vector<operation_up> &args = std::get<2> (m_storage);
  value **argvec = XALLOCAVEC (struct value *, args.size () + 3);
  argvec[0] = nullptr;
  argvec[1] = nullptr;
  for (int i = 0; i < args.size (); ++i)
    argvec[i + 2] = args[i]->evaluate_with_coercion (exp, sub_no_side);
  argvec[args.size () + 2] = nullptr;

  return eval_op_objc_msgcall (expect_type, exp, noside, std::
			       get<0> (m_storage), target,
			       gdb::make_array_view (argvec,
						     args.size () + 3));
}

value *
multi_subscript_operation::evaluate (struct type *expect_type,
				     struct expression *exp,
				     enum noside noside)
{
  value *arg1 = std::get<0> (m_storage)->evaluate_with_coercion (exp, noside);
  std::vector<operation_up> &values = std::get<1> (m_storage);
  value **argvec = XALLOCAVEC (struct value *, values.size ());
  for (int ix = 0; ix < values.size (); ++ix)
    argvec[ix] = values[ix]->evaluate_with_coercion (exp, noside);
  return eval_multi_subscript (expect_type, exp, noside, arg1,
			       gdb::make_array_view (argvec, values.size ()));
}

value *
logical_and_operation::evaluate (struct type *expect_type,
				 struct expression *exp,
				 enum noside noside)
{
  value *arg1 = std::get<0> (m_storage)->evaluate (nullptr, exp, noside);
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);

  value *arg2 = std::get<1> (m_storage)->evaluate (nullptr, exp,
						   EVAL_AVOID_SIDE_EFFECTS);

  if (binop_user_defined_p (BINOP_LOGICAL_AND, arg1, arg2))
    {
      arg2 = std::get<1> (m_storage)->evaluate (nullptr, exp, noside);
      return value_x_binop (arg1, arg2, BINOP_LOGICAL_AND, OP_NULL, noside);
    }
  else
    {
      int tem = value_logical_not (arg1);
      if (!tem)
	{
	  arg2 = std::get<1> (m_storage)->evaluate (nullptr, exp, noside);
	  tem = value_logical_not (arg2);
	}
      struct type *type = language_bool_type (exp->language_defn,
					      exp->gdbarch);
      return value_from_longest (type, !tem);
    }
}

value *
logical_or_operation::evaluate (struct type *expect_type,
				struct expression *exp,
				enum noside noside)
{
  value *arg1 = std::get<0> (m_storage)->evaluate (nullptr, exp, noside);
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);

  value *arg2 = std::get<1> (m_storage)->evaluate (nullptr, exp,
						   EVAL_AVOID_SIDE_EFFECTS);

  if (binop_user_defined_p (BINOP_LOGICAL_OR, arg1, arg2))
    {
      arg2 = std::get<1> (m_storage)->evaluate (nullptr, exp, noside);
      return value_x_binop (arg1, arg2, BINOP_LOGICAL_OR, OP_NULL, noside);
    }
  else
    {
      int tem = value_logical_not (arg1);
      if (tem)
	{
	  arg2 = std::get<1> (m_storage)->evaluate (nullptr, exp, noside);
	  tem = value_logical_not (arg2);
	}

      struct type *type = language_bool_type (exp->language_defn,
					      exp->gdbarch);
      return value_from_longest (type, !tem);
    }
}

value *
adl_func_operation::evaluate (struct type *expect_type,
			      struct expression *exp,
			      enum noside noside)
{
  std::vector<operation_up> &arg_ops = std::get<2> (m_storage);
  std::vector<value *> args (arg_ops.size ());
  for (int i = 0; i < arg_ops.size (); ++i)
    args[i] = arg_ops[i]->evaluate_with_coercion (exp, noside);

  struct symbol *symp;
  find_overload_match (args, std::get<0> (m_storage).c_str (),
		       NON_METHOD,
		       nullptr, nullptr,
		       nullptr, &symp, nullptr, 0, noside);
  if (SYMBOL_TYPE (symp)->code () == TYPE_CODE_ERROR)
    error_unknown_type (symp->print_name ());
  value *callee = evaluate_var_value (noside, std::get<1> (m_storage), symp);
  return evaluate_subexp_do_call (exp, noside, callee, args,
				  nullptr, expect_type);

}

/* This function evaluates brace-initializers (in C/C++) for
   structure types.  */

struct value *
array_operation::evaluate_struct_tuple (struct value *struct_val,
					struct expression *exp,
					enum noside noside, int nargs)
{
  const std::vector<operation_up> &in_args = std::get<2> (m_storage);
  struct type *struct_type = check_typedef (value_type (struct_val));
  struct type *field_type;
  int fieldno = -1;

  int idx = 0;
  while (--nargs >= 0)
    {
      struct value *val = NULL;
      int bitpos, bitsize;
      bfd_byte *addr;

      fieldno++;
      /* Skip static fields.  */
      while (fieldno < struct_type->num_fields ()
	     && field_is_static (&struct_type->field (fieldno)))
	fieldno++;
      if (fieldno >= struct_type->num_fields ())
	error (_("too many initializers"));
      field_type = struct_type->field (fieldno).type ();
      if (field_type->code () == TYPE_CODE_UNION
	  && TYPE_FIELD_NAME (struct_type, fieldno)[0] == '0')
	error (_("don't know which variant you want to set"));

      /* Here, struct_type is the type of the inner struct,
	 while substruct_type is the type of the inner struct.
	 These are the same for normal structures, but a variant struct
	 contains anonymous union fields that contain substruct fields.
	 The value fieldno is the index of the top-level (normal or
	 anonymous union) field in struct_field, while the value
	 subfieldno is the index of the actual real (named inner) field
	 in substruct_type.  */

      field_type = struct_type->field (fieldno).type ();
      if (val == 0)
	val = in_args[idx++]->evaluate (field_type, exp, noside);

      /* Now actually set the field in struct_val.  */

      /* Assign val to field fieldno.  */
      if (value_type (val) != field_type)
	val = value_cast (field_type, val);

      bitsize = TYPE_FIELD_BITSIZE (struct_type, fieldno);
      bitpos = TYPE_FIELD_BITPOS (struct_type, fieldno);
      addr = value_contents_writeable (struct_val) + bitpos / 8;
      if (bitsize)
	modify_field (struct_type, addr,
		      value_as_long (val), bitpos % 8, bitsize);
      else
	memcpy (addr, value_contents (val),
		TYPE_LENGTH (value_type (val)));

    }
  return struct_val;
}

value *
array_operation::evaluate (struct type *expect_type,
			   struct expression *exp,
			   enum noside noside)
{
  int tem;
  int tem2 = std::get<0> (m_storage);
  int tem3 = std::get<1> (m_storage);
  const std::vector<operation_up> &in_args = std::get<2> (m_storage);
  int nargs = tem3 - tem2 + 1;
  struct type *type = expect_type ? check_typedef (expect_type) : nullptr;

  if (expect_type != nullptr && noside != EVAL_SKIP
      && type->code () == TYPE_CODE_STRUCT)
    {
      struct value *rec = allocate_value (expect_type);

      memset (value_contents_raw (rec), '\0', TYPE_LENGTH (type));
      return evaluate_struct_tuple (rec, exp, noside, nargs);
    }

  if (expect_type != nullptr && noside != EVAL_SKIP
      && type->code () == TYPE_CODE_ARRAY)
    {
      struct type *range_type = type->index_type ();
      struct type *element_type = TYPE_TARGET_TYPE (type);
      struct value *array = allocate_value (expect_type);
      int element_size = TYPE_LENGTH (check_typedef (element_type));
      LONGEST low_bound, high_bound, index;

      if (!get_discrete_bounds (range_type, &low_bound, &high_bound))
	{
	  low_bound = 0;
	  high_bound = (TYPE_LENGTH (type) / element_size) - 1;
	}
      index = low_bound;
      memset (value_contents_raw (array), 0, TYPE_LENGTH (expect_type));
      for (tem = nargs; --nargs >= 0;)
	{
	  struct value *element;

	  element = in_args[index - low_bound]->evaluate (element_type,
							  exp, noside);
	  if (value_type (element) != element_type)
	    element = value_cast (element_type, element);
	  if (index > high_bound)
	    /* To avoid memory corruption.  */
	    error (_("Too many array elements"));
	  memcpy (value_contents_raw (array)
		  + (index - low_bound) * element_size,
		  value_contents (element),
		  element_size);
	  index++;
	}
      return array;
    }

  if (expect_type != nullptr && noside != EVAL_SKIP
      && type->code () == TYPE_CODE_SET)
    {
      struct value *set = allocate_value (expect_type);
      gdb_byte *valaddr = value_contents_raw (set);
      struct type *element_type = type->index_type ();
      struct type *check_type = element_type;
      LONGEST low_bound, high_bound;

      /* Get targettype of elementtype.  */
      while (check_type->code () == TYPE_CODE_RANGE
	     || check_type->code () == TYPE_CODE_TYPEDEF)
	check_type = TYPE_TARGET_TYPE (check_type);

      if (!get_discrete_bounds (element_type, &low_bound, &high_bound))
	error (_("(power)set type with unknown size"));
      memset (valaddr, '\0', TYPE_LENGTH (type));
      int idx = 0;
      for (tem = 0; tem < nargs; tem++)
	{
	  LONGEST range_low, range_high;
	  struct type *range_low_type, *range_high_type;
	  struct value *elem_val;

	  elem_val = in_args[idx++]->evaluate (element_type, exp, noside);
	  range_low_type = range_high_type = value_type (elem_val);
	  range_low = range_high = value_as_long (elem_val);

	  /* Check types of elements to avoid mixture of elements from
	     different types. Also check if type of element is "compatible"
	     with element type of powerset.  */
	  if (range_low_type->code () == TYPE_CODE_RANGE)
	    range_low_type = TYPE_TARGET_TYPE (range_low_type);
	  if (range_high_type->code () == TYPE_CODE_RANGE)
	    range_high_type = TYPE_TARGET_TYPE (range_high_type);
	  if ((range_low_type->code () != range_high_type->code ())
	      || (range_low_type->code () == TYPE_CODE_ENUM
		  && (range_low_type != range_high_type)))
	    /* different element modes.  */
	    error (_("POWERSET tuple elements of different mode"));
	  if ((check_type->code () != range_low_type->code ())
	      || (check_type->code () == TYPE_CODE_ENUM
		  && range_low_type != check_type))
	    error (_("incompatible POWERSET tuple elements"));
	  if (range_low > range_high)
	    {
	      warning (_("empty POWERSET tuple range"));
	      continue;
	    }
	  if (range_low < low_bound || range_high > high_bound)
	    error (_("POWERSET tuple element out of range"));
	  range_low -= low_bound;
	  range_high -= low_bound;
	  for (; range_low <= range_high; range_low++)
	    {
	      int bit_index = (unsigned) range_low % TARGET_CHAR_BIT;

	      if (gdbarch_byte_order (exp->gdbarch) == BFD_ENDIAN_BIG)
		bit_index = TARGET_CHAR_BIT - 1 - bit_index;
	      valaddr[(unsigned) range_low / TARGET_CHAR_BIT]
		|= 1 << bit_index;
	    }
	}
      return set;
    }

  value **argvec = XALLOCAVEC (struct value *, nargs);
  for (tem = 0; tem < nargs; tem++)
    {
      /* Ensure that array expressions are coerced into pointer
	 objects.  */
      argvec[tem] = in_args[tem]->evaluate_with_coercion (exp, noside);
    }
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  return value_array (tem2, tem3, argvec);
}

}

struct value *
evaluate_subexp_standard (struct type *expect_type,
			  struct expression *exp, int *pos,
			  enum noside noside)
{
  enum exp_opcode op;
  int tem, tem2, tem3;
  int pc, oldpos;
  struct value *arg1 = NULL;
  struct value *arg2 = NULL;
  struct type *type;
  int nargs;
  struct value **argvec;
  int ix;
  struct type **arg_types;

  pc = (*pos)++;
  op = exp->elts[pc].opcode;

  switch (op)
    {
    case OP_SCOPE:
      tem = longest_to_int (exp->elts[pc + 2].longconst);
      (*pos) += 4 + BYTES_TO_EXP_ELEM (tem + 1);
      return eval_op_scope (expect_type, exp, noside,
			    exp->elts[pc + 1].type,
			    &exp->elts[pc + 3].string);

    case OP_LONG:
      (*pos) += 3;
      return value_from_longest (exp->elts[pc + 1].type,
				 exp->elts[pc + 2].longconst);

    case OP_FLOAT:
      (*pos) += 3;
      return value_from_contents (exp->elts[pc + 1].type,
				  exp->elts[pc + 2].floatconst);

    case OP_ADL_FUNC:
    case OP_VAR_VALUE:
      {
	(*pos) += 3;
	symbol *var = exp->elts[pc + 2].symbol;
	if (SYMBOL_TYPE (var)->code () == TYPE_CODE_ERROR)
	  error_unknown_type (var->print_name ());
	if (noside != EVAL_SKIP)
	    return evaluate_var_value (noside, exp->elts[pc + 1].block, var);
	else
	  {
	    /* Return a dummy value of the correct type when skipping, so
	       that parent functions know what is to be skipped.  */
	    return allocate_value (SYMBOL_TYPE (var));
	  }
      }

    case OP_VAR_MSYM_VALUE:
      {
	(*pos) += 3;

	minimal_symbol *msymbol = exp->elts[pc + 2].msymbol;
	return eval_op_var_msym_value (expect_type, exp, noside,
				       pc == 0, msymbol,
				       exp->elts[pc + 1].objfile);
      }

    case OP_VAR_ENTRY_VALUE:
      (*pos) += 2;

      {
	struct symbol *sym = exp->elts[pc + 1].symbol;

	return eval_op_var_entry_value (expect_type, exp, noside, sym);
      }

    case OP_FUNC_STATIC_VAR:
      tem = longest_to_int (exp->elts[pc + 1].longconst);
      (*pos) += 3 + BYTES_TO_EXP_ELEM (tem + 1);
      if (noside == EVAL_SKIP)
	return eval_skip_value (exp);

      {
	value *func = evaluate_subexp_standard (NULL, exp, pos, noside);

	return eval_op_func_static_var (expect_type, exp, noside, func,
					&exp->elts[pc + 2].string);
      }

    case OP_LAST:
      (*pos) += 2;
      return
	access_value_history (longest_to_int (exp->elts[pc + 1].longconst));

    case OP_REGISTER:
      {
	const char *name = &exp->elts[pc + 2].string;

	(*pos) += 3 + BYTES_TO_EXP_ELEM (exp->elts[pc + 1].longconst + 1);
	return eval_op_register (expect_type, exp, noside, name);
      }
    case OP_BOOL:
      (*pos) += 2;
      type = language_bool_type (exp->language_defn, exp->gdbarch);
      return value_from_longest (type, exp->elts[pc + 1].longconst);

    case OP_INTERNALVAR:
      (*pos) += 2;
      return value_of_internalvar (exp->gdbarch,
				   exp->elts[pc + 1].internalvar);

    case OP_STRING:
      tem = longest_to_int (exp->elts[pc + 1].longconst);
      (*pos) += 3 + BYTES_TO_EXP_ELEM (tem + 1);
      return eval_op_string (expect_type, exp, noside, tem,
			     &exp->elts[pc + 2].string);

    case OP_OBJC_NSSTRING:		/* Objective C Foundation Class
					   NSString constant.  */
      tem = longest_to_int (exp->elts[pc + 1].longconst);
      (*pos) += 3 + BYTES_TO_EXP_ELEM (tem + 1);
      if (noside == EVAL_SKIP)
	return eval_skip_value (exp);
      return value_nsstring (exp->gdbarch, &exp->elts[pc + 2].string, tem + 1);

    case OP_ARRAY:
      (*pos) += 3;
      tem2 = longest_to_int (exp->elts[pc + 1].longconst);
      tem3 = longest_to_int (exp->elts[pc + 2].longconst);
      nargs = tem3 - tem2 + 1;
      type = expect_type ? check_typedef (expect_type) : nullptr;

      if (expect_type != nullptr && noside != EVAL_SKIP
	  && type->code () == TYPE_CODE_STRUCT)
	{
	  struct value *rec = allocate_value (expect_type);

	  memset (value_contents_raw (rec), '\0', TYPE_LENGTH (type));
	  return evaluate_struct_tuple (rec, exp, pos, noside, nargs);
	}

      if (expect_type != nullptr && noside != EVAL_SKIP
	  && type->code () == TYPE_CODE_ARRAY)
	{
	  struct type *range_type = type->index_type ();
	  struct type *element_type = TYPE_TARGET_TYPE (type);
	  struct value *array = allocate_value (expect_type);
	  int element_size = TYPE_LENGTH (check_typedef (element_type));
	  LONGEST low_bound, high_bound, index;

	  if (!get_discrete_bounds (range_type, &low_bound, &high_bound))
	    {
	      low_bound = 0;
	      high_bound = (TYPE_LENGTH (type) / element_size) - 1;
	    }
	  index = low_bound;
	  memset (value_contents_raw (array), 0, TYPE_LENGTH (expect_type));
	  for (tem = nargs; --nargs >= 0;)
	    {
	      struct value *element;

	      element = evaluate_subexp (element_type, exp, pos, noside);
	      if (value_type (element) != element_type)
		element = value_cast (element_type, element);
	      if (index > high_bound)
		/* To avoid memory corruption.  */
		error (_("Too many array elements"));
	      memcpy (value_contents_raw (array)
		      + (index - low_bound) * element_size,
		      value_contents (element),
		      element_size);
	      index++;
	    }
	  return array;
	}

      if (expect_type != nullptr && noside != EVAL_SKIP
	  && type->code () == TYPE_CODE_SET)
	{
	  struct value *set = allocate_value (expect_type);
	  gdb_byte *valaddr = value_contents_raw (set);
	  struct type *element_type = type->index_type ();
	  struct type *check_type = element_type;
	  LONGEST low_bound, high_bound;

	  /* Get targettype of elementtype.  */
	  while (check_type->code () == TYPE_CODE_RANGE
		 || check_type->code () == TYPE_CODE_TYPEDEF)
	    check_type = TYPE_TARGET_TYPE (check_type);

	  if (!get_discrete_bounds (element_type, &low_bound, &high_bound))
	    error (_("(power)set type with unknown size"));
	  memset (valaddr, '\0', TYPE_LENGTH (type));
	  for (tem = 0; tem < nargs; tem++)
	    {
	      LONGEST range_low, range_high;
	      struct type *range_low_type, *range_high_type;
	      struct value *elem_val;

	      elem_val = evaluate_subexp (element_type, exp, pos, noside);
	      range_low_type = range_high_type = value_type (elem_val);
	      range_low = range_high = value_as_long (elem_val);

	      /* Check types of elements to avoid mixture of elements from
		 different types. Also check if type of element is "compatible"
		 with element type of powerset.  */
	      if (range_low_type->code () == TYPE_CODE_RANGE)
		range_low_type = TYPE_TARGET_TYPE (range_low_type);
	      if (range_high_type->code () == TYPE_CODE_RANGE)
		range_high_type = TYPE_TARGET_TYPE (range_high_type);
	      if ((range_low_type->code () != range_high_type->code ())
		  || (range_low_type->code () == TYPE_CODE_ENUM
		      && (range_low_type != range_high_type)))
		/* different element modes.  */
		error (_("POWERSET tuple elements of different mode"));
	      if ((check_type->code () != range_low_type->code ())
		  || (check_type->code () == TYPE_CODE_ENUM
		      && range_low_type != check_type))
		error (_("incompatible POWERSET tuple elements"));
	      if (range_low > range_high)
		{
		  warning (_("empty POWERSET tuple range"));
		  continue;
		}
	      if (range_low < low_bound || range_high > high_bound)
		error (_("POWERSET tuple element out of range"));
	      range_low -= low_bound;
	      range_high -= low_bound;
	      for (; range_low <= range_high; range_low++)
		{
		  int bit_index = (unsigned) range_low % TARGET_CHAR_BIT;

		  if (gdbarch_byte_order (exp->gdbarch) == BFD_ENDIAN_BIG)
		    bit_index = TARGET_CHAR_BIT - 1 - bit_index;
		  valaddr[(unsigned) range_low / TARGET_CHAR_BIT]
		    |= 1 << bit_index;
		}
	    }
	  return set;
	}

      argvec = XALLOCAVEC (struct value *, nargs);
      for (tem = 0; tem < nargs; tem++)
	{
	  /* Ensure that array expressions are coerced into pointer
	     objects.  */
	  argvec[tem] = evaluate_subexp_with_coercion (exp, pos, noside);
	}
      if (noside == EVAL_SKIP)
	return eval_skip_value (exp);
      return value_array (tem2, tem3, argvec);

    case TERNOP_SLICE:
      {
	struct value *array = evaluate_subexp (nullptr, exp, pos, noside);
	struct value *low = evaluate_subexp (nullptr, exp, pos, noside);
	struct value *upper = evaluate_subexp (nullptr, exp, pos, noside);
	return eval_op_ternop (expect_type, exp, noside, array, low, upper);
      }

    case TERNOP_COND:
      /* Skip third and second args to evaluate the first one.  */
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      if (value_logical_not (arg1))
	{
	  evaluate_subexp (nullptr, exp, pos, EVAL_SKIP);
	  return evaluate_subexp (nullptr, exp, pos, noside);
	}
      else
	{
	  arg2 = evaluate_subexp (nullptr, exp, pos, noside);
	  evaluate_subexp (nullptr, exp, pos, EVAL_SKIP);
	  return arg2;
	}

    case OP_OBJC_SELECTOR:
      {				/* Objective C @selector operator.  */
	char *sel = &exp->elts[pc + 2].string;
	int len = longest_to_int (exp->elts[pc + 1].longconst);

	(*pos) += 3 + BYTES_TO_EXP_ELEM (len + 1);
	if (sel[len] != 0)
	  sel[len] = 0;		/* Make sure it's terminated.  */

	return eval_op_objc_selector (expect_type, exp, noside, sel);
      }

    case OP_OBJC_MSGCALL:
      {				/* Objective C message (method) call.  */
	CORE_ADDR selector = 0;

	enum noside sub_no_side = EVAL_NORMAL;

	struct value *target = NULL;

	struct type *selector_type = NULL;

	selector = exp->elts[pc + 1].longconst;
	nargs = exp->elts[pc + 2].longconst;
	argvec = XALLOCAVEC (struct value *, nargs + 3);

	(*pos) += 3;

	selector_type = builtin_type (exp->gdbarch)->builtin_data_ptr;

	if (noside == EVAL_AVOID_SIDE_EFFECTS)
	  sub_no_side = EVAL_NORMAL;
	else
	  sub_no_side = noside;

	target = evaluate_subexp (selector_type, exp, pos, sub_no_side);

	if (value_as_long (target) == 0)
	  sub_no_side = EVAL_SKIP;
	else
	  sub_no_side = noside;

	/* Now depending on whether we found a symbol for the method,
	   we will either call the runtime dispatcher or the method
	   directly.  */

	argvec[0] = nullptr;
	argvec[1] = nullptr;
	/* User-supplied arguments.  */
	for (tem = 0; tem < nargs; tem++)
	  argvec[tem + 2] = evaluate_subexp_with_coercion (exp, pos,
							   sub_no_side);
	argvec[tem + 3] = 0;

	auto call_args = gdb::make_array_view (argvec, nargs + 3);

	return eval_op_objc_msgcall (expect_type, exp, noside, selector,
				     target, call_args);
      }
      break;

    case OP_FUNCALL:
      return evaluate_funcall (expect_type, exp, pos, noside);

    case OP_COMPLEX:
      /* We have a complex number, There should be 2 floating 
	 point numbers that compose it.  */
      (*pos) += 2;
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (nullptr, exp, pos, noside);

      return value_literal_complex (arg1, arg2, exp->elts[pc + 1].type);

    case STRUCTOP_STRUCT:
      tem = longest_to_int (exp->elts[pc + 1].longconst);
      (*pos) += 3 + BYTES_TO_EXP_ELEM (tem + 1);
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      return eval_op_structop_struct (expect_type, exp, noside, arg1,
				      &exp->elts[pc + 2].string);

    case STRUCTOP_PTR:
      tem = longest_to_int (exp->elts[pc + 1].longconst);
      (*pos) += 3 + BYTES_TO_EXP_ELEM (tem + 1);
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      return eval_op_structop_ptr (expect_type, exp, noside, arg1,
				   &exp->elts[pc + 2].string);

    case STRUCTOP_MEMBER:
    case STRUCTOP_MPTR:
      if (op == STRUCTOP_MEMBER)
	arg1 = evaluate_subexp_for_address (exp, pos, noside);
      else
	arg1 = evaluate_subexp (nullptr, exp, pos, noside);

      arg2 = evaluate_subexp (nullptr, exp, pos, noside);

      return eval_op_member (expect_type, exp, noside, arg1, arg2);

    case TYPE_INSTANCE:
      {
	type_instance_flags flags
	  = (type_instance_flag_value) longest_to_int (exp->elts[pc + 1].longconst);
	nargs = longest_to_int (exp->elts[pc + 2].longconst);
	arg_types = (struct type **) alloca (nargs * sizeof (struct type *));
	for (ix = 0; ix < nargs; ++ix)
	  arg_types[ix] = exp->elts[pc + 2 + ix + 1].type;

	fake_method fake_expect_type (flags, nargs, arg_types);
	*(pos) += 4 + nargs;
	return evaluate_subexp_standard (fake_expect_type.type (), exp, pos,
					 noside);
      }

    case BINOP_CONCAT:
      arg1 = evaluate_subexp_with_coercion (exp, pos, noside);
      arg2 = evaluate_subexp_with_coercion (exp, pos, noside);
      return eval_op_concat (expect_type, exp, noside, arg1, arg2);

    case BINOP_ASSIGN:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      /* Special-case assignments where the left-hand-side is a
	 convenience variable -- in these, don't bother setting an
	 expected type.  This avoids a weird case where re-assigning a
	 string or array to an internal variable could error with "Too
	 many array elements".  */
      arg2 = evaluate_subexp (VALUE_LVAL (arg1) == lval_internalvar
				? nullptr
				: value_type (arg1),
			      exp, pos, noside);

      if (noside == EVAL_SKIP || noside == EVAL_AVOID_SIDE_EFFECTS)
	return arg1;
      if (binop_user_defined_p (op, arg1, arg2))
	return value_x_binop (arg1, arg2, op, OP_NULL, noside);
      else
	return value_assign (arg1, arg2);

    case BINOP_ASSIGN_MODIFY:
      (*pos) += 2;
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (value_type (arg1), exp, pos, noside);
      op = exp->elts[pc + 1].opcode;
      return eval_binop_assign_modify (expect_type, exp, noside, op,
				       arg1, arg2);

    case BINOP_ADD:
      arg1 = evaluate_subexp_with_coercion (exp, pos, noside);
      arg2 = evaluate_subexp_with_coercion (exp, pos, noside);
      return eval_op_add (expect_type, exp, noside, arg1, arg2);

    case BINOP_SUB:
      arg1 = evaluate_subexp_with_coercion (exp, pos, noside);
      arg2 = evaluate_subexp_with_coercion (exp, pos, noside);
      return eval_op_sub (expect_type, exp, noside, arg1, arg2);

    case BINOP_EXP:
    case BINOP_MUL:
    case BINOP_DIV:
    case BINOP_INTDIV:
    case BINOP_REM:
    case BINOP_MOD:
    case BINOP_LSH:
    case BINOP_RSH:
    case BINOP_BITWISE_AND:
    case BINOP_BITWISE_IOR:
    case BINOP_BITWISE_XOR:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (nullptr, exp, pos, noside);
      return eval_op_binary (expect_type, exp, noside, op, arg1, arg2);

    case BINOP_SUBSCRIPT:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (nullptr, exp, pos, noside);
      return eval_op_subscript (expect_type, exp, noside, op, arg1, arg2);

    case MULTI_SUBSCRIPT:
      (*pos) += 2;
      nargs = longest_to_int (exp->elts[pc + 1].longconst);
      arg1 = evaluate_subexp_with_coercion (exp, pos, noside);
      argvec = XALLOCAVEC (struct value *, nargs);
      for (ix = 0; ix < nargs; ++ix)
	argvec[ix] = evaluate_subexp_with_coercion (exp, pos, noside);
      return eval_multi_subscript (expect_type, exp, noside, arg1,
				   gdb::make_array_view (argvec, nargs));

    case BINOP_LOGICAL_AND:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      if (noside == EVAL_SKIP)
	{
	  evaluate_subexp (nullptr, exp, pos, noside);
	  return eval_skip_value (exp);
	}

      oldpos = *pos;
      arg2 = evaluate_subexp (nullptr, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      *pos = oldpos;

      if (binop_user_defined_p (op, arg1, arg2))
	{
	  arg2 = evaluate_subexp (nullptr, exp, pos, noside);
	  return value_x_binop (arg1, arg2, op, OP_NULL, noside);
	}
      else
	{
	  tem = value_logical_not (arg1);
	  arg2
	    = evaluate_subexp (nullptr, exp, pos, (tem ? EVAL_SKIP : noside));
	  type = language_bool_type (exp->language_defn, exp->gdbarch);
	  return value_from_longest (type,
			     (LONGEST) (!tem && !value_logical_not (arg2)));
	}

    case BINOP_LOGICAL_OR:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      if (noside == EVAL_SKIP)
	{
	  evaluate_subexp (nullptr, exp, pos, noside);
	  return eval_skip_value (exp);
	}

      oldpos = *pos;
      arg2 = evaluate_subexp (nullptr, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      *pos = oldpos;

      if (binop_user_defined_p (op, arg1, arg2))
	{
	  arg2 = evaluate_subexp (nullptr, exp, pos, noside);
	  return value_x_binop (arg1, arg2, op, OP_NULL, noside);
	}
      else
	{
	  tem = value_logical_not (arg1);
	  arg2
	    = evaluate_subexp (nullptr, exp, pos, (!tem ? EVAL_SKIP : noside));
	  type = language_bool_type (exp->language_defn, exp->gdbarch);
	  return value_from_longest (type,
			     (LONGEST) (!tem || !value_logical_not (arg2)));
	}

    case BINOP_EQUAL:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (value_type (arg1), exp, pos, noside);
      return eval_op_equal (expect_type, exp, noside, op, arg1, arg2);

    case BINOP_NOTEQUAL:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (value_type (arg1), exp, pos, noside);
      return eval_op_notequal (expect_type, exp, noside, op, arg1, arg2);

    case BINOP_LESS:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (value_type (arg1), exp, pos, noside);
      return eval_op_less (expect_type, exp, noside, op, arg1, arg2);

    case BINOP_GTR:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (value_type (arg1), exp, pos, noside);
      return eval_op_gtr (expect_type, exp, noside, op, arg1, arg2);

    case BINOP_GEQ:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (value_type (arg1), exp, pos, noside);
      return eval_op_geq (expect_type, exp, noside, op, arg1, arg2);

    case BINOP_LEQ:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (value_type (arg1), exp, pos, noside);
      return eval_op_leq (expect_type, exp, noside, op, arg1, arg2);

    case BINOP_REPEAT:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      arg2 = evaluate_subexp (nullptr, exp, pos, noside);
      return eval_op_repeat (expect_type, exp, noside, op, arg1, arg2);

    case BINOP_COMMA:
      evaluate_subexp (nullptr, exp, pos, noside);
      return evaluate_subexp (nullptr, exp, pos, noside);

    case UNOP_PLUS:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      return eval_op_plus (expect_type, exp, noside, op, arg1);
      
    case UNOP_NEG:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      return eval_op_neg (expect_type, exp, noside, op, arg1);

    case UNOP_COMPLEMENT:
      /* C++: check for and handle destructor names.  */

      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      return eval_op_complement (expect_type, exp, noside, op, arg1);

    case UNOP_LOGICAL_NOT:
      arg1 = evaluate_subexp (nullptr, exp, pos, noside);
      return eval_op_lognot (expect_type, exp, noside, op, arg1);

    case UNOP_IND:
      if (expect_type && expect_type->code () == TYPE_CODE_PTR)
	expect_type = TYPE_TARGET_TYPE (check_typedef (expect_type));
      arg1 = evaluate_subexp (expect_type, exp, pos, noside);
      return eval_op_ind (expect_type, exp, noside, arg1);

    case UNOP_ADDR:
      /* C++: check for and handle pointer to members.  */

      if (noside == EVAL_SKIP)
	{
	  evaluate_subexp (nullptr, exp, pos, EVAL_SKIP);
	  return eval_skip_value (exp);
	}
      else
	return evaluate_subexp_for_address (exp, pos, noside);

    case UNOP_SIZEOF:
      if (noside == EVAL_SKIP)
	{
	  evaluate_subexp (nullptr, exp, pos, EVAL_SKIP);
	  return eval_skip_value (exp);
	}
      return evaluate_subexp_for_sizeof (exp, pos, noside);

    case UNOP_ALIGNOF:
      arg1 = evaluate_subexp (nullptr, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      return eval_op_alignof (expect_type, exp, noside, arg1);

    case UNOP_CAST:
      (*pos) += 2;
      type = exp->elts[pc + 1].type;
      return evaluate_subexp_for_cast (exp, pos, noside, type);

    case UNOP_CAST_TYPE:
      arg1 = evaluate_subexp (NULL, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      type = value_type (arg1);
      return evaluate_subexp_for_cast (exp, pos, noside, type);

    case UNOP_DYNAMIC_CAST:
      arg1 = evaluate_subexp (NULL, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      type = value_type (arg1);
      arg1 = evaluate_subexp (type, exp, pos, noside);
      if (noside == EVAL_SKIP)
	return eval_skip_value (exp);
      return value_dynamic_cast (type, arg1);

    case UNOP_REINTERPRET_CAST:
      arg1 = evaluate_subexp (NULL, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      type = value_type (arg1);
      arg1 = evaluate_subexp (type, exp, pos, noside);
      if (noside == EVAL_SKIP)
	return eval_skip_value (exp);
      return value_reinterpret_cast (type, arg1);

    case UNOP_MEMVAL:
      (*pos) += 2;
      arg1 = evaluate_subexp (expect_type, exp, pos, noside);
      return eval_op_memval (expect_type, exp, noside, arg1,
			     exp->elts[pc + 1].type);

    case UNOP_MEMVAL_TYPE:
      arg1 = evaluate_subexp (NULL, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      type = value_type (arg1);
      arg1 = evaluate_subexp (expect_type, exp, pos, noside);
      return eval_op_memval (expect_type, exp, noside, arg1, type);

    case UNOP_PREINCREMENT:
      arg1 = evaluate_subexp (expect_type, exp, pos, noside);
      return eval_op_preinc (expect_type, exp, noside, op, arg1);

    case UNOP_PREDECREMENT:
      arg1 = evaluate_subexp (expect_type, exp, pos, noside);
      return eval_op_predec (expect_type, exp, noside, op, arg1);

    case UNOP_POSTINCREMENT:
      arg1 = evaluate_subexp (expect_type, exp, pos, noside);
      return eval_op_postinc (expect_type, exp, noside, op, arg1);

    case UNOP_POSTDECREMENT:
      arg1 = evaluate_subexp (expect_type, exp, pos, noside);
      return eval_op_postdec (expect_type, exp, noside, op, arg1);

    case OP_THIS:
      (*pos) += 1;
      return value_of_this (exp->language_defn);

    case OP_TYPE:
      /* The value is not supposed to be used.  This is here to make it
	 easier to accommodate expressions that contain types.  */
      (*pos) += 2;
      return eval_op_type (expect_type, exp, noside, exp->elts[pc + 1].type);

    case OP_TYPEOF:
    case OP_DECLTYPE:
      if (noside == EVAL_SKIP)
	{
	  evaluate_subexp (nullptr, exp, pos, EVAL_SKIP);
	  return eval_skip_value (exp);
	}
      else if (noside == EVAL_AVOID_SIDE_EFFECTS)
	{
	  enum exp_opcode sub_op = exp->elts[*pos].opcode;
	  struct value *result;

	  result = evaluate_subexp (nullptr, exp, pos, EVAL_AVOID_SIDE_EFFECTS);

	  /* 'decltype' has special semantics for lvalues.  */
	  if (op == OP_DECLTYPE
	      && (sub_op == BINOP_SUBSCRIPT
		  || sub_op == STRUCTOP_MEMBER
		  || sub_op == STRUCTOP_MPTR
		  || sub_op == UNOP_IND
		  || sub_op == STRUCTOP_STRUCT
		  || sub_op == STRUCTOP_PTR
		  || sub_op == OP_SCOPE))
	    {
	      type = value_type (result);

	      if (!TYPE_IS_REFERENCE (type))
		{
		  type = lookup_lvalue_reference_type (type);
		  result = allocate_value (type);
		}
	    }

	  return result;
	}
      else
	error (_("Attempt to use a type as an expression"));

    case OP_TYPEID:
      {
	struct value *result;
	enum exp_opcode sub_op = exp->elts[*pos].opcode;

	if (sub_op == OP_TYPE || sub_op == OP_DECLTYPE || sub_op == OP_TYPEOF)
	  result = evaluate_subexp (nullptr, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
	else
	  result = evaluate_subexp (nullptr, exp, pos, noside);

	if (noside != EVAL_NORMAL)
	  return allocate_value (cplus_typeid_type (exp->gdbarch));

	return cplus_typeid (result);
      }

    default:
      /* Removing this case and compiling with gcc -Wall reveals that
	 a lot of cases are hitting this case.  Some of these should
	 probably be removed from expression.h; others are legitimate
	 expressions which are (apparently) not fully implemented.

	 If there are any cases landing here which mean a user error,
	 then they should be separate cases, with more descriptive
	 error messages.  */

      error (_("GDB does not (yet) know how to "
	       "evaluate that kind of expression"));
    }

  gdb_assert_not_reached ("missed return?");
}

/* Helper for evaluate_subexp_for_address.  */

static value *
evaluate_subexp_for_address_base (struct expression *exp, enum noside noside,
				  value *x)
{
  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    {
      struct type *type = check_typedef (value_type (x));

      if (TYPE_IS_REFERENCE (type))
	return value_zero (lookup_pointer_type (TYPE_TARGET_TYPE (type)),
			   not_lval);
      else if (VALUE_LVAL (x) == lval_memory || value_must_coerce_to_target (x))
	return value_zero (lookup_pointer_type (value_type (x)),
			   not_lval);
      else
	error (_("Attempt to take address of "
		 "value not located in memory."));
    }
  return value_addr (x);
}

/* Evaluate a subexpression of EXP, at index *POS,
   and return the address of that subexpression.
   Advance *POS over the subexpression.
   If the subexpression isn't an lvalue, get an error.
   NOSIDE may be EVAL_AVOID_SIDE_EFFECTS;
   then only the type of the result need be correct.  */

static struct value *
evaluate_subexp_for_address (struct expression *exp, int *pos,
			     enum noside noside)
{
  enum exp_opcode op;
  int pc;
  struct symbol *var;
  struct value *x;
  int tem;

  pc = (*pos);
  op = exp->elts[pc].opcode;

  switch (op)
    {
    case UNOP_IND:
      (*pos)++;
      x = evaluate_subexp (nullptr, exp, pos, noside);

      /* We can't optimize out "&*" if there's a user-defined operator*.  */
      if (unop_user_defined_p (op, x))
	{
	  x = value_x_unop (x, op, noside);
	  goto default_case_after_eval;
	}

      return coerce_array (x);

    case UNOP_MEMVAL:
      (*pos) += 3;
      return value_cast (lookup_pointer_type (exp->elts[pc + 1].type),
			 evaluate_subexp (nullptr, exp, pos, noside));

    case UNOP_MEMVAL_TYPE:
      {
	struct type *type;

	(*pos) += 1;
	x = evaluate_subexp (nullptr, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
	type = value_type (x);
	return value_cast (lookup_pointer_type (type),
			   evaluate_subexp (nullptr, exp, pos, noside));
      }

    case OP_VAR_VALUE:
      var = exp->elts[pc + 2].symbol;

      /* C++: The "address" of a reference should yield the address
       * of the object pointed to.  Let value_addr() deal with it.  */
      if (TYPE_IS_REFERENCE (SYMBOL_TYPE (var)))
	goto default_case;

      (*pos) += 4;
      if (noside == EVAL_AVOID_SIDE_EFFECTS)
	{
	  struct type *type =
	    lookup_pointer_type (SYMBOL_TYPE (var));
	  enum address_class sym_class = SYMBOL_CLASS (var);

	  if (sym_class == LOC_CONST
	      || sym_class == LOC_CONST_BYTES
	      || sym_class == LOC_REGISTER)
	    error (_("Attempt to take address of register or constant."));

	  return
	    value_zero (type, not_lval);
	}
      else
	return address_of_variable (var, exp->elts[pc + 1].block);

    case OP_VAR_MSYM_VALUE:
      {
	(*pos) += 4;

	value *val = evaluate_var_msym_value (noside,
					      exp->elts[pc + 1].objfile,
					      exp->elts[pc + 2].msymbol);
	if (noside == EVAL_AVOID_SIDE_EFFECTS)
	  {
	    struct type *type = lookup_pointer_type (value_type (val));
	    return value_zero (type, not_lval);
	  }
	else
	  return value_addr (val);
      }

    case OP_SCOPE:
      tem = longest_to_int (exp->elts[pc + 2].longconst);
      (*pos) += 5 + BYTES_TO_EXP_ELEM (tem + 1);
      x = value_aggregate_elt (exp->elts[pc + 1].type,
			       &exp->elts[pc + 3].string,
			       NULL, 1, noside);
      if (x == NULL)
	error (_("There is no field named %s"), &exp->elts[pc + 3].string);
      return x;

    default:
    default_case:
      x = evaluate_subexp (nullptr, exp, pos, noside);
    default_case_after_eval:
      return evaluate_subexp_for_address_base (exp, noside, x);
    }
}

namespace expr
{

value *
operation::evaluate_for_cast (struct type *expect_type,
			      struct expression *exp,
			      enum noside noside)
{
  value *val = evaluate (expect_type, exp, noside);
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  return value_cast (expect_type, val);
}

value *
operation::evaluate_for_address (struct expression *exp, enum noside noside)
{
  value *val = evaluate (nullptr, exp, noside);
  return evaluate_subexp_for_address_base (exp, noside, val);
}

value *
scope_operation::evaluate_for_address (struct expression *exp,
				       enum noside noside)
{
  value *x = value_aggregate_elt (std::get<0> (m_storage),
				  std::get<1> (m_storage).c_str (),
				  NULL, 1, noside);
  if (x == NULL)
    error (_("There is no field named %s"), std::get<1> (m_storage).c_str ());
  return x;
}

value *
unop_ind_base_operation::evaluate_for_address (struct expression *exp,
					       enum noside noside)
{
  value *x = std::get<0> (m_storage)->evaluate (nullptr, exp, noside);

  /* We can't optimize out "&*" if there's a user-defined operator*.  */
  if (unop_user_defined_p (UNOP_IND, x))
    {
      x = value_x_unop (x, UNOP_IND, noside);
      return evaluate_subexp_for_address_base (exp, noside, x);
    }

  return coerce_array (x);
}

value *
var_msym_value_operation::evaluate_for_address (struct expression *exp,
						enum noside noside)
{
  value *val = evaluate_var_msym_value (noside,
					std::get<1> (m_storage),
					std::get<0> (m_storage));
  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    {
      struct type *type = lookup_pointer_type (value_type (val));
      return value_zero (type, not_lval);
    }
  else
    return value_addr (val);
}

value *
unop_memval_operation::evaluate_for_address (struct expression *exp,
					     enum noside noside)
{
  return value_cast (lookup_pointer_type (std::get<1> (m_storage)),
		     std::get<0> (m_storage)->evaluate (nullptr, exp, noside));
}

value *
unop_memval_type_operation::evaluate_for_address (struct expression *exp,
						  enum noside noside)
{
  value *typeval = std::get<0> (m_storage)->evaluate (nullptr, exp,
						      EVAL_AVOID_SIDE_EFFECTS);
  struct type *type = value_type (typeval);
  return value_cast (lookup_pointer_type (type),
		     std::get<1> (m_storage)->evaluate (nullptr, exp, noside));
}

}

/* Evaluate like `evaluate_subexp' except coercing arrays to pointers.
   When used in contexts where arrays will be coerced anyway, this is
   equivalent to `evaluate_subexp' but much faster because it avoids
   actually fetching array contents (perhaps obsolete now that we have
   value_lazy()).

   Note that we currently only do the coercion for C expressions, where
   arrays are zero based and the coercion is correct.  For other languages,
   with nonzero based arrays, coercion loses.  Use CAST_IS_CONVERSION
   to decide if coercion is appropriate.  */

struct value *
evaluate_subexp_with_coercion (struct expression *exp,
			       int *pos, enum noside noside)
{
  enum exp_opcode op;
  int pc;
  struct value *val;
  struct symbol *var;
  struct type *type;

  pc = (*pos);
  op = exp->elts[pc].opcode;

  switch (op)
    {
    case OP_VAR_VALUE:
      var = exp->elts[pc + 2].symbol;
      type = check_typedef (SYMBOL_TYPE (var));
      if (type->code () == TYPE_CODE_ARRAY
	  && !type->is_vector ()
	  && CAST_IS_CONVERSION (exp->language_defn))
	{
	  (*pos) += 4;
	  val = address_of_variable (var, exp->elts[pc + 1].block);
	  return value_cast (lookup_pointer_type (TYPE_TARGET_TYPE (type)),
			     val);
	}
      /* FALLTHROUGH */

    default:
      return evaluate_subexp (nullptr, exp, pos, noside);
    }
}

namespace expr
{

value *
var_value_operation::evaluate_for_address (struct expression *exp,
					   enum noside noside)
{
  symbol *var = std::get<0> (m_storage);

  /* C++: The "address" of a reference should yield the address
   * of the object pointed to.  Let value_addr() deal with it.  */
  if (TYPE_IS_REFERENCE (SYMBOL_TYPE (var)))
    return operation::evaluate_for_address (exp, noside);

  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    {
      struct type *type = lookup_pointer_type (SYMBOL_TYPE (var));
      enum address_class sym_class = SYMBOL_CLASS (var);

      if (sym_class == LOC_CONST
	  || sym_class == LOC_CONST_BYTES
	  || sym_class == LOC_REGISTER)
	error (_("Attempt to take address of register or constant."));

      return value_zero (type, not_lval);
    }
  else
    return address_of_variable (var, std::get<1> (m_storage));
}

value *
var_value_operation::evaluate_with_coercion (struct expression *exp,
					     enum noside noside)
{
  struct symbol *var = std::get<0> (m_storage);
  struct type *type = check_typedef (SYMBOL_TYPE (var));
  if (type->code () == TYPE_CODE_ARRAY
      && !type->is_vector ()
      && CAST_IS_CONVERSION (exp->language_defn))
    {
      struct value *val = address_of_variable (var, std::get<1> (m_storage));
      return value_cast (lookup_pointer_type (TYPE_TARGET_TYPE (type)), val);
    }
  return evaluate (nullptr, exp, noside);
}

}

/* Helper function for evaluating the size of a type.  */

static value *
evaluate_subexp_for_sizeof_base (struct expression *exp, struct type *type)
{
  /* FIXME: This should be size_t.  */
  struct type *size_type = builtin_type (exp->gdbarch)->builtin_int;
  /* $5.3.3/2 of the C++ Standard (n3290 draft) says of sizeof:
     "When applied to a reference or a reference type, the result is
     the size of the referenced type."  */
  type = check_typedef (type);
  if (exp->language_defn->la_language == language_cplus
      && (TYPE_IS_REFERENCE (type)))
    type = check_typedef (TYPE_TARGET_TYPE (type));
  return value_from_longest (size_type, (LONGEST) TYPE_LENGTH (type));
}

/* Evaluate a subexpression of EXP, at index *POS,
   and return a value for the size of that subexpression.
   Advance *POS over the subexpression.  If NOSIDE is EVAL_NORMAL
   we allow side-effects on the operand if its type is a variable
   length array.   */

static struct value *
evaluate_subexp_for_sizeof (struct expression *exp, int *pos,
			    enum noside noside)
{
  /* FIXME: This should be size_t.  */
  struct type *size_type = builtin_type (exp->gdbarch)->builtin_int;
  enum exp_opcode op;
  int pc;
  struct type *type;
  struct value *val;

  pc = (*pos);
  op = exp->elts[pc].opcode;

  switch (op)
    {
      /* This case is handled specially
	 so that we avoid creating a value for the result type.
	 If the result type is very big, it's desirable not to
	 create a value unnecessarily.  */
    case UNOP_IND:
      (*pos)++;
      val = evaluate_subexp (nullptr, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      type = check_typedef (value_type (val));
      if (type->code () != TYPE_CODE_PTR
	  && !TYPE_IS_REFERENCE (type)
	  && type->code () != TYPE_CODE_ARRAY)
	error (_("Attempt to take contents of a non-pointer value."));
      type = TYPE_TARGET_TYPE (type);
      if (is_dynamic_type (type))
	type = value_type (value_ind (val));
      return value_from_longest (size_type, (LONGEST) TYPE_LENGTH (type));

    case UNOP_MEMVAL:
      (*pos) += 3;
      type = exp->elts[pc + 1].type;
      break;

    case UNOP_MEMVAL_TYPE:
      (*pos) += 1;
      val = evaluate_subexp (NULL, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      type = value_type (val);
      break;

    case OP_VAR_VALUE:
      type = SYMBOL_TYPE (exp->elts[pc + 2].symbol);
      if (is_dynamic_type (type))
	{
	  val = evaluate_subexp (nullptr, exp, pos, EVAL_NORMAL);
	  type = value_type (val);
	  if (type->code () == TYPE_CODE_ARRAY)
	    {
	      if (type_not_allocated (type) || type_not_associated (type))
		return value_zero (size_type, not_lval);
	      else if (is_dynamic_type (type->index_type ())
		       && type->bounds ()->high.kind () == PROP_UNDEFINED)
		return allocate_optimized_out_value (size_type);
	    }
	}
      else
	(*pos) += 4;
      break;

    case OP_VAR_MSYM_VALUE:
      {
	(*pos) += 4;

	minimal_symbol *msymbol = exp->elts[pc + 2].msymbol;
	value *mval = evaluate_var_msym_value (noside,
					       exp->elts[pc + 1].objfile,
					       msymbol);

	type = value_type (mval);
	if (type->code () == TYPE_CODE_ERROR)
	  error_unknown_type (msymbol->print_name ());

	return value_from_longest (size_type, TYPE_LENGTH (type));
      }
      break;

      /* Deal with the special case if NOSIDE is EVAL_NORMAL and the resulting
	 type of the subscript is a variable length array type. In this case we
	 must re-evaluate the right hand side of the subscription to allow
	 side-effects. */
    case BINOP_SUBSCRIPT:
      if (noside == EVAL_NORMAL)
	{
	  int npc = (*pos) + 1;

	  val = evaluate_subexp (nullptr, exp, &npc, EVAL_AVOID_SIDE_EFFECTS);
	  type = check_typedef (value_type (val));
	  if (type->code () == TYPE_CODE_ARRAY)
	    {
	      type = check_typedef (TYPE_TARGET_TYPE (type));
	      if (type->code () == TYPE_CODE_ARRAY)
		{
		  type = type->index_type ();
		  /* Only re-evaluate the right hand side if the resulting type
		     is a variable length type.  */
		  if (type->bounds ()->flag_bound_evaluated)
		    {
		      val = evaluate_subexp (nullptr, exp, pos, EVAL_NORMAL);
		      return value_from_longest
			(size_type, (LONGEST) TYPE_LENGTH (value_type (val)));
		    }
		}
	    }
	}

      /* Fall through.  */

    default:
      val = evaluate_subexp (nullptr, exp, pos, EVAL_AVOID_SIDE_EFFECTS);
      type = value_type (val);
      break;
    }

  return evaluate_subexp_for_sizeof_base (exp, type);
}

namespace expr
{

value *
operation::evaluate_for_sizeof (struct expression *exp, enum noside noside)
{
  value *val = evaluate (nullptr, exp, EVAL_AVOID_SIDE_EFFECTS);
  return evaluate_subexp_for_sizeof_base (exp, value_type (val));
}

value *
var_msym_value_operation::evaluate_for_sizeof (struct expression *exp,
					       enum noside noside)

{
  minimal_symbol *msymbol = std::get<0> (m_storage);
  value *mval = evaluate_var_msym_value (noside,
					 std::get<1> (m_storage),
					 msymbol);

  struct type *type = value_type (mval);
  if (type->code () == TYPE_CODE_ERROR)
    error_unknown_type (msymbol->print_name ());

  /* FIXME: This should be size_t.  */
  struct type *size_type = builtin_type (exp->gdbarch)->builtin_int;
  return value_from_longest (size_type, TYPE_LENGTH (type));
}

value *
subscript_operation::evaluate_for_sizeof (struct expression *exp,
					  enum noside noside)
{
  if (noside == EVAL_NORMAL)
    {
      value *val = std::get<0> (m_storage)->evaluate (nullptr, exp,
						      EVAL_AVOID_SIDE_EFFECTS);
      struct type *type = check_typedef (value_type (val));
      if (type->code () == TYPE_CODE_ARRAY)
	{
	  type = check_typedef (TYPE_TARGET_TYPE (type));
	  if (type->code () == TYPE_CODE_ARRAY)
	    {
	      type = type->index_type ();
	      /* Only re-evaluate the right hand side if the resulting type
		 is a variable length type.  */
	      if (type->bounds ()->flag_bound_evaluated)
		{
		  val = evaluate (nullptr, exp, EVAL_NORMAL);
		  /* FIXME: This should be size_t.  */
		  struct type *size_type
		    = builtin_type (exp->gdbarch)->builtin_int;
		  return value_from_longest
		    (size_type, (LONGEST) TYPE_LENGTH (value_type (val)));
		}
	    }
	}
    }

  return operation::evaluate_for_sizeof (exp, noside);
}

value *
unop_ind_base_operation::evaluate_for_sizeof (struct expression *exp,
					      enum noside noside)
{
  value *val = std::get<0> (m_storage)->evaluate (nullptr, exp,
						  EVAL_AVOID_SIDE_EFFECTS);
  struct type *type = check_typedef (value_type (val));
  if (type->code () != TYPE_CODE_PTR
      && !TYPE_IS_REFERENCE (type)
      && type->code () != TYPE_CODE_ARRAY)
    error (_("Attempt to take contents of a non-pointer value."));
  type = TYPE_TARGET_TYPE (type);
  if (is_dynamic_type (type))
    type = value_type (value_ind (val));
  /* FIXME: This should be size_t.  */
  struct type *size_type = builtin_type (exp->gdbarch)->builtin_int;
  return value_from_longest (size_type, (LONGEST) TYPE_LENGTH (type));
}

value *
unop_memval_operation::evaluate_for_sizeof (struct expression *exp,
					    enum noside noside)
{
  return evaluate_subexp_for_sizeof_base (exp, std::get<1> (m_storage));
}

value *
unop_memval_type_operation::evaluate_for_sizeof (struct expression *exp,
						 enum noside noside)
{
  value *typeval = std::get<0> (m_storage)->evaluate (nullptr, exp,
						      EVAL_AVOID_SIDE_EFFECTS);
  return evaluate_subexp_for_sizeof_base (exp, value_type (typeval));
}

value *
var_value_operation::evaluate_for_sizeof (struct expression *exp,
					  enum noside noside)
{
  struct type *type = SYMBOL_TYPE (std::get<0> (m_storage));
  if (is_dynamic_type (type))
    {
      value *val = evaluate (nullptr, exp, EVAL_NORMAL);
      type = value_type (val);
      if (type->code () == TYPE_CODE_ARRAY)
	{
	  /* FIXME: This should be size_t.  */
	  struct type *size_type = builtin_type (exp->gdbarch)->builtin_int;
	  if (type_not_allocated (type) || type_not_associated (type))
	    return value_zero (size_type, not_lval);
	  else if (is_dynamic_type (type->index_type ())
		   && type->bounds ()->high.kind () == PROP_UNDEFINED)
	    return allocate_optimized_out_value (size_type);
	}
    }
  return evaluate_subexp_for_sizeof_base (exp, type);
}

}

/* Evaluate a subexpression of EXP, at index *POS, and return a value
   for that subexpression cast to TO_TYPE.  Advance *POS over the
   subexpression.  */

static value *
evaluate_subexp_for_cast (expression *exp, int *pos,
			  enum noside noside,
			  struct type *to_type)
{
  int pc = *pos;

  /* Don't let symbols be evaluated with evaluate_subexp because that
     throws an "unknown type" error for no-debug data symbols.
     Instead, we want the cast to reinterpret the symbol.  */
  if (exp->elts[pc].opcode == OP_VAR_MSYM_VALUE
      || exp->elts[pc].opcode == OP_VAR_VALUE)
    {
      (*pos) += 4;

      value *val;
      if (exp->elts[pc].opcode == OP_VAR_MSYM_VALUE)
	{
	  if (noside == EVAL_AVOID_SIDE_EFFECTS)
	    return value_zero (to_type, not_lval);

	  val = evaluate_var_msym_value (noside,
					 exp->elts[pc + 1].objfile,
					 exp->elts[pc + 2].msymbol);
	}
      else
	val = evaluate_var_value (noside,
				  exp->elts[pc + 1].block,
				  exp->elts[pc + 2].symbol);

      if (noside == EVAL_SKIP)
	return eval_skip_value (exp);

      val = value_cast (to_type, val);

      /* Don't allow e.g. '&(int)var_with_no_debug_info'.  */
      if (VALUE_LVAL (val) == lval_memory)
	{
	  if (value_lazy (val))
	    value_fetch_lazy (val);
	  VALUE_LVAL (val) = not_lval;
	}
      return val;
    }

  value *val = evaluate_subexp (to_type, exp, pos, noside);
  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);
  return value_cast (to_type, val);
}

namespace expr
{

value *
var_msym_value_operation::evaluate_for_cast (struct type *to_type,
					     struct expression *exp,
					     enum noside noside)
{
  if (noside == EVAL_AVOID_SIDE_EFFECTS)
    return value_zero (to_type, not_lval);

  value *val = evaluate_var_msym_value (noside,
					std::get<1> (m_storage),
					std::get<0> (m_storage));

  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);

  val = value_cast (to_type, val);

  /* Don't allow e.g. '&(int)var_with_no_debug_info'.  */
  if (VALUE_LVAL (val) == lval_memory)
    {
      if (value_lazy (val))
	value_fetch_lazy (val);
      VALUE_LVAL (val) = not_lval;
    }
  return val;
}

value *
var_value_operation::evaluate_for_cast (struct type *to_type,
					struct expression *exp,
					enum noside noside)
{
  value *val = evaluate_var_value (noside,
				   std::get<1> (m_storage),
				   std::get<0> (m_storage));

  if (noside == EVAL_SKIP)
    return eval_skip_value (exp);

  val = value_cast (to_type, val);

  /* Don't allow e.g. '&(int)var_with_no_debug_info'.  */
  if (VALUE_LVAL (val) == lval_memory)
    {
      if (value_lazy (val))
	value_fetch_lazy (val);
      VALUE_LVAL (val) = not_lval;
    }
  return val;
}

}

/* Parse a type expression in the string [P..P+LENGTH).  */

struct type *
parse_and_eval_type (const char *p, int length)
{
  char *tmp = (char *) alloca (length + 4);

  tmp[0] = '(';
  memcpy (tmp + 1, p, length);
  tmp[length + 1] = ')';
  tmp[length + 2] = '0';
  tmp[length + 3] = '\0';
  expression_up expr = parse_expression (tmp);
  if (expr->first_opcode () != UNOP_CAST)
    error (_("Internal error in eval_type."));
  return expr->elts[1].type;
}
