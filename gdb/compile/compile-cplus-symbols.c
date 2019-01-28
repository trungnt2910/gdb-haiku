/* Convert symbols from GDB to GCC

   Copyright (C) 2014-2019 Free Software Foundation, Inc.

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
#include "compile-internal.h"
#include "compile-cplus.h"
#include "common/gdb_assert.h"
#include "symtab.h"
#include "parser-defs.h"
#include "block.h"
#include "objfiles.h"
#include "compile.h"
#include "value.h"
#include "exceptions.h"
#include "gdbtypes.h"
#include "dwarf2loc.h"
#include "cp-support.h"
#include "gdbcmd.h"
#include "compile-c.h"

/* Convert a given symbol, SYM, to the compiler's representation.
   INSTANCE is the compiler instance.  IS_GLOBAL is true if the
   symbol came from the global scope.  IS_LOCAL is true if the symbol
   came from a local scope.  (Note that the two are not strictly
   inverses because the symbol might have come from the static
   scope.)  */

static void
convert_one_symbol (compile_cplus_instance *instance,
		    struct block_symbol sym, bool is_global, bool is_local)
{
  /* Squash compiler warning.  */
  gcc_type sym_type = 0;
  const char *filename = symbol_symtab (sym.symbol)->filename;
  unsigned short line = SYMBOL_LINE (sym.symbol);

  instance->error_symbol_once (sym.symbol);

  if (SYMBOL_CLASS (sym.symbol) == LOC_LABEL)
    sym_type = 0;
  else
    sym_type = instance->convert_type (SYMBOL_TYPE (sym.symbol));

  if (SYMBOL_DOMAIN (sym.symbol) == STRUCT_DOMAIN)
    {
      /* Nothing to do.  */
    }
  else
    {
      /* Squash compiler warning.  */
      gcc_cp_symbol_kind_flags kind = GCC_CP_FLAG_BASE;
      CORE_ADDR addr = 0;
      std::string name;
      gdb::unique_xmalloc_ptr<char> symbol_name;

      switch (SYMBOL_CLASS (sym.symbol))
	{
	case LOC_TYPEDEF:
	  if (TYPE_CODE (SYMBOL_TYPE (sym.symbol)) == TYPE_CODE_TYPEDEF)
	    kind = GCC_CP_SYMBOL_TYPEDEF;
	  else  if (TYPE_CODE (SYMBOL_TYPE (sym.symbol)) == TYPE_CODE_NAMESPACE)
	    return;
	  break;

	case LOC_LABEL:
	  kind = GCC_CP_SYMBOL_LABEL;
	  addr = SYMBOL_VALUE_ADDRESS (sym.symbol);
	  break;

	case LOC_BLOCK:
	  {
	    kind = GCC_CP_SYMBOL_FUNCTION;
	    addr = BLOCK_START (SYMBOL_BLOCK_VALUE (sym.symbol));
	    if (is_global && TYPE_GNU_IFUNC (SYMBOL_TYPE (sym.symbol)))
	      addr = gnu_ifunc_resolve_addr (target_gdbarch (), addr);
	  }
	  break;

	case LOC_CONST:
	  if (TYPE_CODE (SYMBOL_TYPE (sym.symbol)) == TYPE_CODE_ENUM)
	    {
	      /* Already handled by convert_enum.  */
	      return;
	    }
	  instance->plugin ().build_constant
	    (sym_type, SYMBOL_NATURAL_NAME (sym.symbol),
	     SYMBOL_VALUE (sym.symbol), filename, line);
	  return;

	case LOC_CONST_BYTES:
	  error (_("Unsupported LOC_CONST_BYTES for symbol \"%s\"."),
		 SYMBOL_PRINT_NAME (sym.symbol));

	case LOC_UNDEF:
	  internal_error (__FILE__, __LINE__, _("LOC_UNDEF found for \"%s\"."),
			  SYMBOL_PRINT_NAME (sym.symbol));

	case LOC_COMMON_BLOCK:
	  error (_("Fortran common block is unsupported for compilation "
		   "evaluaton of symbol \"%s\"."),
		 SYMBOL_PRINT_NAME (sym.symbol));

	case LOC_OPTIMIZED_OUT:
	  error (_("Symbol \"%s\" cannot be used for compilation evaluation "
		   "as it is optimized out."),
		 SYMBOL_PRINT_NAME (sym.symbol));

	case LOC_COMPUTED:
	  if (is_local)
	    goto substitution;
	  /* Probably TLS here.  */
	  warning (_("Symbol \"%s\" is thread-local and currently can only "
		     "be referenced from the current thread in "
		     "compiled code."),
		   SYMBOL_PRINT_NAME (sym.symbol));
	  /* FALLTHROUGH */
	case LOC_UNRESOLVED:
	  /* 'symbol_name' cannot be used here as that one is used only for
	     local variables from compile_dwarf_expr_to_c.
	     Global variables can be accessed by GCC only by their address, not
	     by their name.  */
	  {
	    struct value *val;
	    struct frame_info *frame = nullptr;

	    if (symbol_read_needs_frame (sym.symbol))
	      {
		frame = get_selected_frame (nullptr);
		if (frame == nullptr)
		  error (_("Symbol \"%s\" cannot be used because "
			   "there is no selected frame"),
			 SYMBOL_PRINT_NAME (sym.symbol));
	      }

	    val = read_var_value (sym.symbol, sym.block, frame);
	    if (VALUE_LVAL (val) != lval_memory)
	      error (_("Symbol \"%s\" cannot be used for compilation "
		       "evaluation as its address has not been found."),
		     SYMBOL_PRINT_NAME (sym.symbol));

	    kind = GCC_CP_SYMBOL_VARIABLE;
	    addr = value_address (val);
	  }
	  break;


	case LOC_REGISTER:
	case LOC_ARG:
	case LOC_REF_ARG:
	case LOC_REGPARM_ADDR:
	case LOC_LOCAL:
	substitution:
	  kind = GCC_CP_SYMBOL_VARIABLE;
	  symbol_name = c_symbol_substitution_name (sym.symbol);
	  break;

	case LOC_STATIC:
	  kind = GCC_CP_SYMBOL_VARIABLE;
	  addr = SYMBOL_VALUE_ADDRESS (sym.symbol);
	  break;

	case LOC_FINAL_VALUE:
	default:
	  gdb_assert_not_reached ("Unreachable case in convert_one_symbol.");
	}

      /* Don't emit local variable decls for a raw expression.  */
      if (instance->scope () != COMPILE_I_RAW_SCOPE || symbol_name == nullptr)
	{
	  /* For non-local symbols, create/push a new scope so that the
	     symbol is properly scoped to the plug-in.  */
	  if (!is_local)
	    {
	      compile_scope scope
		= instance->new_scope (SYMBOL_NATURAL_NAME (sym.symbol),
				       SYMBOL_TYPE (sym.symbol));
	      if (scope.nested_type () != GCC_TYPE_NONE)
		{
		  /* We found a symbol for this type that was defined inside
		     some other symbol, e.g., a class tyepdef defined.  */
		  return;
		}

	      instance->enter_scope (std::move (scope));
	    }

	  /* Get the `raw' name of the symbol.  */
	  if (name.empty () && SYMBOL_NATURAL_NAME (sym.symbol) != nullptr)
	    name = compile_cplus_instance::decl_name
	      (SYMBOL_NATURAL_NAME (sym.symbol)).get ();

	  /* Define the decl.  */
	  instance->plugin ().build_decl
	    ("variable", name.c_str (), kind, sym_type,
	     symbol_name.get (), addr, filename, line);

	  /* Pop scope for non-local symbols.  */
	  if (!is_local)
	    instance->leave_scope ();
	}
    }
}

/* Convert a full symbol to its gcc form.  CONTEXT is the compiler to
   use, IDENTIFIER is the name of the symbol, SYM is the symbol
   itself, and DOMAIN is the domain which was searched.  */

static void
convert_symbol_sym (compile_cplus_instance *instance,
		    const char *identifier, struct block_symbol sym,
		    domain_enum domain)
{
  /* If we found a symbol and it is not in the  static or global
     scope, then we should first convert any static or global scope
     symbol of the same name.  This lets this unusual case work:

     int x; // Global.
     int func(void)
     {
     int x;
     // At this spot, evaluate "extern int x; x"
     }
  */

  const struct block *static_block = block_static_block (sym.block);
  /* STATIC_BLOCK is NULL if FOUND_BLOCK is the global block.  */
  bool is_local_symbol = (sym.block != static_block && static_block != nullptr);
  if (is_local_symbol)
    {
      struct block_symbol global_sym;

      global_sym = lookup_symbol (identifier, nullptr, domain, nullptr);
      /* If the outer symbol is in the static block, we ignore it, as
	 it cannot be referenced.  */
      if (global_sym.symbol != nullptr
	  && global_sym.block != block_static_block (global_sym.block))
	{
	  if (compile_debug)
	    fprintf_unfiltered (gdb_stdlog,
				"gcc_convert_symbol \"%s\": global symbol\n",
				identifier);
	  convert_one_symbol (instance, global_sym, true, false);
	}
    }

  if (compile_debug)
    fprintf_unfiltered (gdb_stdlog,
			"gcc_convert_symbol \"%s\": local symbol\n",
			identifier);
  convert_one_symbol (instance, sym, false, is_local_symbol);
}

/* Convert a minimal symbol to its gcc form.  CONTEXT is the compiler
   to use and BMSYM is the minimal symbol to convert.  */

static void
convert_symbol_bmsym (compile_cplus_instance *instance,
		      struct bound_minimal_symbol bmsym)
{
  struct minimal_symbol *msym = bmsym.minsym;
  struct objfile *objfile = bmsym.objfile;
  struct type *type;
  gcc_cp_symbol_kind_flags kind;
  gcc_type sym_type;
  CORE_ADDR addr;

  addr = MSYMBOL_VALUE_ADDRESS (objfile, msym);

  /* Conversion copied from write_exp_msymbol.  */
  switch (MSYMBOL_TYPE (msym))
    {
    case mst_text:
    case mst_file_text:
    case mst_solib_trampoline:
      type = objfile_type (objfile)->nodebug_text_symbol;
      kind = GCC_CP_SYMBOL_FUNCTION;
      break;

    case mst_text_gnu_ifunc:
      /* nodebug_text_gnu_ifunc_symbol would cause:
	 function return type cannot be function  */
      type = objfile_type (objfile)->nodebug_text_symbol;
      kind = GCC_CP_SYMBOL_FUNCTION;
      addr = gnu_ifunc_resolve_addr (target_gdbarch (), addr);
      break;

    case mst_data:
    case mst_file_data:
    case mst_bss:
    case mst_file_bss:
      type = objfile_type (objfile)->nodebug_data_symbol;
      kind = GCC_CP_SYMBOL_VARIABLE;
      break;

    case mst_slot_got_plt:
      type = objfile_type (objfile)->nodebug_got_plt_symbol;
      kind = GCC_CP_SYMBOL_FUNCTION;
      break;

    default:
      type = objfile_type (objfile)->nodebug_unknown_symbol;
      kind = GCC_CP_SYMBOL_VARIABLE;
      break;
    }

  sym_type = instance->convert_type (type);
  instance->plugin ().push_namespace ("");
  instance->plugin ().build_decl
    ("minsym", MSYMBOL_NATURAL_NAME (msym), kind, sym_type, nullptr, addr,
     nullptr, 0);
  instance->plugin ().pop_binding_level ("");
}

/* See compile-cplus.h.  */

void
gcc_cplus_convert_symbol (void *datum,
			  struct gcc_cp_context *gcc_context,
			  enum gcc_cp_oracle_request request,
			  const char *identifier)
{
  if (compile_debug)
    fprintf_unfiltered (gdb_stdlog,
			"got oracle request for \"%s\"\n", identifier);

  bool found = false;
  compile_cplus_instance *instance = (compile_cplus_instance *) datum;

  TRY
    {
      /* Symbol searching is a three part process unfortunately.  */

      /* First do a "standard" lookup, converting any found symbols.
	 This will find variables in the current scope.  */

      struct block_symbol sym
	= lookup_symbol (identifier, instance->block (), VAR_DOMAIN, nullptr);

      if (sym.symbol != nullptr)
	{
	  found = true;
	  convert_symbol_sym (instance, identifier, sym, VAR_DOMAIN);
	}

      /* Then use linespec.c's multi-symbol search.  This should find
	 all non-variable symbols for which we have debug info.  */

      symbol_searcher searcher;
      searcher.find_all_symbols (identifier, current_language,
				 ALL_DOMAIN, nullptr, nullptr);

      /* Convert any found symbols.  */
      for (const auto &it : searcher.matching_symbols ())
	{
	  /* Don't convert the symbol found above, if any, twice!  */
	  if (it.symbol != sym.symbol)
	    {
	      found = true;
	      convert_symbol_sym (instance, identifier, it,
				  SYMBOL_DOMAIN (it.symbol));
	    }
	}

      /* Finally, if no symbols have been found, fall back to minsyms.  */
      if (!found)
	{
	  for (const auto &it : searcher.matching_msymbols ())
	    {
	      found = true;
	      convert_symbol_bmsym (instance, it);
	    }
	}
    }
  CATCH (e, RETURN_MASK_ALL)
    {
      /* We can't allow exceptions to escape out of this callback.  Safest
	 is to simply emit a gcc error.  */
      instance->plugin ().error (e.what ());
    }
  END_CATCH

  if (compile_debug && !found)
    fprintf_unfiltered (gdb_stdlog,
			"gcc_convert_symbol \"%s\": lookup_symbol failed\n",
			identifier);

  if (compile_debug)
    {
      if (found)
	fprintf_unfiltered (gdb_stdlog, "found type for %s\n", identifier);
      else
	{
	  fprintf_unfiltered (gdb_stdlog, "did not find type for %s\n",
			      identifier);
	}
    }

  return;
}

/* See compile-cplus.h.  */

gcc_address
gcc_cplus_symbol_address (void *datum, struct gcc_cp_context *gcc_context,
			  const char *identifier)
{
  compile_cplus_instance *instance = (compile_cplus_instance *) datum;
  gcc_address result = 0;
  int found = 0;

  if (compile_debug)
    fprintf_unfiltered (gdb_stdlog,
			"got oracle request for address of %s\n", identifier);

  /* We can't allow exceptions to escape out of this callback.  Safest
     is to simply emit a gcc error.  */
  TRY
    {
      struct symbol *sym
	= lookup_symbol (identifier, nullptr, VAR_DOMAIN, nullptr).symbol;

      if (sym != nullptr && SYMBOL_CLASS (sym) == LOC_BLOCK)
	{
	  if (compile_debug)
	    fprintf_unfiltered (gdb_stdlog,
				"gcc_symbol_address \"%s\": full symbol\n",
				identifier);
	  result = BLOCK_START (SYMBOL_BLOCK_VALUE (sym));
	  if (TYPE_GNU_IFUNC (SYMBOL_TYPE (sym)))
	    result = gnu_ifunc_resolve_addr (target_gdbarch (), result);
	  found = 1;
	}
      else
	{
	  struct bound_minimal_symbol msym;

	  msym = lookup_bound_minimal_symbol (identifier);
	  if (msym.minsym != nullptr)
	    {
	      if (compile_debug)
		fprintf_unfiltered (gdb_stdlog,
				    "gcc_symbol_address \"%s\": minimal "
				    "symbol\n",
				    identifier);
	      result = BMSYMBOL_VALUE_ADDRESS (msym);
	      if (MSYMBOL_TYPE (msym.minsym) == mst_text_gnu_ifunc)
		result = gnu_ifunc_resolve_addr (target_gdbarch (), result);
	      found = 1;
	    }
	}
    }

  CATCH (e, RETURN_MASK_ERROR)
    {
      instance->plugin ().error (e.what ());
    }
  END_CATCH

  if (compile_debug && !found)
    fprintf_unfiltered (gdb_stdlog,
			"gcc_symbol_address \"%s\": failed\n",
			identifier);

  if (compile_debug)
    {
      if (found)
	fprintf_unfiltered (gdb_stdlog, "found address for %s!\n", identifier);
      else
	fprintf_unfiltered (gdb_stdlog,
			    "did not find address for %s\n", identifier);
    }

  return result;
}
