/* Definitions for a frame unwinder, for GDB, the GNU debugger.

   Copyright (C) 2003-2024 Free Software Foundation, Inc.

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

#if !defined (FRAME_UNWIND_H)
#define FRAME_UNWIND_H 1

struct frame_data;
class frame_info_ptr;
struct frame_id;
struct frame_unwind;
struct gdbarch;
struct regcache;
struct value;

#include "frame.h"

/* The following unwind functions assume a chain of frames forming the
   sequence: (outer) prev <-> this <-> next (inner).  All the
   functions are called with this frame's `struct frame_info' and
   prologue cache.

   THIS frame's register values can be obtained by unwinding NEXT
   frame's registers (a recursive operation).

   THIS frame's prologue cache can be used to cache information such
   as where this frame's prologue stores the previous frame's
   registers.  */

/* Given THIS frame, take a whiff of its registers (namely
   the PC and attributes) and if SELF is the applicable unwinder,
   return non-zero.  Possibly also initialize THIS_PROLOGUE_CACHE; but
   only if returning 1.  Initializing THIS_PROLOGUE_CACHE in other
   cases (0 return) is invalid.  In case of exception, the caller has
   to set *THIS_PROLOGUE_CACHE to NULL.  */

typedef int (frame_sniffer_ftype) (const struct frame_unwind *self,
				   frame_info_ptr this_frame,
				   void **this_prologue_cache);

typedef enum unwind_stop_reason (frame_unwind_stop_reason_ftype)
  (frame_info_ptr this_frame, void **this_prologue_cache);

/* A default frame sniffer which always accepts the frame.  Used by
   fallback prologue unwinders.  */

int default_frame_sniffer (const struct frame_unwind *self,
			   frame_info_ptr this_frame,
			   void **this_prologue_cache);

/* A default stop_reason callback which always claims the frame is
   unwindable.  */

enum unwind_stop_reason
  default_frame_unwind_stop_reason (frame_info_ptr this_frame,
				    void **this_cache);

/* A default unwind_pc callback that simply unwinds the register identified
   by GDBARCH_PC_REGNUM.  */

extern CORE_ADDR default_unwind_pc (struct gdbarch *gdbarch,
				    frame_info_ptr next_frame);

/* A default unwind_sp callback that simply unwinds the register identified
   by GDBARCH_SP_REGNUM.  */

extern CORE_ADDR default_unwind_sp (struct gdbarch *gdbarch,
				    frame_info_ptr next_frame);

/* Assuming the frame chain: (outer) prev <-> this <-> next (inner);
   use THIS frame, and through it the NEXT frame's register unwind
   method, to determine the frame ID of THIS frame.

   A frame ID provides an invariant that can be used to re-identify an
   instance of a frame.  It is a combination of the frame's `base' and
   the frame's function's code address.

   Traditionally, THIS frame's ID was determined by examining THIS
   frame's function's prologue, and identifying the register/offset
   used as THIS frame's base.

   Example: An examination of THIS frame's prologue reveals that, on
   entry, it saves the PC(+12), SP(+8), and R1(+4) registers
   (decrementing the SP by 12).  Consequently, the frame ID's base can
   be determined by adding 12 to the THIS frame's stack-pointer, and
   the value of THIS frame's SP can be obtained by unwinding the NEXT
   frame's SP.

   THIS_PROLOGUE_CACHE can be used to share any prolog analysis data
   with the other unwind methods.  Memory for that cache should be
   allocated using FRAME_OBSTACK_ZALLOC().  */

typedef void (frame_this_id_ftype) (frame_info_ptr this_frame,
				    void **this_prologue_cache,
				    struct frame_id *this_id);

/* Assuming the frame chain: (outer) prev <-> this <-> next (inner);
   use THIS frame, and implicitly the NEXT frame's register unwind
   method, to unwind THIS frame's registers (returning the value of
   the specified register REGNUM in the previous frame).

   Traditionally, THIS frame's registers were unwound by examining
   THIS frame's function's prologue and identifying which registers
   that prolog code saved on the stack.

   Example: An examination of THIS frame's prologue reveals that, on
   entry, it saves the PC(+12), SP(+8), and R1(+4) registers
   (decrementing the SP by 12).  Consequently, the value of the PC
   register in the previous frame is found in memory at SP+12, and
   THIS frame's SP can be obtained by unwinding the NEXT frame's SP.

   This function takes THIS_FRAME as an argument.  It can find the
   values of registers in THIS frame by calling get_frame_register
   (THIS_FRAME), and reinvoke itself to find other registers in the
   PREVIOUS frame by calling frame_unwind_register (THIS_FRAME).

   The result is a GDB value object describing the register value.  It
   may be a lazy reference to memory, a lazy reference to the value of
   a register in THIS frame, or a non-lvalue.

   If the previous frame's register was not saved by THIS_FRAME and is
   therefore undefined, return a wholly optimized-out not_lval value.

   THIS_PROLOGUE_CACHE can be used to share any prolog analysis data
   with the other unwind methods.  Memory for that cache should be
   allocated using FRAME_OBSTACK_ZALLOC().  */

typedef struct value * (frame_prev_register_ftype)
  (frame_info_ptr this_frame, void **this_prologue_cache,
   int regnum);

/* Deallocate extra memory associated with the frame cache if any.  */

typedef void (frame_dealloc_cache_ftype) (frame_info *self,
					  void *this_cache);

/* Assuming the frame chain: (outer) prev <-> this <-> next (inner);
   use THIS frame, and implicitly the NEXT frame's register unwind
   method, return PREV frame's architecture.  */

typedef struct gdbarch *(frame_prev_arch_ftype) (frame_info_ptr this_frame,
						 void **this_prologue_cache);

enum frame_unwind_class {
  FRAME_UNWIND_GDB,
  FRAME_UNWIND_EXTENSION,
  FRAME_UNWIND_DEBUGINFO,
  FRAME_UNWIND_ARCH,
};

class frame_unwind
{
private:
  const char *m_name;
  /* The frame's type.  Should this instead be a collection of
     predicates that test the frame for various attributes?  */
  enum frame_type m_type;
  /* What kind of unwinder is this.  It generally follows from where
     the unwinder was added or where it looks for information to do the
     unwinding.  */
  enum frame_unwind_class m_unwinder_class;
  const struct frame_data *m_unwind_data;
public:
  frame_unwind (const char *n, frame_type t, frame_unwind_class c,
		       const struct frame_data *d)
    : m_name (n), m_type (t), m_unwinder_class (c), m_unwind_data (d) { }

  const char *name () const
  {
    return m_name;
  }

  enum frame_type type () const
  {
    return m_type;
  }

  enum frame_unwind_class unwinder_class () const
  {
    return m_unwinder_class;
  }

  const struct frame_data *unwind_data () const
  {
    return m_unwind_data;
  }

  /* Default stop_reason function.  It reports NO_REASON, unless the
     frame is the outermost.  */
  virtual enum unwind_stop_reason stop_reason (frame_info_ptr this_frame,
					       void **this_prologue_cache) const;

  /* Default frame sniffer.  Will always return that the unwinder
     is able to unwind the frame.  */
  virtual int sniffer (const frame_unwind *self,
		       frame_info_ptr this_frame,
		       void **this_prologue_cache) const;

  /* The following methods are here mostly for interface functionality.  They
     all throw an error when called, as a safe way to check if an unwinder has
     implemented the desired functionality.  */

  /* Calculate the ID of the given frame using this unwinder.  */
  virtual void this_id (frame_info_ptr this_frame, void **this_prologue_cache,
			struct frame_id *id) const
  {
    error (_("No method this_id implemented for unwinder %s"), m_name);
  }

  /* Get the value of a register in a previous frame.  */
  virtual struct value *prev_register (frame_info_ptr this_frame,
					     void **this_prologue_cache,
					     int regnum) const
  {
    error (_("No method prev_register implemented for unwinder %s"), m_name);
  }
  
  /* Properly deallocate the cache.  */
  virtual void dealloc_cache (frame_info *self, void *this_cache) const
  {
    error (_("No method dealloc_cache implemented for unwinder %s"), m_name);
  }

  /* Get the previous architecture.  */
  virtual struct gdbarch *prev_arch (frame_info_ptr this_frame,
				     void **this_prologue_cache) const
  {
    error (_("No method prev_arch implemented for unwinder %s"), m_name);
  }
};

/* This is a legacy version of the frame unwinder.  The original struct
   used function pointers for callbacks, this updated version has a
   method that just passes the parameters along to the callback
   pointer.  */
class frame_unwind_legacy : public frame_unwind
{
public:
  /* Should an attribute indicating the frame's address-in-block go
     here?  */
  frame_unwind_stop_reason_ftype *stop_reason_p;
  frame_this_id_ftype *this_id_p;
  frame_prev_register_ftype *prev_register_p;
  frame_sniffer_ftype *sniffer_p;
  frame_dealloc_cache_ftype *dealloc_cache_p;
  frame_prev_arch_ftype *prev_arch_p;
//public:
  frame_unwind_legacy (const char *n, frame_type t, frame_unwind_class c,
		       frame_unwind_stop_reason_ftype *sr,
		       frame_this_id_ftype *ti,
		       frame_prev_register_ftype *pr,
		       const struct frame_data *ud,
		       frame_sniffer_ftype *s,
		       frame_dealloc_cache_ftype *dc = nullptr,
		       frame_prev_arch_ftype *pa = nullptr)
  : frame_unwind (n, t, c, ud), stop_reason_p (sr),
    this_id_p (ti), prev_register_p (pr), sniffer_p (s),
    dealloc_cache_p (dc), prev_arch_p (pa) { }

  /* This method just passes the parameters to the callback pointer.  */
  enum unwind_stop_reason stop_reason (frame_info_ptr this_frame,
					void **this_prologue_cache) const override;

  /* This method just passes the parameters to the callback pointer.  */
  void this_id (frame_info_ptr this_frame, void **this_prologue_cache,
		 struct frame_id *id) const override;

  /* This method just passes the parameters to the callback pointer.  */
  struct value *prev_register (frame_info_ptr this_frame,
				void **this_prologue_cache,
				int regnum) const override;

  /* This method just passes the parameters to the callback pointer.  */
  int sniffer (const frame_unwind *self,
		frame_info_ptr this_frame,
		void **this_prologue_cache) const override;

  /* This method just passes the parameters to the callback pointer.
     It is safe to call this method if no callback is installed, it
     just turns into a noop.  */
  void dealloc_cache (frame_info *self, void *this_cache) const override;

  /* This method just passes the parameters to the callback pointer.
     If this function is called with no installed callback, this method
     will error out.  Wrap calls in try-catch blocks.  */
  struct gdbarch *prev_arch (frame_info_ptr this_frame,
			      void **this_prologue_cache) const override;
};

/* Register a frame unwinder, _prepending_ it to the front of the
   search list (so it is sniffed before previously registered
   unwinders).  By using a prepend, later calls can install unwinders
   that override earlier calls.  This allows, for instance, an OSABI
   to install a more specific sigtramp unwinder that overrides the
   traditional brute-force unwinder.  */
extern void frame_unwind_prepend_unwinder (struct gdbarch *,
					   const struct frame_unwind *);

/* Add a frame sniffer to the list.  The predicates are polled in the
   order that they are appended.  The initial list contains the dummy
   frame sniffer.  */

extern void frame_unwind_append_unwinder (struct gdbarch *gdbarch,
					  const struct frame_unwind *unwinder);

/* Iterate through sniffers for THIS_FRAME frame until one returns with an
   unwinder implementation.  THIS_FRAME->UNWIND must be NULL, it will get set
   by this function.  Possibly initialize THIS_CACHE.  */

extern void frame_unwind_find_by_frame (frame_info_ptr this_frame,
					void **this_cache);

/* Helper functions for value-based register unwinding.  These return
   a (possibly lazy) value of the appropriate type.  */

/* Return a value which indicates that FRAME did not save REGNUM.  */

struct value *frame_unwind_got_optimized (frame_info_ptr frame,
					  int regnum);

/* Return a value which indicates that FRAME copied REGNUM into
   register NEW_REGNUM.  */

struct value *frame_unwind_got_register (frame_info_ptr frame, int regnum,
					 int new_regnum);

/* Return a value which indicates that FRAME saved REGNUM in memory at
   ADDR.  */

struct value *frame_unwind_got_memory (frame_info_ptr frame, int regnum,
				       CORE_ADDR addr);

/* Return a value which indicates that FRAME's saved version of
   REGNUM has a known constant (computed) value of VAL.  */

struct value *frame_unwind_got_constant (frame_info_ptr frame, int regnum,
					 ULONGEST val);

/* Return a value which indicates that FRAME's saved version of
   REGNUM has a known constant (computed) value which is stored
   inside BUF.  */

struct value *frame_unwind_got_bytes (frame_info_ptr frame, int regnum,
				      const gdb_byte *buf);

/* Return a value which indicates that FRAME's saved version of REGNUM
   has a known constant (computed) value of ADDR.  Convert the
   CORE_ADDR to a target address if necessary.  */

struct value *frame_unwind_got_address (frame_info_ptr frame, int regnum,
					CORE_ADDR addr);

#endif
