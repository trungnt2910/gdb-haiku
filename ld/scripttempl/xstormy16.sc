#
# Unusual variables checked by this code:
#	NOP - two byte opcode for no-op (defaults to 0)
#	INITIAL_READONLY_SECTIONS - at start of text segment
#	OTHER_READONLY_SECTIONS - other than .text .init .rodata ...
#		(e.g., .PARISC.milli)
#	OTHER_TEXT_SECTIONS - these get put in .text when relocating
#	OTHER_READWRITE_SECTIONS - other than .data .bss .ctors .sdata ...
#		(e.g., .PARISC.global)
#	OTHER_BSS_SECTIONS - other than .bss .sbss ...
#	OTHER_SECTIONS - at the end
#	EXECUTABLE_SYMBOLS - symbols that must be defined for an
#		executable (e.g., _DYNAMIC_LINK)
#	TEXT_START_SYMBOLS - symbols that appear at the start of the
#		.text section.
#	DATA_START_SYMBOLS - symbols that appear at the start of the
#		.data section.
#	OTHER_GOT_SYMBOLS - symbols defined just before .got.
#	OTHER_GOT_SECTIONS - sections just after .got and .sdata.
#	OTHER_BSS_SYMBOLS - symbols that appear at the start of the
#		.bss section besides __bss_start.
#	INPUT_FILES - INPUT command of files to always include
#	INIT_START, INIT_END -  statements just before and just after
# 	combination of .init sections.
#	FINI_START, FINI_END - statements just before and just after
# 	combination of .fini sections.
#
# When adding sections, do note that the names of some sections are used
# when specifying the start address of the next.
#

#  Many sections come in three flavours.  There is the 'real' section,
#  like ".data".  Then there are the per-procedure or per-variable
#  sections, generated by -ffunction-sections and -fdata-sections in GCC,
#  and useful for --gc-sections, which for a variable "foo" might be
#  ".data.foo".  Then there are the linkonce sections, for which the linker
#  eliminates duplicates, which are named like ".gnu.linkonce.d.foo".
#  The exact correspondences are:
#
#  Section	Linkonce section
#  .text	.gnu.linkonce.t.foo
#  .rodata	.gnu.linkonce.r.foo
#  .data	.gnu.linkonce.d.foo
#  .bss		.gnu.linkonce.b.foo
#  .sdata	.gnu.linkonce.s.foo
#  .sbss	.gnu.linkonce.sb.foo
#  .sdata2	.gnu.linkonce.s2.foo
#  .sbss2	.gnu.linkonce.sb2.foo
#
#  Each of these can also have corresponding .rel.* and .rela.* sections.

test -z "$ENTRY" && ENTRY=_start
test -z "${BIG_OUTPUT_FORMAT}" && BIG_OUTPUT_FORMAT=${OUTPUT_FORMAT}
test -z "${LITTLE_OUTPUT_FORMAT}" && LITTLE_OUTPUT_FORMAT=${OUTPUT_FORMAT}
if [ -z "$MACHINE" ]; then OUTPUT_ARCH=${ARCH}; else OUTPUT_ARCH=${ARCH}:${MACHINE}; fi
test -z "${ELFSIZE}" && ELFSIZE=32
test -z "${ALIGNMENT}" && ALIGNMENT="${ELFSIZE} / 8"
CTOR=".ctors ${CONSTRUCTING-0} : 
  {
    ${CONSTRUCTING+${CTOR_START}}
    /* gcc uses crtbegin.o to find the start of
       the constructors, so we make sure it is
       first.  Because this is a wildcard, it
       doesn't matter if the user does not
       actually link against crtbegin.o; the
       linker won't look for a file to match a
       wildcard.  The wildcard also means that it
       doesn't matter which directory crtbegin.o
       is in.  */

    KEEP (*crtbegin*.o(.ctors))

    /* We don't want to include the .ctor section from
       from the crtend.o file until after the sorted ctors.
       The .ctor section from the crtend file contains the
       end of ctors marker and it must be last */

    KEEP (*(EXCLUDE_FILE (*crtend*.o $OTHER_EXCLUDE_FILES) .ctors))
    KEEP (*(SORT(.ctors.*)))
    KEEP (*(.ctors))
    ${CONSTRUCTING+${CTOR_END}}
  } > ROM"

DTOR=" .dtors       ${CONSTRUCTING-0} :
  {
    ${CONSTRUCTING+${DTOR_START}}
    KEEP (*crtbegin*.o(.dtors))
    KEEP (*(EXCLUDE_FILE (*crtend*.o $OTHER_EXCLUDE_FILES) .dtors))
    KEEP (*(SORT(.dtors.*)))
    KEEP (*(.dtors))
    ${CONSTRUCTING+${DTOR_END}}
  } > ROM"

cat <<EOF
OUTPUT_FORMAT("${OUTPUT_FORMAT}", "${BIG_OUTPUT_FORMAT}",
	      "${LITTLE_OUTPUT_FORMAT}")
OUTPUT_ARCH(${OUTPUT_ARCH})
ENTRY(${ENTRY})

${RELOCATING+${LIB_SEARCH_DIRS}}
${RELOCATING+${EXECUTABLE_SYMBOLS}}
${RELOCATING+${INPUT_FILES}}
${RELOCATING- /* For some reason, the Solaris linker makes bad executables
  if gld -r is used and the intermediate file has sections starting
  at non-zero addresses.  Could be a Solaris ld bug, could be a GNU ld
  bug.  But for now assigning the zero vmas works.  */}

/* There are two memory regions we care about, one from 0 through 0x7F00
   that is RAM and one from 0x8000 up which is ROM.  */
MEMORY 
{
  RAM (w) : ORIGIN = 0, LENGTH = 0x7F00
  ROM (!w) : ORIGIN = 0x8000, LENGTH = 0xFF8000
}

SECTIONS
{
  .data  ${RELOCATING-0} :
  {
    ${RELOCATING+${DATA_START_SYMBOLS}}
    *(.data)
    ${RELOCATING+*(.data.*)}
    ${RELOCATING+*(.gnu.linkonce.d.*)}
    ${CONSTRUCTING+SORT(CONSTRUCTORS)}
  } > RAM
  ${RELOCATING+${OTHER_READWRITE_SECTIONS}}
  ${RELOCATING+${OTHER_GOT_SYMBOLS}}
  ${RELOCATING+${OTHER_GOT_SECTIONS}}
  ${RELOCATING+_edata = .;}
  ${RELOCATING+PROVIDE (edata = .);}
  ${RELOCATING+__bss_start = .;}
  ${RELOCATING+${OTHER_BSS_SYMBOLS}}
  .bss     ${RELOCATING-0} :
  {
   *(.dynbss)
   *(.bss)
   ${RELOCATING+*(.bss.*)}
   ${RELOCATING+*(.gnu.linkonce.b.*)}
   *(COMMON)
   /* Align here to ensure that the .bss section occupies space up to
      _end.  Align after .bss to ensure correct alignment even if the
      .bss section disappears because there are no input sections.  */
   ${RELOCATING+. = ALIGN(${ALIGNMENT});}
  } > RAM
  ${RELOCATING+${OTHER_BSS_SECTIONS}}
  ${RELOCATING+. = ALIGN(${ALIGNMENT});}
  ${RELOCATING+_end = .;}
  ${RELOCATING+__stack = .;}
  ${RELOCATING+${OTHER_BSS_END_SYMBOLS}}
  ${RELOCATING+PROVIDE (end = .);}

  /* Read-only sections in ROM.  */
  .int_vec     ${RELOCATING-0} : { *(.int_vec)	} > ROM

  .rodata ${RELOCATING-0} : { *(.rodata) ${RELOCATING+*(.rodata.*)} ${RELOCATING+*(.gnu.linkonce.r.*)} } > ROM
  ${RELOCATING+${CTOR}}
  ${RELOCATING+${DTOR}}
  .eh_frame : { KEEP (*(.eh_frame)) } > ROM
  .gcc_except_table : { *(.gcc_except_table) } > ROM
  .plt : { *(.plt) } > ROM

  .text    ${RELOCATING-0} :
  {
    ${RELOCATING+${TEXT_START_SYMBOLS}}
    *(.text)
    ${RELOCATING+*(.text.*)}
    *(.stub)
    /* .gnu.warning sections are handled specially by elf32.em.  */
    *(.gnu.warning)
    ${RELOCATING+*(.gnu.linkonce.t.*)}
    ${RELOCATING+${OTHER_TEXT_SECTIONS}}
  } > ROM =${NOP-0}
  .init        ${RELOCATING-0} : 
  { 
    ${RELOCATING+${INIT_START}}
    KEEP (*(.init))
    ${RELOCATING+${INIT_END}}
  } > ROM =${NOP-0}
  .fini    ${RELOCATING-0} :
  {
    ${RELOCATING+${FINI_START}}
    KEEP (*(.fini))
    ${RELOCATING+${FINI_END}}
  } > ROM =${NOP-0}
  ${RELOCATING+PROVIDE (__etext = .);}
  ${RELOCATING+PROVIDE (_etext = .);}
  ${RELOCATING+PROVIDE (etext = .);}
  ${RELOCATING+${OTHER_READONLY_SECTIONS}}


  /* Stabs debugging sections.  */
  .stab 0 : { *(.stab) }
  .stabstr 0 : { *(.stabstr) }
  .stab.excl 0 : { *(.stab.excl) }
  .stab.exclstr 0 : { *(.stab.exclstr) }
  .stab.index 0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }

  .comment 0 : { *(.comment) }

  /* DWARF debug sections.
     Symbols in the DWARF debugging sections are relative to the beginning
     of the section so we begin them at 0.  */

  /* DWARF 1 */
  .debug          0 : { *(.debug) }
  .line           0 : { *(.line) }

  /* GNU DWARF 1 extensions */
  .debug_srcinfo  0 : { *(.debug_srcinfo) }
  .debug_sfnames  0 : { *(.debug_sfnames) }

  /* DWARF 1.1 and DWARF 2 */
  .debug_aranges  0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }

  /* DWARF 2 */
  .debug_info     0 : { *(.debug_info) *(.gnu.linkonce.wi.*) }
  .debug_abbrev   0 : { *(.debug_abbrev) }
  .debug_line     0 : { *(.debug_line) }
  .debug_frame    0 : { *(.debug_frame) }
  .debug_str      0 : { *(.debug_str) }
  .debug_loc      0 : { *(.debug_loc) }
  .debug_macinfo  0 : { *(.debug_macinfo) }

  /* SGI/MIPS DWARF 2 extensions */
  .debug_weaknames 0 : { *(.debug_weaknames) }
  .debug_funcnames 0 : { *(.debug_funcnames) }
  .debug_typenames 0 : { *(.debug_typenames) }
  .debug_varnames  0 : { *(.debug_varnames) }

  ${RELOCATING+${OTHER_RELOCATING_SECTIONS}}

  /* These must appear regardless of ${RELOCATING}.  */
  ${OTHER_SECTIONS}
}
EOF
