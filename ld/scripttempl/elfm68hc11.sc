#
# Unusual variables checked by this code:
#	NOP - four byte opcode for no-op (defaults to 0)
#	DATA_ADDR - if end-of-text-plus-one-page isn't right for data start
#	OTHER_READWRITE_SECTIONS - other than .data .bss .ctors .sdata ...
#		(e.g., .PARISC.global)
#	OTHER_SECTIONS - at the end
#	EXECUTABLE_SYMBOLS - symbols that must be defined for an
#		executable (e.g., _DYNAMIC_LINK)
#	TEXT_START_SYMBOLS - symbols that appear at the start of the
#		.text section.
#	DATA_START_SYMBOLS - symbols that appear at the start of the
#		.data section.
#	OTHER_BSS_SYMBOLS - symbols that appear at the start of the
#		.bss section besides __bss_start.
#	EMBEDDED - whether this is for an embedded system. 
#
# When adding sections, do note that the names of some sections are used
# when specifying the start address of the next.
#
test -z "$ENTRY" && ENTRY=_start
test -z "${BIG_OUTPUT_FORMAT}" && BIG_OUTPUT_FORMAT=${OUTPUT_FORMAT}
test -z "${LITTLE_OUTPUT_FORMAT}" && LITTLE_OUTPUT_FORMAT=${OUTPUT_FORMAT}
if [ -z "$MACHINE" ]; then OUTPUT_ARCH=${ARCH}; else OUTPUT_ARCH=${ARCH}:${MACHINE}; fi
test "$LD_FLAG" = "N" && DATA_ADDR=.

CTOR=".ctors  : 
  {
    ${CONSTRUCTING+ PROVIDE (__CTOR_LIST__ = .); }
    ${CONSTRUCTING+${CTOR_START}}
    KEEP (*(.ctors))

    ${CONSTRUCTING+${CTOR_END}}
    ${CONSTRUCTING+ PROVIDE(__CTOR_END__ = .); }
  } ${RELOCATING+ > ${TEXT_MEMORY}}"

DTOR="  .dtors	 :
  {
    ${CONSTRUCTING+ PROVIDE(__DTOR_LIST__ = .); }
    KEEP (*(.dtors))
    ${CONSTRUCTING+ PROVIDE(__DTOR_END__ = .); }
  } ${RELOCATING+ > ${TEXT_MEMORY}}"


VECTORS="
  /* If the 'vectors_addr' symbol is defined, it indicates the start address
     of interrupt vectors.  This depends on the 68HC11 operating mode:

			Addr
     Single chip	0xffc0
     Extended mode	0xffc0
     Bootstrap		0x00c0
     Test		0xbfc0

     In general, the vectors address is 0xffc0.  This can be overriden 
     with the '-defsym vectors_addr=0xbfc0' ld option.

     Note: for the bootstrap mode, the interrupt vectors are at 0xbfc0 but
     they are redirected to 0x00c0 by the internal PROM.  Application's vectors
     must also consist of jump instructions (see Motorola's manual).  */

  PROVIDE (_vectors_addr = DEFINED (vectors_addr) ? vectors_addr : 0xffc0);
  .vectors DEFINED (vectors_addr) ? vectors_addr : 0xffc0 :
  {
    KEEP (*(.vectors))
  }"

#
# We provide two emulations: a fixed on that defines some memory banks
# and a configurable one that includes a user provided memory definition.
#
case $GENERIC_BOARD in
  yes|1|YES)
	MEMORY_DEF="
/* Get memory banks definition from some user configuration file.
   This file must be located in some linker directory (search path
   with -L<dir>). See fixed memory banks emulation script.  */
INCLUDE memory.x;
"
	;;
  *)
MEMORY_DEF="
/* Fixed definition of the available memory banks.
   See generic emulation script for a user defined configuration.  */
MEMORY
{
  page0 (rwx) : ORIGIN = 0x0, LENGTH = 256
  text  (rx)  : ORIGIN = ${ROM_START_ADDR}, LENGTH = ${ROM_SIZE}
  data        : ORIGIN = ${RAM_START_ADDR}, LENGTH = ${RAM_SIZE}
  eeprom      : ORIGIN = ${EEPROM_START_ADDR}, LENGTH = ${EEPROM_SIZE}
}

/* Setup the stack on the top of the data memory bank.  */
PROVIDE (_stack = ${RAM_START_ADDR} + ${RAM_SIZE} - 1);
"
	;;
esac

STARTUP_CODE="
    /* Startup code.  */
    KEEP (*(.install0))	/* Section should setup the stack pointer.  */
    KEEP (*(.install1))	/* Place holder for applications.  */
    KEEP (*(.install2))	/* Optional installation of data sections in RAM.  */
    KEEP (*(.install3))	/* Place holder for applications.  */
    KEEP (*(.install4))	/* Section that calls the main.  */
"

FINISH_CODE="
    /* Finish code.  */
    KEEP (*(.fini0))	/* Beginning of finish code (_exit symbol).  */
    KEEP (*(.fini1))	/* Place holder for applications.  */
    KEEP (*(.fini2))	/* C++ destructors.  */
    KEEP (*(.fini3))	/* Place holder for applications.  */
    KEEP (*(.fini4))	/* Runtime exit.  */
"

PRE_COMPUTE_DATA_SIZE="
/* SCz: this does not work yet... This is supposed to force the loading
   of _map_data.o (from libgcc.a) when the .data section is not empty.
   By doing so, this should bring the code that copies the .data section
   from ROM to RAM at init time.

  ___pre_comp_data_size = SIZEOF(.data);
  __install_data_sections = ___pre_comp_data_size > 0 ?
		__map_data_sections : 0;
*/
"

INSTALL_RELOC="
  .install0  : { *(.install0) }
  .install1  : { *(.install1) }
  .install2  : { *(.install2) }
  .install3  : { *(.install3) }
  .install4  : { *(.install4) }
"

FINISH_RELOC="
  .fini0  : { *(.fini0) }
  .fini1  : { *(.fini1) }
  .fini2  : { *(.fini2) }
  .fini3  : { *(.fini3) }
  .fini4  : { *(.fini4) }
"

BSS_DATA_RELOC="
  .data1  : { *(.data1) }

  /* We want the small data sections together, so single-instruction offsets
     can access them all, and initialized data all before uninitialized, so
     we can shorten the on-disk segment size.  */
  .sdata    : { *(.sdata) }
  .sbss     : { *(.sbss) }
  .scommon  : { *(.scommon) }
"

SOFT_REGS_RELOC="
  .softregs  : { *(.softregs) }
"

cat <<EOF
${RELOCATING+/* Linker script for 68HC11 executable (PROM).  */}
${RELOCATING-/* Linker script for 68HC11 object file (ld -r).  */}

OUTPUT_FORMAT("${OUTPUT_FORMAT}", "${BIG_OUTPUT_FORMAT}",
	      "${LITTLE_OUTPUT_FORMAT}")
OUTPUT_ARCH(${OUTPUT_ARCH})
${RELOCATING+ENTRY(${ENTRY})}

${RELOCATING+${LIB_SEARCH_DIRS}}
${RELOCATING+${EXECUTABLE_SYMBOLS}}
${RELOCATING+${MEMORY_DEF}}

SECTIONS
{
  .hash         : { *(.hash)		}
  .dynsym       : { *(.dynsym)		}
  .dynstr       : { *(.dynstr)		}
  .gnu.version		 : { *(.gnu.version) }
  .gnu.version_d	 : { *(.gnu.version_d) }
  .gnu.version_r	 : { *(.gnu.version_r) }

  .rel.text     :
    {
      *(.rel.text)
      ${RELOCATING+*(.rel.text.*)}
      ${RELOCATING+*(.rel.gnu.linkonce.t.*)}
    }
  .rela.text    :
    {
      *(.rela.text)
      ${RELOCATING+*(.rela.text.*)}
      ${RELOCATING+*(.rela.gnu.linkonce.t.*)}
    }
  .rel.data     :
    {
      *(.rel.data)
      ${RELOCATING+*(.rel.data.*)}
      ${RELOCATING+*(.rel.gnu.linkonce.d.*)}
    }
  .rela.data    :
    {
      *(.rela.data)
      ${RELOCATING+*(.rela.data.*)}
      ${RELOCATING+*(.rela.gnu.linkonce.d.*)}
    }
  .rel.rodata   :
    {
      *(.rel.rodata)
      ${RELOCATING+*(.rel.rodata.*)}
      ${RELOCATING+*(.rel.gnu.linkonce.r.*)}
    }
  .rela.rodata  :
    {
      *(.rela.rodata)
      ${RELOCATING+*(.rela.rodata.*)}
      ${RELOCATING+*(.rela.gnu.linkonce.r.*)}
    }
  .rel.sdata    :
    {
      *(.rel.sdata)
      ${RELOCATING+*(.rel.sdata.*)}
      ${RELOCATING+*(.rel.gnu.linkonce.s.*)}
    }
  .rela.sdata    :
    {
      *(.rela.sdata)
      ${RELOCATING+*(.rela.sdata.*)}
      ${RELOCATING+*(.rela.gnu.linkonce.s.*)}
    }
  .rel.sbss     :
    { 
      *(.rel.sbss)
      ${RELOCATING+*(.rel.sbss.*)}
      ${RELOCATING+*(.rel.gnu.linkonce.sb.*)}
    }
  .rela.sbss    :
    {
      *(.rela.sbss)
      ${RELOCATING+*(.rela.sbss.*)}
      ${RELOCATING+*(.rel.gnu.linkonce.sb.*)}
    }
  .rel.bss      : 
    { 
      *(.rel.bss)
      ${RELOCATING+*(.rel.bss.*)}
      ${RELOCATING+*(.rel.gnu.linkonce.b.*)}
    }
  .rela.bss     : 
    { 
      *(.rela.bss)
      ${RELOCATING+*(.rela.bss.*)}
      ${RELOCATING+*(.rela.gnu.linkonce.b.*)}
    }
  .rel.stext		 : { *(.rel.stest) }
  .rela.stext		 : { *(.rela.stest) }
  .rel.etext		 : { *(.rel.etest) }
  .rela.etext		 : { *(.rela.etest) }
  .rel.sdata		 : { *(.rel.sdata) }
  .rela.sdata		 : { *(.rela.sdata) }
  .rel.edata		 : { *(.rel.edata) }
  .rela.edata		 : { *(.rela.edata) }
  .rel.eit_v		 : { *(.rel.eit_v) }
  .rela.eit_v		 : { *(.rela.eit_v) }
  .rel.ebss		 : { *(.rel.ebss) }
  .rela.ebss		 : { *(.rela.ebss) }
  .rel.srodata		 : { *(.rel.srodata) }
  .rela.srodata		 : { *(.rela.srodata) }
  .rel.erodata		 : { *(.rel.erodata) }
  .rela.erodata		 : { *(.rela.erodata) }
  .rel.got		 : { *(.rel.got) }
  .rela.got		 : { *(.rela.got) }
  .rel.ctors		 : { *(.rel.ctors) }
  .rela.ctors		 : { *(.rela.ctors) }
  .rel.dtors		 : { *(.rel.dtors) }
  .rela.dtors		 : { *(.rela.dtors) }
  .rel.init		 : { *(.rel.init) }
  .rela.init		 : { *(.rela.init) }
  .rel.fini		 : { *(.rel.fini) }
  .rela.fini		 : { *(.rela.fini) }
  .rel.plt		 : { *(.rel.plt) }
  .rela.plt		 : { *(.rela.plt) }

  /* Concatenate .page0 sections.  Put them in the page0 memory bank
     unless we are creating a relocatable file.  */
  .page0 :
  {
    *(.page0)
    ${RELOCATING+*(.softregs)}
  } ${RELOCATING+ > page0}

  /* Start of text section.  */
  .stext  : 
  {
    *(.stext)
  } ${RELOCATING+ > ${TEXT_MEMORY}}

  .init	 :
  {
    *(.init) 
  } ${RELOCATING+=${NOP-0}}

  ${RELOCATING-${INSTALL_RELOC}}
  ${RELOCATING-${FINISH_RELOC}}

  .text :
  {
    /* Put startup code at beginning so that _start keeps same address.  */
    ${RELOCATING+${STARTUP_CODE}}

    ${RELOCATING+*(.init)}
    *(.text)
    ${RELOCATING+*(.text.*)}
    /* .gnu.warning sections are handled specially by elf32.em.  */
    *(.gnu.warning)
    ${RELOCATING+*(.gnu.linkonce.t.*)}
    ${RELOCATING+*(.tramp)}
    ${RELOCATING+*(.tramp.*)}

    ${RELOCATING+${FINISH_CODE}}

    ${RELOCATING+_etext = .;}
    ${RELOCATING+PROVIDE (etext = .);}

  } ${RELOCATING+ > ${TEXT_MEMORY}}

  .eh_frame  :
  {
    KEEP (*(.eh_frame))
  } ${RELOCATING+ > ${TEXT_MEMORY}}

  .gcc_except_table  :
  {
    *(.gcc_except_table)
  } ${RELOCATING+ > ${TEXT_MEMORY}}

  .rodata   :
  {
    *(.rodata)
    ${RELOCATING+*(.rodata.*)}
    ${RELOCATING+*(.gnu.linkonce.r*)}
  } ${RELOCATING+ > ${TEXT_MEMORY}}

  .rodata1  :
  {
    *(.rodata1)
  } ${RELOCATING+ > ${TEXT_MEMORY}}

  /* Constructor and destructor tables are in ROM.  */
  ${RELOCATING+${CTOR}}
  ${RELOCATING+${DTOR}}

  .jcr  :
  {
    KEEP (*(.jcr))
  } ${RELOCATING+ > ${TEXT_MEMORY}}

  /* Start of the data section image in ROM.  */
  ${RELOCATING+__data_image = .;}
  ${RELOCATING+PROVIDE (__data_image = .);}

  /* All read-only sections that normally go in PROM must be above.
     We construct the DATA image section in PROM at end of all these
     read-only sections.  The data image must be copied at init time.
     Refer to GNU ld, Section 3.6.8.2 Output Section LMA.  */
  .data   : ${RELOCATING+AT (__data_image)}
  {
    ${RELOCATING+__data_section_start = .;}
    ${RELOCATING+PROVIDE (__data_section_start = .);}

    ${RELOCATING+${DATA_START_SYMBOLS}}
    ${RELOCATING+*(.sdata)}
    *(.data)
    ${RELOCATING+*(.data.*)}
    ${RELOCATING+*(.data1)}
    ${RELOCATING+*(.gnu.linkonce.d.*)}
    ${CONSTRUCTING+CONSTRUCTORS}

    ${RELOCATING+_edata  =  .;}
    ${RELOCATING+PROVIDE (edata = .);}
  } ${RELOCATING+ > ${DATA_MEMORY}}

  ${RELOCATING+__data_section_size = SIZEOF(.data);}
  ${RELOCATING+PROVIDE (__data_section_size = SIZEOF(.data));}
  ${RELOCATING+__data_image_end = __data_image + __data_section_size;}

  ${RELOCATING+${PRE_COMPUTE_DATA_SIZE}}

  /* .install :
  {
    . = _data_image_end;
  } ${RELOCATING+ > ${TEXT_MEMORY}} */

  /* Relocation for some bss and data sections.  */
  ${RELOCATING-${BSS_DATA_RELOC}}
  ${RELOCATING-${SOFT_REGS_RELOC}}

  .bss  :
  {
    ${RELOCATING+__bss_start = .;}
    ${RELOCATING+*(.sbss)}
    ${RELOCATING+*(.scommon)}

    *(.dynbss)
    *(.bss)
    ${RELOCATING+*(.bss.*)}
    ${RELOCATING+*(.gnu.linkonce.b.*)}
    *(COMMON)
    ${RELOCATING+PROVIDE (_end = .);}
  } ${RELOCATING+ > ${DATA_MEMORY}}
  ${RELOCATING+__bss_size = SIZEOF(.bss);}
  ${RELOCATING+PROVIDE (__bss_size = SIZEOF(.bss));}

  .eeprom  :
  {
    *(.eeprom)
    *(.eeprom.*)
  } ${RELOCATING+ > ${EEPROM_MEMORY}}

  ${RELOCATING+${VECTORS}}

  /* Stabs debugging sections.  */
  .stab		 0 : { *(.stab) }
  .stabstr	 0 : { *(.stabstr) }
  .stab.excl	 0 : { *(.stab.excl) }
  .stab.exclstr	 0 : { *(.stab.exclstr) }
  .stab.index	 0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }

  .comment	 0 : { *(.comment) }

  /* DWARF debug sections.
     Symbols in the DWARF debugging sections are relative to the beginning
     of the section so we begin them at 0.
     Treatment of DWARF debug section must be at end of the linker
     script to avoid problems when there are undefined symbols. It's necessary
     to avoid that the DWARF section is relocated before such undefined
     symbols are found.  */

  /* DWARF 1 */
  .debug	 0 : { *(.debug) }
  .line		 0 : { *(.line) }

  /* GNU DWARF 1 extensions */
  .debug_srcinfo 0 : { *(.debug_srcinfo) }
  .debug_sfnames 0 : { *(.debug_sfnames) }

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
}
EOF
