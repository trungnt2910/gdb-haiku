#readelf: -wf
#name: CFI on SH
The section .eh_frame contains:

00000000 00000010 00000000 CIE
  Version:               1
  Augmentation:          "zR"
  Code alignment factor: 2
  Data alignment factor: -4
  Return address column: 17
  Augmentation data:     1b

  DW_CFA_def_cfa: r15 ofs 0

00000014 00000020 00000018 FDE cie=00000000 pc=0000001c..00000048
  DW_CFA_advance_loc: 2 to 0000001e
  DW_CFA_def_cfa_offset: 4
  DW_CFA_advance_loc: 2 to 00000020
  DW_CFA_def_cfa_offset: 8
  DW_CFA_offset: r15 at cfa-4
  DW_CFA_offset: r17 at cfa-8
  DW_CFA_advance_loc: 6 to 00000026
  DW_CFA_def_cfa_reg: r14
  DW_CFA_advance_loc: 2 to 00000028
  DW_CFA_def_cfa_offset: 40
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop

