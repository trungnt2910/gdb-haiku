/* Decode header for crisv32f.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright 1996-2007 Free Software Foundation, Inc.

This file is part of the GNU simulators.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

*/

#ifndef CRISV32F_DECODE_H
#define CRISV32F_DECODE_H

extern const IDESC *crisv32f_decode (SIM_CPU *, IADDR,
                                  CGEN_INSN_INT,
                                  ARGBUF *);
extern void crisv32f_init_idesc_table (SIM_CPU *);
extern void crisv32f_sem_init_idesc_table (SIM_CPU *);
extern void crisv32f_semf_init_idesc_table (SIM_CPU *);

/* Enum declaration for instructions in cpu family crisv32f.  */
typedef enum crisv32f_insn_type {
  CRISV32F_INSN_X_INVALID, CRISV32F_INSN_X_AFTER, CRISV32F_INSN_X_BEFORE, CRISV32F_INSN_X_CTI_CHAIN
 , CRISV32F_INSN_X_CHAIN, CRISV32F_INSN_X_BEGIN, CRISV32F_INSN_MOVE_B_R, CRISV32F_INSN_MOVE_W_R
 , CRISV32F_INSN_MOVE_D_R, CRISV32F_INSN_MOVEQ, CRISV32F_INSN_MOVS_B_R, CRISV32F_INSN_MOVS_W_R
 , CRISV32F_INSN_MOVU_B_R, CRISV32F_INSN_MOVU_W_R, CRISV32F_INSN_MOVECBR, CRISV32F_INSN_MOVECWR
 , CRISV32F_INSN_MOVECDR, CRISV32F_INSN_MOVSCBR, CRISV32F_INSN_MOVSCWR, CRISV32F_INSN_MOVUCBR
 , CRISV32F_INSN_MOVUCWR, CRISV32F_INSN_ADDQ, CRISV32F_INSN_SUBQ, CRISV32F_INSN_CMP_R_B_R
 , CRISV32F_INSN_CMP_R_W_R, CRISV32F_INSN_CMP_R_D_R, CRISV32F_INSN_CMP_M_B_M, CRISV32F_INSN_CMP_M_W_M
 , CRISV32F_INSN_CMP_M_D_M, CRISV32F_INSN_CMPCBR, CRISV32F_INSN_CMPCWR, CRISV32F_INSN_CMPCDR
 , CRISV32F_INSN_CMPQ, CRISV32F_INSN_CMPS_M_B_M, CRISV32F_INSN_CMPS_M_W_M, CRISV32F_INSN_CMPSCBR
 , CRISV32F_INSN_CMPSCWR, CRISV32F_INSN_CMPU_M_B_M, CRISV32F_INSN_CMPU_M_W_M, CRISV32F_INSN_CMPUCBR
 , CRISV32F_INSN_CMPUCWR, CRISV32F_INSN_MOVE_M_B_M, CRISV32F_INSN_MOVE_M_W_M, CRISV32F_INSN_MOVE_M_D_M
 , CRISV32F_INSN_MOVS_M_B_M, CRISV32F_INSN_MOVS_M_W_M, CRISV32F_INSN_MOVU_M_B_M, CRISV32F_INSN_MOVU_M_W_M
 , CRISV32F_INSN_MOVE_R_SPRV32, CRISV32F_INSN_MOVE_SPR_RV32, CRISV32F_INSN_MOVE_M_SPRV32, CRISV32F_INSN_MOVE_C_SPRV32_P2
 , CRISV32F_INSN_MOVE_C_SPRV32_P3, CRISV32F_INSN_MOVE_C_SPRV32_P5, CRISV32F_INSN_MOVE_C_SPRV32_P6, CRISV32F_INSN_MOVE_C_SPRV32_P7
 , CRISV32F_INSN_MOVE_C_SPRV32_P9, CRISV32F_INSN_MOVE_C_SPRV32_P10, CRISV32F_INSN_MOVE_C_SPRV32_P11, CRISV32F_INSN_MOVE_C_SPRV32_P12
 , CRISV32F_INSN_MOVE_C_SPRV32_P13, CRISV32F_INSN_MOVE_C_SPRV32_P14, CRISV32F_INSN_MOVE_C_SPRV32_P15, CRISV32F_INSN_MOVE_SPR_MV32
 , CRISV32F_INSN_MOVE_SS_R, CRISV32F_INSN_MOVE_R_SS, CRISV32F_INSN_MOVEM_R_M_V32, CRISV32F_INSN_MOVEM_M_R_V32
 , CRISV32F_INSN_ADD_B_R, CRISV32F_INSN_ADD_W_R, CRISV32F_INSN_ADD_D_R, CRISV32F_INSN_ADD_M_B_M
 , CRISV32F_INSN_ADD_M_W_M, CRISV32F_INSN_ADD_M_D_M, CRISV32F_INSN_ADDCBR, CRISV32F_INSN_ADDCWR
 , CRISV32F_INSN_ADDCDR, CRISV32F_INSN_ADDS_B_R, CRISV32F_INSN_ADDS_W_R, CRISV32F_INSN_ADDS_M_B_M
 , CRISV32F_INSN_ADDS_M_W_M, CRISV32F_INSN_ADDSCBR, CRISV32F_INSN_ADDSCWR, CRISV32F_INSN_ADDU_B_R
 , CRISV32F_INSN_ADDU_W_R, CRISV32F_INSN_ADDU_M_B_M, CRISV32F_INSN_ADDU_M_W_M, CRISV32F_INSN_ADDUCBR
 , CRISV32F_INSN_ADDUCWR, CRISV32F_INSN_SUB_B_R, CRISV32F_INSN_SUB_W_R, CRISV32F_INSN_SUB_D_R
 , CRISV32F_INSN_SUB_M_B_M, CRISV32F_INSN_SUB_M_W_M, CRISV32F_INSN_SUB_M_D_M, CRISV32F_INSN_SUBCBR
 , CRISV32F_INSN_SUBCWR, CRISV32F_INSN_SUBCDR, CRISV32F_INSN_SUBS_B_R, CRISV32F_INSN_SUBS_W_R
 , CRISV32F_INSN_SUBS_M_B_M, CRISV32F_INSN_SUBS_M_W_M, CRISV32F_INSN_SUBSCBR, CRISV32F_INSN_SUBSCWR
 , CRISV32F_INSN_SUBU_B_R, CRISV32F_INSN_SUBU_W_R, CRISV32F_INSN_SUBU_M_B_M, CRISV32F_INSN_SUBU_M_W_M
 , CRISV32F_INSN_SUBUCBR, CRISV32F_INSN_SUBUCWR, CRISV32F_INSN_ADDC_R, CRISV32F_INSN_ADDC_M
 , CRISV32F_INSN_ADDC_C, CRISV32F_INSN_LAPC_D, CRISV32F_INSN_LAPCQ, CRISV32F_INSN_ADDI_B_R
 , CRISV32F_INSN_ADDI_W_R, CRISV32F_INSN_ADDI_D_R, CRISV32F_INSN_NEG_B_R, CRISV32F_INSN_NEG_W_R
 , CRISV32F_INSN_NEG_D_R, CRISV32F_INSN_TEST_M_B_M, CRISV32F_INSN_TEST_M_W_M, CRISV32F_INSN_TEST_M_D_M
 , CRISV32F_INSN_MOVE_R_M_B_M, CRISV32F_INSN_MOVE_R_M_W_M, CRISV32F_INSN_MOVE_R_M_D_M, CRISV32F_INSN_MULS_B
 , CRISV32F_INSN_MULS_W, CRISV32F_INSN_MULS_D, CRISV32F_INSN_MULU_B, CRISV32F_INSN_MULU_W
 , CRISV32F_INSN_MULU_D, CRISV32F_INSN_MCP, CRISV32F_INSN_DSTEP, CRISV32F_INSN_ABS
 , CRISV32F_INSN_AND_B_R, CRISV32F_INSN_AND_W_R, CRISV32F_INSN_AND_D_R, CRISV32F_INSN_AND_M_B_M
 , CRISV32F_INSN_AND_M_W_M, CRISV32F_INSN_AND_M_D_M, CRISV32F_INSN_ANDCBR, CRISV32F_INSN_ANDCWR
 , CRISV32F_INSN_ANDCDR, CRISV32F_INSN_ANDQ, CRISV32F_INSN_ORR_B_R, CRISV32F_INSN_ORR_W_R
 , CRISV32F_INSN_ORR_D_R, CRISV32F_INSN_OR_M_B_M, CRISV32F_INSN_OR_M_W_M, CRISV32F_INSN_OR_M_D_M
 , CRISV32F_INSN_ORCBR, CRISV32F_INSN_ORCWR, CRISV32F_INSN_ORCDR, CRISV32F_INSN_ORQ
 , CRISV32F_INSN_XOR, CRISV32F_INSN_SWAP, CRISV32F_INSN_ASRR_B_R, CRISV32F_INSN_ASRR_W_R
 , CRISV32F_INSN_ASRR_D_R, CRISV32F_INSN_ASRQ, CRISV32F_INSN_LSRR_B_R, CRISV32F_INSN_LSRR_W_R
 , CRISV32F_INSN_LSRR_D_R, CRISV32F_INSN_LSRQ, CRISV32F_INSN_LSLR_B_R, CRISV32F_INSN_LSLR_W_R
 , CRISV32F_INSN_LSLR_D_R, CRISV32F_INSN_LSLQ, CRISV32F_INSN_BTST, CRISV32F_INSN_BTSTQ
 , CRISV32F_INSN_SETF, CRISV32F_INSN_CLEARF, CRISV32F_INSN_RFE, CRISV32F_INSN_SFE
 , CRISV32F_INSN_RFG, CRISV32F_INSN_RFN, CRISV32F_INSN_HALT, CRISV32F_INSN_BCC_B
 , CRISV32F_INSN_BA_B, CRISV32F_INSN_BCC_W, CRISV32F_INSN_BA_W, CRISV32F_INSN_JAS_R
 , CRISV32F_INSN_JAS_C, CRISV32F_INSN_JUMP_P, CRISV32F_INSN_BAS_C, CRISV32F_INSN_JASC_R
 , CRISV32F_INSN_JASC_C, CRISV32F_INSN_BASC_C, CRISV32F_INSN_BREAK, CRISV32F_INSN_BOUND_R_B_R
 , CRISV32F_INSN_BOUND_R_W_R, CRISV32F_INSN_BOUND_R_D_R, CRISV32F_INSN_BOUND_CB, CRISV32F_INSN_BOUND_CW
 , CRISV32F_INSN_BOUND_CD, CRISV32F_INSN_SCC, CRISV32F_INSN_LZ, CRISV32F_INSN_ADDOQ
 , CRISV32F_INSN_ADDO_M_B_M, CRISV32F_INSN_ADDO_M_W_M, CRISV32F_INSN_ADDO_M_D_M, CRISV32F_INSN_ADDO_CB
 , CRISV32F_INSN_ADDO_CW, CRISV32F_INSN_ADDO_CD, CRISV32F_INSN_ADDI_ACR_B_R, CRISV32F_INSN_ADDI_ACR_W_R
 , CRISV32F_INSN_ADDI_ACR_D_R, CRISV32F_INSN_FIDXI, CRISV32F_INSN_FTAGI, CRISV32F_INSN_FIDXD
 , CRISV32F_INSN_FTAGD, CRISV32F_INSN__MAX
} CRISV32F_INSN_TYPE;

/* Enum declaration for semantic formats in cpu family crisv32f.  */
typedef enum crisv32f_sfmt_type {
  CRISV32F_SFMT_EMPTY, CRISV32F_SFMT_MOVE_B_R, CRISV32F_SFMT_MOVE_D_R, CRISV32F_SFMT_MOVEQ
 , CRISV32F_SFMT_MOVS_B_R, CRISV32F_SFMT_MOVECBR, CRISV32F_SFMT_MOVECWR, CRISV32F_SFMT_MOVECDR
 , CRISV32F_SFMT_MOVSCBR, CRISV32F_SFMT_MOVSCWR, CRISV32F_SFMT_MOVUCBR, CRISV32F_SFMT_MOVUCWR
 , CRISV32F_SFMT_ADDQ, CRISV32F_SFMT_CMP_R_B_R, CRISV32F_SFMT_CMP_M_B_M, CRISV32F_SFMT_CMP_M_W_M
 , CRISV32F_SFMT_CMP_M_D_M, CRISV32F_SFMT_CMPCBR, CRISV32F_SFMT_CMPCWR, CRISV32F_SFMT_CMPCDR
 , CRISV32F_SFMT_CMPQ, CRISV32F_SFMT_CMPUCBR, CRISV32F_SFMT_CMPUCWR, CRISV32F_SFMT_MOVE_M_B_M
 , CRISV32F_SFMT_MOVE_M_W_M, CRISV32F_SFMT_MOVE_M_D_M, CRISV32F_SFMT_MOVS_M_B_M, CRISV32F_SFMT_MOVS_M_W_M
 , CRISV32F_SFMT_MOVE_R_SPRV32, CRISV32F_SFMT_MOVE_SPR_RV32, CRISV32F_SFMT_MOVE_M_SPRV32, CRISV32F_SFMT_MOVE_C_SPRV32_P2
 , CRISV32F_SFMT_MOVE_SPR_MV32, CRISV32F_SFMT_MOVE_SS_R, CRISV32F_SFMT_MOVE_R_SS, CRISV32F_SFMT_MOVEM_R_M_V32
 , CRISV32F_SFMT_MOVEM_M_R_V32, CRISV32F_SFMT_ADD_B_R, CRISV32F_SFMT_ADD_D_R, CRISV32F_SFMT_ADD_M_B_M
 , CRISV32F_SFMT_ADD_M_W_M, CRISV32F_SFMT_ADD_M_D_M, CRISV32F_SFMT_ADDCBR, CRISV32F_SFMT_ADDCWR
 , CRISV32F_SFMT_ADDCDR, CRISV32F_SFMT_ADDS_M_B_M, CRISV32F_SFMT_ADDS_M_W_M, CRISV32F_SFMT_ADDSCBR
 , CRISV32F_SFMT_ADDSCWR, CRISV32F_SFMT_ADDC_M, CRISV32F_SFMT_LAPC_D, CRISV32F_SFMT_LAPCQ
 , CRISV32F_SFMT_ADDI_B_R, CRISV32F_SFMT_NEG_B_R, CRISV32F_SFMT_NEG_D_R, CRISV32F_SFMT_TEST_M_B_M
 , CRISV32F_SFMT_TEST_M_W_M, CRISV32F_SFMT_TEST_M_D_M, CRISV32F_SFMT_MOVE_R_M_B_M, CRISV32F_SFMT_MOVE_R_M_W_M
 , CRISV32F_SFMT_MOVE_R_M_D_M, CRISV32F_SFMT_MULS_B, CRISV32F_SFMT_MCP, CRISV32F_SFMT_DSTEP
 , CRISV32F_SFMT_AND_B_R, CRISV32F_SFMT_AND_W_R, CRISV32F_SFMT_AND_D_R, CRISV32F_SFMT_AND_M_B_M
 , CRISV32F_SFMT_AND_M_W_M, CRISV32F_SFMT_AND_M_D_M, CRISV32F_SFMT_ANDCBR, CRISV32F_SFMT_ANDCWR
 , CRISV32F_SFMT_ANDCDR, CRISV32F_SFMT_ANDQ, CRISV32F_SFMT_SWAP, CRISV32F_SFMT_ASRR_B_R
 , CRISV32F_SFMT_ASRQ, CRISV32F_SFMT_LSRR_B_R, CRISV32F_SFMT_LSRR_D_R, CRISV32F_SFMT_BTST
 , CRISV32F_SFMT_BTSTQ, CRISV32F_SFMT_SETF, CRISV32F_SFMT_RFE, CRISV32F_SFMT_SFE
 , CRISV32F_SFMT_RFG, CRISV32F_SFMT_RFN, CRISV32F_SFMT_HALT, CRISV32F_SFMT_BCC_B
 , CRISV32F_SFMT_BA_B, CRISV32F_SFMT_BCC_W, CRISV32F_SFMT_BA_W, CRISV32F_SFMT_JAS_R
 , CRISV32F_SFMT_JAS_C, CRISV32F_SFMT_JUMP_P, CRISV32F_SFMT_BAS_C, CRISV32F_SFMT_JASC_R
 , CRISV32F_SFMT_BREAK, CRISV32F_SFMT_BOUND_CB, CRISV32F_SFMT_BOUND_CW, CRISV32F_SFMT_BOUND_CD
 , CRISV32F_SFMT_SCC, CRISV32F_SFMT_ADDOQ, CRISV32F_SFMT_ADDO_M_B_M, CRISV32F_SFMT_ADDO_M_W_M
 , CRISV32F_SFMT_ADDO_M_D_M, CRISV32F_SFMT_ADDO_CB, CRISV32F_SFMT_ADDO_CW, CRISV32F_SFMT_ADDO_CD
 , CRISV32F_SFMT_ADDI_ACR_B_R, CRISV32F_SFMT_FIDXI
} CRISV32F_SFMT_TYPE;

/* Function unit handlers (user written).  */

extern int crisv32f_model_crisv32_u_exec_to_sr (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Rs*/, INT /*Pd*/);
extern int crisv32f_model_crisv32_u_exec_movem (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Rs*/, INT /*Rd*/);
extern int crisv32f_model_crisv32_u_exec (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Rd*/, INT /*Rs*/, INT /*Rd*/);
extern int crisv32f_model_crisv32_u_skip4 (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/);
extern int crisv32f_model_crisv32_u_const32 (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/);
extern int crisv32f_model_crisv32_u_const16 (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/);
extern int crisv32f_model_crisv32_u_jump (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Pd*/);
extern int crisv32f_model_crisv32_u_jump_sr (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Ps*/);
extern int crisv32f_model_crisv32_u_jump_r (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Rs*/);
extern int crisv32f_model_crisv32_u_branch (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/);
extern int crisv32f_model_crisv32_u_multiply (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Rs*/, INT /*Rd*/);
extern int crisv32f_model_crisv32_u_movem_mtor (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Rs*/, INT /*Rd*/);
extern int crisv32f_model_crisv32_u_movem_rtom (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Rs*/, INT /*Rd*/);
extern int crisv32f_model_crisv32_u_mem_w (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/);
extern int crisv32f_model_crisv32_u_mem_r (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/);
extern int crisv32f_model_crisv32_u_mem (SIM_CPU *, const IDESC *, int /*unit_num*/, int /*referenced*/, INT /*Rs*/);

/* Profiling before/after handlers (user written) */

extern void crisv32f_model_insn_before (SIM_CPU *, int /*first_p*/);
extern void crisv32f_model_insn_after (SIM_CPU *, int /*last_p*/, int /*cycles*/);

#endif /* CRISV32F_DECODE_H */
