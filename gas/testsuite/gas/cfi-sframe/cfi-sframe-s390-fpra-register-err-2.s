	.cfi_sections .sframe
	.cfi_startproc
	ldgr	%f0,%r14
	.cfi_register 14, 16
	ldgr	%f2,%r11
	.cfi_register 11, 17
	la	%r11,0
	la	%r14,0
.Lreturn:
	lgdr	%r11,%f2
	.cfi_restore 11
	lgdr	%r14,%f0
	.cfi_restore 14
	br	%r14
	.cfi_endproc
