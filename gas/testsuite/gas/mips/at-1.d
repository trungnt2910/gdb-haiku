#objdump: -dr --prefix-addresses -mmips:3000
#name: MIPS at-1
#as: -32 -mips1

# Test the .set at=REG directive.

.*: +file format .*mips.*

Disassembly of section \.text:
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	at,0x1
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(at\)
[0-9a-f]+ <[^>]*> lui	at,0x1
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(at\)
[0-9a-f]+ <[^>]*> lui	at,0xffff
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(at\)
[0-9a-f]+ <[^>]*> lui	at,0xffff
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(at\)
[0-9a-f]+ <[^>]*> lui	at,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(at\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	at,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(at\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	v0,0x1
[0-9a-f]+ <[^>]*> addu	v0,v0,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(v0\)
[0-9a-f]+ <[^>]*> lui	v0,0x1
[0-9a-f]+ <[^>]*> addu	v0,v0,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(v0\)
[0-9a-f]+ <[^>]*> lui	v0,0xffff
[0-9a-f]+ <[^>]*> addu	v0,v0,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(v0\)
[0-9a-f]+ <[^>]*> lui	v0,0xffff
[0-9a-f]+ <[^>]*> addu	v0,v0,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(v0\)
[0-9a-f]+ <[^>]*> lui	v0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	v0,v0,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(v0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	v0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	v0,v0,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(v0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	v1,0x1
[0-9a-f]+ <[^>]*> addu	v1,v1,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(v1\)
[0-9a-f]+ <[^>]*> lui	v1,0x1
[0-9a-f]+ <[^>]*> addu	v1,v1,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(v1\)
[0-9a-f]+ <[^>]*> lui	v1,0xffff
[0-9a-f]+ <[^>]*> addu	v1,v1,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(v1\)
[0-9a-f]+ <[^>]*> lui	v1,0xffff
[0-9a-f]+ <[^>]*> addu	v1,v1,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(v1\)
[0-9a-f]+ <[^>]*> lui	v1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	v1,v1,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(v1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	v1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	v1,v1,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(v1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	a0,0x1
[0-9a-f]+ <[^>]*> addu	a0,a0,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(a0\)
[0-9a-f]+ <[^>]*> lui	a0,0x1
[0-9a-f]+ <[^>]*> addu	a0,a0,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(a0\)
[0-9a-f]+ <[^>]*> lui	a0,0xffff
[0-9a-f]+ <[^>]*> addu	a0,a0,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(a0\)
[0-9a-f]+ <[^>]*> lui	a0,0xffff
[0-9a-f]+ <[^>]*> addu	a0,a0,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(a0\)
[0-9a-f]+ <[^>]*> lui	a0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	a0,a0,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(a0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	a0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	a0,a0,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(a0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	a1,0x1
[0-9a-f]+ <[^>]*> addu	a1,a1,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(a1\)
[0-9a-f]+ <[^>]*> lui	a1,0x1
[0-9a-f]+ <[^>]*> addu	a1,a1,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(a1\)
[0-9a-f]+ <[^>]*> lui	a1,0xffff
[0-9a-f]+ <[^>]*> addu	a1,a1,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(a1\)
[0-9a-f]+ <[^>]*> lui	a1,0xffff
[0-9a-f]+ <[^>]*> addu	a1,a1,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(a1\)
[0-9a-f]+ <[^>]*> lui	a1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	a1,a1,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(a1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	a1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	a1,a1,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(a1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	a2,0x1
[0-9a-f]+ <[^>]*> addu	a2,a2,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(a2\)
[0-9a-f]+ <[^>]*> lui	a2,0x1
[0-9a-f]+ <[^>]*> addu	a2,a2,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(a2\)
[0-9a-f]+ <[^>]*> lui	a2,0xffff
[0-9a-f]+ <[^>]*> addu	a2,a2,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(a2\)
[0-9a-f]+ <[^>]*> lui	a2,0xffff
[0-9a-f]+ <[^>]*> addu	a2,a2,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(a2\)
[0-9a-f]+ <[^>]*> lui	a2,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	a2,a2,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(a2\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	a2,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	a2,a2,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(a2\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	a3,0x1
[0-9a-f]+ <[^>]*> addu	a3,a3,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(a3\)
[0-9a-f]+ <[^>]*> lui	a3,0x1
[0-9a-f]+ <[^>]*> addu	a3,a3,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(a3\)
[0-9a-f]+ <[^>]*> lui	a3,0xffff
[0-9a-f]+ <[^>]*> addu	a3,a3,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(a3\)
[0-9a-f]+ <[^>]*> lui	a3,0xffff
[0-9a-f]+ <[^>]*> addu	a3,a3,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(a3\)
[0-9a-f]+ <[^>]*> lui	a3,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	a3,a3,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(a3\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	a3,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	a3,a3,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(a3\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t0,0x1
[0-9a-f]+ <[^>]*> addu	t0,t0,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t0\)
[0-9a-f]+ <[^>]*> lui	t0,0x1
[0-9a-f]+ <[^>]*> addu	t0,t0,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t0\)
[0-9a-f]+ <[^>]*> lui	t0,0xffff
[0-9a-f]+ <[^>]*> addu	t0,t0,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t0\)
[0-9a-f]+ <[^>]*> lui	t0,0xffff
[0-9a-f]+ <[^>]*> addu	t0,t0,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t0\)
[0-9a-f]+ <[^>]*> lui	t0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t0,t0,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t0,t0,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t1,0x1
[0-9a-f]+ <[^>]*> addu	t1,t1,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t1\)
[0-9a-f]+ <[^>]*> lui	t1,0x1
[0-9a-f]+ <[^>]*> addu	t1,t1,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t1\)
[0-9a-f]+ <[^>]*> lui	t1,0xffff
[0-9a-f]+ <[^>]*> addu	t1,t1,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t1\)
[0-9a-f]+ <[^>]*> lui	t1,0xffff
[0-9a-f]+ <[^>]*> addu	t1,t1,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t1\)
[0-9a-f]+ <[^>]*> lui	t1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t1,t1,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t1,t1,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t2,0x1
[0-9a-f]+ <[^>]*> addu	t2,t2,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t2\)
[0-9a-f]+ <[^>]*> lui	t2,0x1
[0-9a-f]+ <[^>]*> addu	t2,t2,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t2\)
[0-9a-f]+ <[^>]*> lui	t2,0xffff
[0-9a-f]+ <[^>]*> addu	t2,t2,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t2\)
[0-9a-f]+ <[^>]*> lui	t2,0xffff
[0-9a-f]+ <[^>]*> addu	t2,t2,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t2\)
[0-9a-f]+ <[^>]*> lui	t2,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t2,t2,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t2\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t2,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t2,t2,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t2\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t3,0x1
[0-9a-f]+ <[^>]*> addu	t3,t3,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t3\)
[0-9a-f]+ <[^>]*> lui	t3,0x1
[0-9a-f]+ <[^>]*> addu	t3,t3,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t3\)
[0-9a-f]+ <[^>]*> lui	t3,0xffff
[0-9a-f]+ <[^>]*> addu	t3,t3,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t3\)
[0-9a-f]+ <[^>]*> lui	t3,0xffff
[0-9a-f]+ <[^>]*> addu	t3,t3,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t3\)
[0-9a-f]+ <[^>]*> lui	t3,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t3,t3,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t3\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t3,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t3,t3,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t3\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t4,0x1
[0-9a-f]+ <[^>]*> addu	t4,t4,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t4\)
[0-9a-f]+ <[^>]*> lui	t4,0x1
[0-9a-f]+ <[^>]*> addu	t4,t4,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t4\)
[0-9a-f]+ <[^>]*> lui	t4,0xffff
[0-9a-f]+ <[^>]*> addu	t4,t4,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t4\)
[0-9a-f]+ <[^>]*> lui	t4,0xffff
[0-9a-f]+ <[^>]*> addu	t4,t4,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t4\)
[0-9a-f]+ <[^>]*> lui	t4,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t4,t4,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t4\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t4,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t4,t4,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t4\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t5,0x1
[0-9a-f]+ <[^>]*> addu	t5,t5,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t5\)
[0-9a-f]+ <[^>]*> lui	t5,0x1
[0-9a-f]+ <[^>]*> addu	t5,t5,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t5\)
[0-9a-f]+ <[^>]*> lui	t5,0xffff
[0-9a-f]+ <[^>]*> addu	t5,t5,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t5\)
[0-9a-f]+ <[^>]*> lui	t5,0xffff
[0-9a-f]+ <[^>]*> addu	t5,t5,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t5\)
[0-9a-f]+ <[^>]*> lui	t5,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t5,t5,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t5\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t5,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t5,t5,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t5\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t6,0x1
[0-9a-f]+ <[^>]*> addu	t6,t6,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t6\)
[0-9a-f]+ <[^>]*> lui	t6,0x1
[0-9a-f]+ <[^>]*> addu	t6,t6,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t6\)
[0-9a-f]+ <[^>]*> lui	t6,0xffff
[0-9a-f]+ <[^>]*> addu	t6,t6,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t6\)
[0-9a-f]+ <[^>]*> lui	t6,0xffff
[0-9a-f]+ <[^>]*> addu	t6,t6,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t6\)
[0-9a-f]+ <[^>]*> lui	t6,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t6,t6,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t6\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t6,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t6,t6,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t6\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t7,0x1
[0-9a-f]+ <[^>]*> addu	t7,t7,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t7\)
[0-9a-f]+ <[^>]*> lui	t7,0x1
[0-9a-f]+ <[^>]*> addu	t7,t7,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t7\)
[0-9a-f]+ <[^>]*> lui	t7,0xffff
[0-9a-f]+ <[^>]*> addu	t7,t7,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t7\)
[0-9a-f]+ <[^>]*> lui	t7,0xffff
[0-9a-f]+ <[^>]*> addu	t7,t7,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t7\)
[0-9a-f]+ <[^>]*> lui	t7,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t7,t7,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t7\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t7,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t7,t7,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t7\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	s0,0x1
[0-9a-f]+ <[^>]*> addu	s0,s0,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(s0\)
[0-9a-f]+ <[^>]*> lui	s0,0x1
[0-9a-f]+ <[^>]*> addu	s0,s0,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(s0\)
[0-9a-f]+ <[^>]*> lui	s0,0xffff
[0-9a-f]+ <[^>]*> addu	s0,s0,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(s0\)
[0-9a-f]+ <[^>]*> lui	s0,0xffff
[0-9a-f]+ <[^>]*> addu	s0,s0,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(s0\)
[0-9a-f]+ <[^>]*> lui	s0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s0,s0,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(s0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	s0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s0,s0,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(s0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	s1,0x1
[0-9a-f]+ <[^>]*> addu	s1,s1,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(s1\)
[0-9a-f]+ <[^>]*> lui	s1,0x1
[0-9a-f]+ <[^>]*> addu	s1,s1,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(s1\)
[0-9a-f]+ <[^>]*> lui	s1,0xffff
[0-9a-f]+ <[^>]*> addu	s1,s1,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(s1\)
[0-9a-f]+ <[^>]*> lui	s1,0xffff
[0-9a-f]+ <[^>]*> addu	s1,s1,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(s1\)
[0-9a-f]+ <[^>]*> lui	s1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s1,s1,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(s1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	s1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s1,s1,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(s1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	s2,0x1
[0-9a-f]+ <[^>]*> addu	s2,s2,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(s2\)
[0-9a-f]+ <[^>]*> lui	s2,0x1
[0-9a-f]+ <[^>]*> addu	s2,s2,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(s2\)
[0-9a-f]+ <[^>]*> lui	s2,0xffff
[0-9a-f]+ <[^>]*> addu	s2,s2,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(s2\)
[0-9a-f]+ <[^>]*> lui	s2,0xffff
[0-9a-f]+ <[^>]*> addu	s2,s2,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(s2\)
[0-9a-f]+ <[^>]*> lui	s2,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s2,s2,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(s2\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	s2,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s2,s2,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(s2\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	s3,0x1
[0-9a-f]+ <[^>]*> addu	s3,s3,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(s3\)
[0-9a-f]+ <[^>]*> lui	s3,0x1
[0-9a-f]+ <[^>]*> addu	s3,s3,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(s3\)
[0-9a-f]+ <[^>]*> lui	s3,0xffff
[0-9a-f]+ <[^>]*> addu	s3,s3,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(s3\)
[0-9a-f]+ <[^>]*> lui	s3,0xffff
[0-9a-f]+ <[^>]*> addu	s3,s3,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(s3\)
[0-9a-f]+ <[^>]*> lui	s3,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s3,s3,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(s3\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	s3,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s3,s3,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(s3\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	s4,0x1
[0-9a-f]+ <[^>]*> addu	s4,s4,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(s4\)
[0-9a-f]+ <[^>]*> lui	s4,0x1
[0-9a-f]+ <[^>]*> addu	s4,s4,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(s4\)
[0-9a-f]+ <[^>]*> lui	s4,0xffff
[0-9a-f]+ <[^>]*> addu	s4,s4,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(s4\)
[0-9a-f]+ <[^>]*> lui	s4,0xffff
[0-9a-f]+ <[^>]*> addu	s4,s4,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(s4\)
[0-9a-f]+ <[^>]*> lui	s4,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s4,s4,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(s4\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	s4,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s4,s4,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(s4\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	s5,0x1
[0-9a-f]+ <[^>]*> addu	s5,s5,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(s5\)
[0-9a-f]+ <[^>]*> lui	s5,0x1
[0-9a-f]+ <[^>]*> addu	s5,s5,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(s5\)
[0-9a-f]+ <[^>]*> lui	s5,0xffff
[0-9a-f]+ <[^>]*> addu	s5,s5,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(s5\)
[0-9a-f]+ <[^>]*> lui	s5,0xffff
[0-9a-f]+ <[^>]*> addu	s5,s5,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(s5\)
[0-9a-f]+ <[^>]*> lui	s5,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s5,s5,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(s5\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	s5,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s5,s5,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(s5\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	s6,0x1
[0-9a-f]+ <[^>]*> addu	s6,s6,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(s6\)
[0-9a-f]+ <[^>]*> lui	s6,0x1
[0-9a-f]+ <[^>]*> addu	s6,s6,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(s6\)
[0-9a-f]+ <[^>]*> lui	s6,0xffff
[0-9a-f]+ <[^>]*> addu	s6,s6,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(s6\)
[0-9a-f]+ <[^>]*> lui	s6,0xffff
[0-9a-f]+ <[^>]*> addu	s6,s6,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(s6\)
[0-9a-f]+ <[^>]*> lui	s6,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s6,s6,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(s6\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	s6,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s6,s6,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(s6\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	s7,0x1
[0-9a-f]+ <[^>]*> addu	s7,s7,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(s7\)
[0-9a-f]+ <[^>]*> lui	s7,0x1
[0-9a-f]+ <[^>]*> addu	s7,s7,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(s7\)
[0-9a-f]+ <[^>]*> lui	s7,0xffff
[0-9a-f]+ <[^>]*> addu	s7,s7,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(s7\)
[0-9a-f]+ <[^>]*> lui	s7,0xffff
[0-9a-f]+ <[^>]*> addu	s7,s7,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(s7\)
[0-9a-f]+ <[^>]*> lui	s7,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s7,s7,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(s7\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	s7,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s7,s7,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(s7\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t8,0x1
[0-9a-f]+ <[^>]*> addu	t8,t8,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t8\)
[0-9a-f]+ <[^>]*> lui	t8,0x1
[0-9a-f]+ <[^>]*> addu	t8,t8,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t8\)
[0-9a-f]+ <[^>]*> lui	t8,0xffff
[0-9a-f]+ <[^>]*> addu	t8,t8,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t8\)
[0-9a-f]+ <[^>]*> lui	t8,0xffff
[0-9a-f]+ <[^>]*> addu	t8,t8,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t8\)
[0-9a-f]+ <[^>]*> lui	t8,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t8,t8,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t8\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t8,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t8,t8,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t8\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	t9,0x1
[0-9a-f]+ <[^>]*> addu	t9,t9,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(t9\)
[0-9a-f]+ <[^>]*> lui	t9,0x1
[0-9a-f]+ <[^>]*> addu	t9,t9,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(t9\)
[0-9a-f]+ <[^>]*> lui	t9,0xffff
[0-9a-f]+ <[^>]*> addu	t9,t9,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(t9\)
[0-9a-f]+ <[^>]*> lui	t9,0xffff
[0-9a-f]+ <[^>]*> addu	t9,t9,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(t9\)
[0-9a-f]+ <[^>]*> lui	t9,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t9,t9,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(t9\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	t9,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	t9,t9,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(t9\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	k0,0x1
[0-9a-f]+ <[^>]*> addu	k0,k0,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k0\)
[0-9a-f]+ <[^>]*> lui	k0,0x1
[0-9a-f]+ <[^>]*> addu	k0,k0,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k0\)
[0-9a-f]+ <[^>]*> lui	k0,0xffff
[0-9a-f]+ <[^>]*> addu	k0,k0,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(k0\)
[0-9a-f]+ <[^>]*> lui	k0,0xffff
[0-9a-f]+ <[^>]*> addu	k0,k0,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(k0\)
[0-9a-f]+ <[^>]*> lui	k0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	k0,k0,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(k0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	k0,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	k0,k0,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(k0\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k0,32767\(k0\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k0,32767\(k0\)
[0-9a-f]+ <[^>]*> lw	k0,-32768\(k0\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k0,-32768\(k0\)
[0-9a-f]+ <[^>]*> lui	k1,0x1
[0-9a-f]+ <[^>]*> addu	k1,k1,k0
[0-9a-f]+ <[^>]*> lw	k0,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	k1,0x1
[0-9a-f]+ <[^>]*> addu	k1,k1,k0
[0-9a-f]+ <[^>]*> sw	k0,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	k1,0xffff
[0-9a-f]+ <[^>]*> addu	k1,k1,k0
[0-9a-f]+ <[^>]*> lw	k0,32767\(k1\)
[0-9a-f]+ <[^>]*> lui	k1,0xffff
[0-9a-f]+ <[^>]*> addu	k1,k1,k0
[0-9a-f]+ <[^>]*> sw	k0,32767\(k1\)
[0-9a-f]+ <[^>]*> lui	k1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	k1,k1,k0
[0-9a-f]+ <[^>]*> lw	k0,0\(k1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	k1,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	k1,k1,k0
[0-9a-f]+ <[^>]*> sw	k0,0\(k1\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	gp,0x1
[0-9a-f]+ <[^>]*> addu	gp,gp,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(gp\)
[0-9a-f]+ <[^>]*> lui	gp,0x1
[0-9a-f]+ <[^>]*> addu	gp,gp,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(gp\)
[0-9a-f]+ <[^>]*> lui	gp,0xffff
[0-9a-f]+ <[^>]*> addu	gp,gp,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(gp\)
[0-9a-f]+ <[^>]*> lui	gp,0xffff
[0-9a-f]+ <[^>]*> addu	gp,gp,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(gp\)
[0-9a-f]+ <[^>]*> lui	gp,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	gp,gp,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(gp\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	gp,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	gp,gp,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(gp\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	s8,0x1
[0-9a-f]+ <[^>]*> addu	s8,s8,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(s8\)
[0-9a-f]+ <[^>]*> lui	s8,0x1
[0-9a-f]+ <[^>]*> addu	s8,s8,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(s8\)
[0-9a-f]+ <[^>]*> lui	s8,0xffff
[0-9a-f]+ <[^>]*> addu	s8,s8,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(s8\)
[0-9a-f]+ <[^>]*> lui	s8,0xffff
[0-9a-f]+ <[^>]*> addu	s8,s8,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(s8\)
[0-9a-f]+ <[^>]*> lui	s8,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s8,s8,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(s8\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	s8,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	s8,s8,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(s8\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	sp,0x1
[0-9a-f]+ <[^>]*> addu	sp,sp,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(sp\)
[0-9a-f]+ <[^>]*> lui	sp,0x1
[0-9a-f]+ <[^>]*> addu	sp,sp,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(sp\)
[0-9a-f]+ <[^>]*> lui	sp,0xffff
[0-9a-f]+ <[^>]*> addu	sp,sp,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(sp\)
[0-9a-f]+ <[^>]*> lui	sp,0xffff
[0-9a-f]+ <[^>]*> addu	sp,sp,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(sp\)
[0-9a-f]+ <[^>]*> lui	sp,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	sp,sp,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(sp\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	sp,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	sp,sp,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(sp\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	ra,0x1
[0-9a-f]+ <[^>]*> addu	ra,ra,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(ra\)
[0-9a-f]+ <[^>]*> lui	ra,0x1
[0-9a-f]+ <[^>]*> addu	ra,ra,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(ra\)
[0-9a-f]+ <[^>]*> lui	ra,0xffff
[0-9a-f]+ <[^>]*> addu	ra,ra,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(ra\)
[0-9a-f]+ <[^>]*> lui	ra,0xffff
[0-9a-f]+ <[^>]*> addu	ra,ra,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(ra\)
[0-9a-f]+ <[^>]*> lui	ra,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	ra,ra,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(ra\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	ra,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	ra,ra,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(ra\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> lw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,32767\(k1\)
[0-9a-f]+ <[^>]*> lw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> sw	k1,-32768\(k1\)
[0-9a-f]+ <[^>]*> lui	at,0x1
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> lw	k1,-32768\(at\)
[0-9a-f]+ <[^>]*> lui	at,0x1
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> sw	k1,-32768\(at\)
[0-9a-f]+ <[^>]*> lui	at,0xffff
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> lw	k1,32767\(at\)
[0-9a-f]+ <[^>]*> lui	at,0xffff
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> sw	k1,32767\(at\)
[0-9a-f]+ <[^>]*> lui	at,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> lw	k1,0\(at\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
[0-9a-f]+ <[^>]*> nop
[0-9a-f]+ <[^>]*> lui	at,0x0
[ 	]*[0-9a-f]+: (R_MIPS_HI16|REFHI)	symbol
[0-9a-f]+ <[^>]*> addu	at,at,k1
[0-9a-f]+ <[^>]*> sw	k1,0\(at\)
[ 	]*[0-9a-f]+: (R_MIPS_LO16|REFLO)	symbol
	\.\.\.
