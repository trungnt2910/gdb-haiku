# 64bit long Instructions

	.text
foo:
.byte 0xf2
.byte 0xf0
.byte 0xf0
.byte 0xf0
.byte 0xf2
.byte 0xf2
.byte 0xf2
.byte 0xf2
.byte 0xf2
.byte 0xf2
.byte 0xf0
.byte 0xf0
movapd	(%rax), %xmm0
.byte 0xf2
.byte 0xf0
.byte 0xf0
.byte 0xf0
.byte 0xf2
.byte 0xf2
.byte 0xf2
.byte 0xf2
.byte 0xf0
.byte 0xf0
.byte 0xf0
.byte 0xf0
movapd	(%rax), %xmm0
