# Source file used to test li/addi on MIPS16
	
	.set	mips16
	
	.data
data_label:
	.word	0
data_label2:
	.word	0
	
	.extern big_external_data_label,1000
	.extern small_external_data_label,1
	.comm big_external_common,1000
	.comm small_external_common,1
	.lcomm big_local_common,1000
	.lcomm small_local_common,1
	
	.text
stuff:		
	li	$4,%hi(0)
	sll	$4,16
	addiu	$4,%lo(0)
	li	$4,%hi(data_label)
	sll	$4,16
	addiu	$4,%lo(data_label)
	li	$4,%hi(data_label2)
	sll	$4,16
	addiu	$4,%lo(data_label2)
	li	$4,%hi(big_external_data_label)
	sll	$4,16
	addiu	$4,%lo(big_external_data_label)
	li	$4,%hi(small_external_data_label)
	sll	$4,16
	addiu	$4,%lo(small_external_data_label)
	li	$4,%hi(big_external_common)
	sll	$4,16
	addiu	$4,%lo(big_external_common)
	li	$4,%hi(small_external_common)
	sll	$4,16
	addiu	$4,%lo(small_external_common)
	li	$4,%hi(big_local_common)
	sll	$4,16
	addiu	$4,%lo(big_local_common)
	li	$4,%hi(small_local_common)
	sll	$4,16
	addiu	$4,%lo(small_local_common)
	li	$4,%hi(1)
	sll	$4,16
	addiu	$4,%lo(1)
	li	$4,%hi(data_label+1)
	sll	$4,16
	addiu	$4,%lo(data_label+1)
	li	$4,%hi(data_label2+1)
	sll	$4,16
	addiu	$4,%lo(data_label2+1)
	li	$4,%hi(big_external_data_label+1)
	sll	$4,16
	addiu	$4,%lo(big_external_data_label+1)
	li	$4,%hi(small_external_data_label+1)
	sll	$4,16
	addiu	$4,%lo(small_external_data_label+1)
	li	$4,%hi(big_external_common+1)
	sll	$4,16
	addiu	$4,%lo(big_external_common+1)
	li	$4,%hi(small_external_common+1)
	sll	$4,16
	addiu	$4,%lo(small_external_common+1)
	li	$4,%hi(big_local_common+1)
	sll	$4,16
	addiu	$4,%lo(big_local_common+1)
	li	$4,%hi(small_local_common+1)
	sll	$4,16
	addiu	$4,%lo(small_local_common+1)
	li	$4,%hi(0x8000)
	sll	$4,16
	addiu	$4,%lo(0x8000)
	li	$4,%hi(data_label+0x8000)
	sll	$4,16
	addiu	$4,%lo(data_label+0x8000)
	li	$4,%hi(data_label2+0x8000)
	sll	$4,16
	addiu	$4,%lo(data_label2+0x8000)
	li	$4,%hi(big_external_data_label+0x8000)
	sll	$4,16
	addiu	$4,%lo(big_external_data_label+0x8000)
	li	$4,%hi(small_external_data_label+0x8000)
	sll	$4,16
	addiu	$4,%lo(small_external_data_label+0x8000)
	li	$4,%hi(big_external_common+0x8000)
	sll	$4,16
	addiu	$4,%lo(big_external_common+0x8000)
	li	$4,%hi(small_external_common+0x8000)
	sll	$4,16
	addiu	$4,%lo(small_external_common+0x8000)
	li	$4,%hi(big_local_common+0x8000)
	sll	$4,16
	addiu	$4,%lo(big_local_common+0x8000)
	li	$4,%hi(small_local_common+0x8000)
	sll	$4,16
	addiu	$4,%lo(small_local_common+0x8000)
	li	$4,%hi(-0x8000)
	sll	$4,16
	addiu	$4,%lo(-0x8000)
	li	$4,%hi(data_label-0x8000)
	sll	$4,16
	addiu	$4,%lo(data_label-0x8000)
	li	$4,%hi(data_label2-0x8000)
	sll	$4,16
	addiu	$4,%lo(data_label2-0x8000)
	li	$4,%hi(big_external_data_label-0x8000)
	sll	$4,16
	addiu	$4,%lo(big_external_data_label-0x8000)
	li	$4,%hi(small_external_data_label-0x8000)
	sll	$4,16
	addiu	$4,%lo(small_external_data_label-0x8000)
	li	$4,%hi(big_external_common-0x8000)
	sll	$4,16
	addiu	$4,%lo(big_external_common-0x8000)
	li	$4,%hi(small_external_common-0x8000)
	sll	$4,16
	addiu	$4,%lo(small_external_common-0x8000)
	li	$4,%hi(big_local_common-0x8000)
	sll	$4,16
	addiu	$4,%lo(big_local_common-0x8000)
	li	$4,%hi(small_local_common-0x8000)
	sll	$4,16
	addiu	$4,%lo(small_local_common-0x8000)
	li	$4,%hi(0x10000)
	sll	$4,16
	addiu	$4,%lo(0x10000)
	li	$4,%hi(data_label+0x10000)
	sll	$4,16
	addiu	$4,%lo(data_label+0x10000)
	li	$4,%hi(data_label2+0x10000)
	sll	$4,16
	addiu	$4,%lo(data_label2+0x10000)
	li	$4,%hi(big_external_data_label+0x10000)
	sll	$4,16
	addiu	$4,%lo(big_external_data_label+0x10000)
	li	$4,%hi(small_external_data_label+0x10000)
	sll	$4,16
	addiu	$4,%lo(small_external_data_label+0x10000)
	li	$4,%hi(big_external_common+0x10000)
	sll	$4,16
	addiu	$4,%lo(big_external_common+0x10000)
	li	$4,%hi(small_external_common+0x10000)
	sll	$4,16
	addiu	$4,%lo(small_external_common+0x10000)
	li	$4,%hi(big_local_common+0x10000)
	sll	$4,16
	addiu	$4,%lo(big_local_common+0x10000)
	li	$4,%hi(small_local_common+0x10000)
	sll	$4,16
	addiu	$4,%lo(small_local_common+0x10000)
	li	$4,%hi(0x1a5a5)
	sll	$4,16
	addiu	$4,%lo(0x1a5a5)
	li	$4,%hi(data_label+0x1a5a5)
	sll	$4,16
	addiu	$4,%lo(data_label+0x1a5a5)
	li	$4,%hi(data_label2+0x1a5a5)
	sll	$4,16
	addiu	$4,%lo(data_label2+0x1a5a5)
	li	$4,%hi(big_external_data_label+0x1a5a5)
	sll	$4,16
	addiu	$4,%lo(big_external_data_label+0x1a5a5)
	li	$4,%hi(small_external_data_label+0x1a5a5)
	sll	$4,16
	addiu	$4,%lo(small_external_data_label+0x1a5a5)
	li	$4,%hi(big_external_common+0x1a5a5)
	sll	$4,16
	addiu	$4,%lo(big_external_common+0x1a5a5)
	li	$4,%hi(small_external_common+0x1a5a5)
	sll	$4,16
	addiu	$4,%lo(small_external_common+0x1a5a5)
	li	$4,%hi(big_local_common+0x1a5a5)
	sll	$4,16
	addiu	$4,%lo(big_local_common+0x1a5a5)
	li	$4,%hi(small_local_common+0x1a5a5)
	sll	$4,16
	addiu	$4,%lo(small_local_common+0x1a5a5)
	li	$5,%hi(0)
	sll	$5,16
	lw	$4,%hi(0)($5)
	li	$5,%hi(data_label)
	sll	$5,16
	lw	$4,%hi(data_label)($5)
	li	$5,%hi(data_label2)
	sll	$5,16
	lw	$4,%hi(data_label2)($5)
	li	$5,%hi(big_external_data_label)
	sll	$5,16
	lw	$4,%lo(big_external_data_label)($5)
	li	$5,%hi(small_external_data_label)
	sll	$5,16
	lw	$4,%lo(small_external_data_label)($5)
	li	$5,%hi(big_external_common)
	sll	$5,16
	lw	$4,%lo(big_external_common)($5)
	li	$5,%hi(small_external_common)
	sll	$5,16
	lw	$4,%lo(small_external_common)($5)
	li	$5,%hi(big_local_common)
	sll	$5,16
	lw	$4,%lo(big_local_common)($5)
	li	$5,%hi(small_local_common)
	sll	$5,16
	lw	$4,%lo(small_local_common)($5)
	li	$5,%hi(1)
	sll	$5,16
	lw	$4,%lo(1)($5)
	li	$5,%hi(data_label+1)
	sll	$5,16
	lw	$4,%lo(data_label+1)($5)
	li	$5,%hi(data_label2+1)
	sll	$5,16
	lw	$4,%lo(data_label2+1)($5)
	li	$5,%hi(big_external_data_label+1)
	sll	$5,16
	lw	$4,%lo(big_external_data_label+1)($5)
	li	$5,%hi(small_external_data_label+1)
	sll	$5,16
	lw	$4,%lo(small_external_data_label+1)($5)
	li	$5,%hi(big_external_common+1)
	sll	$5,16
	lw	$4,%lo(big_external_common+1)($5)
	li	$5,%hi(small_external_common+1)
	sll	$5,16
	lw	$4,%lo(small_external_common+1)($5)
	li	$5,%hi(big_local_common+1)
	sll	$5,16
	lw	$4,%lo(big_local_common+1)($5)
	li	$5,%hi(small_local_common+1)
	sll	$5,16
	lw	$4,%lo(small_local_common+1)($5)
	li	$5,%hi(0x8000)
	sll	$5,16
	lw	$4,%lo(0x8000)($5)
	li	$5,%hi(data_label+0x8000)
	sll	$5,16
	lw	$4,%lo(data_label+0x8000)($5)
	li	$5,%hi(data_label2+0x8000)
	sll	$5,16
	lw	$4,%lo(data_label2+0x8000)($5)
	li	$5,%hi(big_external_data_label+0x8000)
	sll	$5,16
	lw	$4,%lo(big_external_data_label+0x8000)($5)
	li	$5,%hi(small_external_data_label+0x8000)
	sll	$5,16
	lw	$4,%lo(small_external_data_label+0x8000)($5)
	li	$5,%hi(big_external_common+0x8000)
	sll	$5,16
	lw	$4,%lo(big_external_common+0x8000)($5)
	li	$5,%hi(small_external_common+0x8000)
	sll	$5,16
	lw	$4,%lo(small_external_common+0x8000)($5)
	li	$5,%hi(big_local_common+0x8000)
	sll	$5,16
	lw	$4,%lo(big_local_common+0x8000)($5)
	li	$5,%hi(small_local_common+0x8000)
	sll	$5,16
	lw	$4,%lo(small_local_common+0x8000)($5)
	li	$5,%hi(-0x8000)
	sll	$5,16
	lw	$4,%lo(-0x8000)($5)
	li	$5,%hi(data_label-0x8000)
	sll	$5,16
	lw	$4,%lo(data_label-0x8000)($5)
	li	$5,%hi(data_label2-0x8000)
	sll	$5,16
	lw	$4,%lo(data_label2-0x8000)($5)
	li	$5,%hi(big_external_data_label-0x8000)
	sll	$5,16
	lw	$4,%lo(big_external_data_label-0x8000)($5)
	li	$5,%hi(small_external_data_label-0x8000)
	sll	$5,16
	lw	$4,%lo(small_external_data_label-0x8000)($5)
	li	$5,%hi(big_external_common-0x8000)
	sll	$5,16
	lw	$4,%lo(big_external_common-0x8000)($5)
	li	$5,%hi(small_external_common-0x8000)
	sll	$5,16
	lw	$4,%lo(small_external_common-0x8000)($5)
	li	$5,%hi(big_local_common-0x8000)
	sll	$5,16
	lw	$4,%lo(big_local_common-0x8000)($5)
	li	$5,%hi(small_local_common-0x8000)
	sll	$5,16
	lw	$4,%lo(small_local_common-0x8000)($5)
	li	$5,%hi(0x10000)
	sll	$5,16
	lw	$4,%lo(0x10000)($5)
	li	$5,%hi(data_label+0x10000)
	sll	$5,16
	lw	$4,%lo(data_label+0x10000)($5)
	li	$5,%hi(data_label2+0x10000)
	sll	$5,16
	lw	$4,%lo(data_label2+0x10000)($5)
	li	$5,%hi(big_external_data_label+0x10000)
	sll	$5,16
	lw	$4,%lo(big_external_data_label+0x10000)($5)
	li	$5,%hi(small_external_data_label+0x10000)
	sll	$5,16
	lw	$4,%lo(small_external_data_label+0x10000)($5)
	li	$5,%hi(big_external_common+0x10000)
	sll	$5,16
	lw	$4,%lo(big_external_common+0x10000)($5)
	li	$5,%hi(small_external_common+0x10000)
	sll	$5,16
	lw	$4,%lo(small_external_common+0x10000)($5)
	li	$5,%hi(big_local_common+0x10000)
	sll	$5,16
	lw	$4,%lo(big_local_common+0x10000)($5)
	li	$5,%hi(small_local_common+0x10000)
	sll	$5,16
	lw	$4,%lo(small_local_common+0x10000)($5)
	li	$5,%hi(0x1a5a5)
	sll	$5,16
	lw	$4,%lo(0x1a5a5)($5)
	li	$5,%hi(data_label+0x1a5a5)
	sll	$5,16
	lw	$4,%lo(data_label+0x1a5a5)($5)
	li	$5,%hi(data_label2+0x1a5a5)
	sll	$5,16
	lw	$4,%lo(data_label2+0x1a5a5)($5)
	li	$5,%hi(big_external_data_label+0x1a5a5)
	sll	$5,16
	lw	$4,%lo(big_external_data_label+0x1a5a5)($5)
	li	$5,%hi(small_external_data_label+0x1a5a5)
	sll	$5,16
	lw	$4,%lo(small_external_data_label+0x1a5a5)($5)
	li	$5,%hi(big_external_common+0x1a5a5)
	sll	$5,16
	lw	$4,%lo(big_external_common+0x1a5a5)($5)
	li	$5,%hi(small_external_common+0x1a5a5)
	sll	$5,16
	lw	$4,%lo(small_external_common+0x1a5a5)($5)
	li	$5,%hi(big_local_common+0x1a5a5)
	sll	$5,16
	lw	$4,%lo(big_local_common+0x1a5a5)($5)
	li	$5,%hi(small_local_common+0x1a5a5)
	sll	$5,16
	lw	$4,%lo(small_local_common+0x1a5a5)($5)

# align section end to 16-byte boundary for easier testing on multiple targets
	.p2align 4
