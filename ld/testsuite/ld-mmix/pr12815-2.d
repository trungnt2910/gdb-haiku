#as: -no-predefined-syms -x
#ld: -e 0x1000 --defsym bar=0x100000000 -m elf64mmix -T $srcdir/$subdir/pr12815-1.ld
#error: invalid input relocation.*objcopy.*"-no-expand".*truncated

# Check that we emit a meaningful error message rather than SEGV when
# someone attempts linking to the "binary" output format with
# expanding PUSHJ insns, expecting relaxation to work.
