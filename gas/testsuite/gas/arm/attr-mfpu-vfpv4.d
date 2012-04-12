# name: attributes for -mfpu=vfpv4
# source: blank.s
# as: -mfpu=vfpv4
# readelf: -A
# This test is only valid on EABI based ports.
# target: *-*-*eabi *-*-nacl*

Attribute Section: aeabi
File Attributes
  Tag_ARM_ISA_use: Yes
  Tag_THUMB_ISA_use: Thumb-1
  Tag_FP_arch: VFPv4
  Tag_FP_HP_extension: Allowed
