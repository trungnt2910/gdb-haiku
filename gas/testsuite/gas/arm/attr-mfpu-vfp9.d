# name: attributes for -mfpu=vfp9
# source: blank.s
# as: -mfpu=vfp9
# readelf: -A
# This test is only valid on EABI based ports.
# target: *-*-*eabi

Attribute Section: aeabi
File Attributes
  Tag_ARM_ISA_use: Yes
  Tag_THUMB_ISA_use: Thumb-1
  Tag_VFP_arch: VFPv2
