#name: MOVW/MOVT shared libraries test 4
#source: movw-shared-4.s
#ld: -shared
#error: .*: relocation R_ARM_THM_MOVT_ABS against `d' can not be used when making a shared object; recompile with -fPIC
