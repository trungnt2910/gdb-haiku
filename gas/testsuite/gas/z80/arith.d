#objdump: -d
#name: arithmetic and logic

.*: .*

Disassembly of section .text:

0+ <.text>:
[ 	]+[0-9a-f]+:[ 	]+87[ 	]+add a,a
[ 	]+[0-9a-f]+:[ 	]+80[ 	]+add a,b
[ 	]+[0-9a-f]+:[ 	]+81[ 	]+add a,c
[ 	]+[0-9a-f]+:[ 	]+82[ 	]+add a,d
[ 	]+[0-9a-f]+:[ 	]+83[ 	]+add a,e
[ 	]+[0-9a-f]+:[ 	]+84[ 	]+add a,h
[ 	]+[0-9a-f]+:[ 	]+85[ 	]+add a,l
[ 	]+[0-9a-f]+:[ 	]+86[ 	]+add a,\(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd 86 05[ 	]+add a,\(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd 86 05[ 	]+add a,\(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+c6 11[ 	]+add a,0x11
[ 	]+[0-9a-f]+:[ 	]+8f[ 	]+adc a,a
[ 	]+[0-9a-f]+:[ 	]+88[ 	]+adc a,b
[ 	]+[0-9a-f]+:[ 	]+89[ 	]+adc a,c
[ 	]+[0-9a-f]+:[ 	]+8a[ 	]+adc a,d
[ 	]+[0-9a-f]+:[ 	]+8b[ 	]+adc a,e
[ 	]+[0-9a-f]+:[ 	]+8c[ 	]+adc a,h
[ 	]+[0-9a-f]+:[ 	]+8d[ 	]+adc a,l
[ 	]+[0-9a-f]+:[ 	]+8e[ 	]+adc a,\(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd 8e 05[ 	]+adc a,\(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd 8e 05[ 	]+adc a,\(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+ce 11[ 	]+adc a,0x11
[ 	]+[0-9a-f]+:[ 	]+97[ 	]+sub a
[ 	]+[0-9a-f]+:[ 	]+90[ 	]+sub b
[ 	]+[0-9a-f]+:[ 	]+91[ 	]+sub c
[ 	]+[0-9a-f]+:[ 	]+92[ 	]+sub d
[ 	]+[0-9a-f]+:[ 	]+93[ 	]+sub e
[ 	]+[0-9a-f]+:[ 	]+94[ 	]+sub h
[ 	]+[0-9a-f]+:[ 	]+95[ 	]+sub l
[ 	]+[0-9a-f]+:[ 	]+96[ 	]+sub \(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd 96 05[ 	]+sub \(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd 96 05[ 	]+sub \(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+d6 11[ 	]+sub 0x11
[ 	]+[0-9a-f]+:[ 	]+9f[ 	]+sbc a,a
[ 	]+[0-9a-f]+:[ 	]+98[ 	]+sbc a,b
[ 	]+[0-9a-f]+:[ 	]+99[ 	]+sbc a,c
[ 	]+[0-9a-f]+:[ 	]+9a[ 	]+sbc a,d
[ 	]+[0-9a-f]+:[ 	]+9b[ 	]+sbc a,e
[ 	]+[0-9a-f]+:[ 	]+9c[ 	]+sbc a,h
[ 	]+[0-9a-f]+:[ 	]+9d[ 	]+sbc a,l
[ 	]+[0-9a-f]+:[ 	]+9e[ 	]+sbc a,\(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd 9e 05[ 	]+sbc a,\(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd 9e 05[ 	]+sbc a,\(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+de 11[ 	]+sbc a,0x11
[ 	]+[0-9a-f]+:[ 	]+a7[ 	]+and a
[ 	]+[0-9a-f]+:[ 	]+a0[ 	]+and b
[ 	]+[0-9a-f]+:[ 	]+a1[ 	]+and c
[ 	]+[0-9a-f]+:[ 	]+a2[ 	]+and d
[ 	]+[0-9a-f]+:[ 	]+a3[ 	]+and e
[ 	]+[0-9a-f]+:[ 	]+a4[ 	]+and h
[ 	]+[0-9a-f]+:[ 	]+a5[ 	]+and l
[ 	]+[0-9a-f]+:[ 	]+a6[ 	]+and \(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd a6 05[ 	]+and \(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd a6 05[ 	]+and \(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+e6 11[ 	]+and 0x11
[ 	]+[0-9a-f]+:[ 	]+af[ 	]+xor a
[ 	]+[0-9a-f]+:[ 	]+a8[ 	]+xor b
[ 	]+[0-9a-f]+:[ 	]+a9[ 	]+xor c
[ 	]+[0-9a-f]+:[ 	]+aa[ 	]+xor d
[ 	]+[0-9a-f]+:[ 	]+ab[ 	]+xor e
[ 	]+[0-9a-f]+:[ 	]+ac[ 	]+xor h
[ 	]+[0-9a-f]+:[ 	]+ad[ 	]+xor l
[ 	]+[0-9a-f]+:[ 	]+ae[ 	]+xor \(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd ae 05[ 	]+xor \(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd ae 05[ 	]+xor \(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+ee 11[ 	]+xor 0x11
[ 	]+[0-9a-f]+:[ 	]+b7[ 	]+or a
[ 	]+[0-9a-f]+:[ 	]+b0[ 	]+or b
[ 	]+[0-9a-f]+:[ 	]+b1[ 	]+or c
[ 	]+[0-9a-f]+:[ 	]+b2[ 	]+or d
[ 	]+[0-9a-f]+:[ 	]+b3[ 	]+or e
[ 	]+[0-9a-f]+:[ 	]+b4[ 	]+or h
[ 	]+[0-9a-f]+:[ 	]+b5[ 	]+or l
[ 	]+[0-9a-f]+:[ 	]+b6[ 	]+or \(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd b6 05[ 	]+or \(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd b6 05[ 	]+or \(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+f6 11[ 	]+or 0x11
[ 	]+[0-9a-f]+:[ 	]+bf[ 	]+cp a
[ 	]+[0-9a-f]+:[ 	]+b8[ 	]+cp b
[ 	]+[0-9a-f]+:[ 	]+b9[ 	]+cp c
[ 	]+[0-9a-f]+:[ 	]+ba[ 	]+cp d
[ 	]+[0-9a-f]+:[ 	]+bb[ 	]+cp e
[ 	]+[0-9a-f]+:[ 	]+bc[ 	]+cp h
[ 	]+[0-9a-f]+:[ 	]+bd[ 	]+cp l
[ 	]+[0-9a-f]+:[ 	]+be[ 	]+cp \(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd be 05[ 	]+cp \(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd be 05[ 	]+cp \(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+fe 11[ 	]+cp 0x11
[ 	]+[0-9a-f]+:[ 	]+3c[ 	]+inc a
[ 	]+[0-9a-f]+:[ 	]+04[ 	]+inc b
[ 	]+[0-9a-f]+:[ 	]+0c[ 	]+inc c
[ 	]+[0-9a-f]+:[ 	]+14[ 	]+inc d
[ 	]+[0-9a-f]+:[ 	]+1c[ 	]+inc e
[ 	]+[0-9a-f]+:[ 	]+24[ 	]+inc h
[ 	]+[0-9a-f]+:[ 	]+2c[ 	]+inc l
[ 	]+[0-9a-f]+:[ 	]+34[ 	]+inc \(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd 34 05[ 	]+inc \(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd 34 05[ 	]+inc \(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+3d[ 	]+dec a
[ 	]+[0-9a-f]+:[ 	]+05[ 	]+dec b
[ 	]+[0-9a-f]+:[ 	]+0d[ 	]+dec c
[ 	]+[0-9a-f]+:[ 	]+15[ 	]+dec d
[ 	]+[0-9a-f]+:[ 	]+1d[ 	]+dec e
[ 	]+[0-9a-f]+:[ 	]+25[ 	]+dec h
[ 	]+[0-9a-f]+:[ 	]+2d[ 	]+dec l
[ 	]+[0-9a-f]+:[ 	]+35[ 	]+dec \(hl\)
[ 	]+[0-9a-f]+:[ 	]+dd 35 05[ 	]+dec \(ix\+5\)
[ 	]+[0-9a-f]+:[ 	]+fd 35 05[ 	]+dec \(iy\+5\)
[ 	]+[0-9a-f]+:[ 	]+09[ 	]+add hl,bc
[ 	]+[0-9a-f]+:[ 	]+19[ 	]+add hl,de
[ 	]+[0-9a-f]+:[ 	]+29[ 	]+add hl,hl
[ 	]+[0-9a-f]+:[ 	]+39[ 	]+add hl,sp
[ 	]+[0-9a-f]+:[ 	]+dd 09[ 	]+add ix,bc
[ 	]+[0-9a-f]+:[ 	]+dd 19[ 	]+add ix,de
[ 	]+[0-9a-f]+:[ 	]+dd 29[ 	]+add ix,ix
[ 	]+[0-9a-f]+:[ 	]+dd 39[ 	]+add ix,sp
[ 	]+[0-9a-f]+:[ 	]+fd 09[ 	]+add iy,bc
[ 	]+[0-9a-f]+:[ 	]+fd 19[ 	]+add iy,de
[ 	]+[0-9a-f]+:[ 	]+fd 29[ 	]+add iy,iy
[ 	]+[0-9a-f]+:[ 	]+fd 39[ 	]+add iy,sp
[ 	]+[0-9a-f]+:[ 	]+ed 4a[ 	]+adc hl,bc
[ 	]+[0-9a-f]+:[ 	]+ed 5a[ 	]+adc hl,de
[ 	]+[0-9a-f]+:[ 	]+ed 6a[ 	]+adc hl,hl
[ 	]+[0-9a-f]+:[ 	]+ed 7a[ 	]+adc hl,sp
[ 	]+[0-9a-f]+:[ 	]+ed 42[ 	]+sbc hl,bc
[ 	]+[0-9a-f]+:[ 	]+ed 52[ 	]+sbc hl,de
[ 	]+[0-9a-f]+:[ 	]+ed 62[ 	]+sbc hl,hl
[ 	]+[0-9a-f]+:[ 	]+ed 72[ 	]+sbc hl,sp
[ 	]+[0-9a-f]+:[ 	]+03[ 	]+inc bc
[ 	]+[0-9a-f]+:[ 	]+13[ 	]+inc de
[ 	]+[0-9a-f]+:[ 	]+23[ 	]+inc hl
[ 	]+[0-9a-f]+:[ 	]+33[ 	]+inc sp
[ 	]+[0-9a-f]+:[ 	]+dd 23[ 	]+inc ix
[ 	]+[0-9a-f]+:[ 	]+fd 23[ 	]+inc iy
[ 	]+[0-9a-f]+:[ 	]+0b[ 	]+dec bc
[ 	]+[0-9a-f]+:[ 	]+1b[ 	]+dec de
[ 	]+[0-9a-f]+:[ 	]+2b[ 	]+dec hl
[ 	]+[0-9a-f]+:[ 	]+3b[ 	]+dec sp
[ 	]+[0-9a-f]+:[ 	]+dd 2b[ 	]+dec ix
[ 	]+[0-9a-f]+:[ 	]+fd 2b[ 	]+dec iy
#pass
