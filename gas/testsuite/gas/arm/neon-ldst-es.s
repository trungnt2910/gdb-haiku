@ test element and structure loads and stores.

	.text
	.arm
	.syntax unified

	vst2.8 {d2,d3},[r6,:128]
	vld3.8 {d1,d2,d3},[r7]!
	vst3.16 {d1,d3,d5},[r9,:64],r3
	vld4.32 {d2,d3,d4,d5},[r10]
	vst4.16 {d1,d3,d5,d7},[r10]
	vld1.16 {d1[],d2[]},[r10]
	vld1.16 {d1[]},[r10,:16]
	vld2.32 {d1[],d3[]},[r10,:64]
	vld3.s8 {d3[],d4[],d5[]},[r10],r12
	vld4.16 {d10[],d12[],d14[],d16[]},[r9]!
	vld4.16 {d10[],d11[],d12[],d13[]},[r9,:64]
	vld4.32 {d10[],d11[],d12[],d13[]},[r9,:64]
	vld4.32 {d10[],d11[],d12[],d13[]},[r9,:128]
	vld1.8 {d3[7]},[r5]!
	vst1.16 {d5[3]},[r5,:16]
	vld2.16 {d3[3],d4[3]},[r5,:32]!
	vst3.32 {d8[1],d9[1],d10[1]},[r5],r3
        
        vld1.8 {d8[2]},[r7]
        vld1.16 {d8[2]},[r7]
        vld1.16 {d8[2]},[r7,:16]
        vld1.32 {d8[1]},[r7]
        vld1.32 {d8[1]},[r7,:32]
        vld2.8 {d8[1],d9[1]},[r7]
        vld2.8 {d8[1],d9[1]},[r7,:16]
        vld2.16 {d8[1],d9[1]},[r7]
        vld2.16 {d8[1],d9[1]},[r7,:32]
        vld2.16 {d8[1],d10[1]},[r7]
        vld2.16 {d8[1],d10[1]},[r7,:32]
        vld2.32 {d8[1],d9[1]},[r7]
        vld2.32 {d8[1],d9[1]},[r7,:64]
        vld2.32 {d8[1],d10[1]},[r7]
        vld2.32 {d8[1],d10[1]},[r7,:64]
        vld3.8 {d8[1],d9[1],d10[1]},[r7]
        vld3.16 {d8[1],d9[1],d10[1]},[r7]
        vld3.16 {d8[1],d10[1],d12[1]},[r7]
        vld3.32 {d8[1],d9[1],d10[1]},[r7]
        vld3.32 {d8[1],d10[1],d12[1]},[r7]
	vld4.8 {d8[2],d9[2],d10[2],d11[2]},[r7]
	vld4.8 {d8[2],d9[2],d10[2],d11[2]},[r7,:32]
        vld4.16 {d8[1],d10[1],d12[1],d14[1]},[r7]
        vld4.16 {d8[1],d9[1],d10[1],d11[1]},[r7,:64]
        vld4.32 {d8[1],d10[1],d12[1],d14[1]},[r7]
        vld4.32 {d8[1],d10[1],d12[1],d14[1]},[r7,:64]
        vld4.32 {d8[1],d10[1],d12[1],d14[1]},[r7,:128]

	vtbl.8 d3,{d4},d5
	vtbl.8 d3,{q1-q2},d5
	vtbl.8 d3,{q15},d5

	vld2.32 {q1},[r7]
	vld4.32 {q1-q2},[r7]
	vld4.32 {q14-q15},[r7]
