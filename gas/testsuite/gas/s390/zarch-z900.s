.text
foo:
	ag	%r9,4095(%r5,%r10)
	agf	%r9,4095(%r5,%r10)
	agfr	%r9,%r6
	aghi	%r9,-32767
	agr	%r9,%r6
	alcg	%r9,4095(%r5,%r10)
	alcgr	%r9,%r6
	alg	%r9,4095(%r5,%r10)
	algf	%r9,4095(%r5,%r10)
	algfr	%r9,%r6
	algr	%r9,%r6
	bctg	%r9,4095(%r5,%r10)
	bctgr	%r9,%r6
	brctg	%r9,.
	brxhg	%r9,%r6,.
	brxlg	%r9,%r6,.
	bxhg	%r9,%r6,4095(%r5)
	bxleg	%r9,%r6,4095(%r5)
	cdgbr	%f9,%r6
	cdgr	%f9,%r6
	cdsg	%r8,%r6,4095(%r5)
	cegbr	%f9,%r6
	cegr	%f9,%r6
	cg	%r9,4095(%r5,%r10)
	cgdbr	%r6,15,%f5
	cgdr	%r6,15,%f5
	cgebr	%r6,15,%f5
	cger	%r6,15,%f5
	cgf	%r9,4095(%r5,%r10)
	cgfr	%r9,%r6
	cghi	%r9,-32767
	cgr	%r9,%r6
	cgxbr	%r6,15,%f4
	cgxr	%r6,15,%f4
	clg	%r9,4095(%r5,%r10)
	clgf	%r9,4095(%r5,%r10)
	clgfr	%r9,%r6
	clgr	%r9,%r6
	clmh	%r9,10,4095(%r5)
	csg	%r9,%r6,4095(%r5)
	cvbg	%r9,4095(%r5,%r10)
	cvdg	%r9,4095(%r5,%r10)
	cxgbr	%f8,%r6
	cxgr	%f8,%r6
	dlg	%r8,4095(%r5,%r10)
	dlgr	%r8,%r6
	dsg	%r8,4095(%r5,%r10)
	dsgf	%r8,4095(%r5,%r10)
	dsgfr	%r8,%r6
	dsgr	%r8,%r6
	eregg	%r9,%r6
	esea	%r9
	icmh	%r9,10,4095(%r5)
	iihh	%r9,65535
	iihl	%r9,65535
	iilh	%r9,65535
	iill	%r9,65535
	lcgfr	%r9,%r6
	lcgr	%r9,%r6
	lctlg	%c9,%c6,4095(%r5)
	lg	%r9,4095(%r5,%r10)
	lgf	%r9,4095(%r5,%r10)
	lgfr	%r9,%r6
	lgh	%r9,4095(%r5,%r10)
	lghi	%r9,-32767
	lgr	%r9,%r6
	llgc	%r9,4095(%r5,%r10)
	llgf	%r9,4095(%r5,%r10)
	llgfr	%r9,%r6
	llgh	%r9,4095(%r5,%r10)
	llgt	%r9,4095(%r5,%r10)
	llgtr	%r9,%r6
	llihh	%r9,65535
	llihl	%r9,65535
	llilh	%r9,65535
	llill	%r9,65535
	lmd	%r9,%r6,4095(%r5),4095(%r10)
	lmg	%r9,%r6,4095(%r5)
	lmh	%r9,%r6,4095(%r5)
	lngfr	%r9,%r6
	lngr	%r9,%r6
	lpgfr	%r9,%r6
	lpgr	%r9,%r6
	lpq	%r8,4095(%r5,%r10)
	lpswe	4095(%r5)
	lrag	%r9,4095(%r5,%r10)
	lrvg	%r9,4095(%r5,%r10)
	lrvgr	%r9,%r6
	ltgfr	%r9,%r6
	ltgr	%r9,%r6
	lurag	%r9,%r6
	mghi	%r9,-32767
	mlg	%r8,4095(%r5,%r10)
	mlgr	%r8,%r6
	msg	%r9,4095(%r5,%r10)
	msgf	%r9,4095(%r5,%r10)
	msgfr	%r9,%r6
	msgr	%r9,%r6
	ng	%r9,4095(%r5,%r10)
	ngr	%r9,%r6
	nihh	%r9,65535
	nihl	%r9,65535
	nilh	%r9,65535
	nill	%r9,65535
	og	%r9,4095(%r5,%r10)
	ogr	%r9,%r6
	oihh	%r9,65535
	oihl	%r9,65535
	oilh	%r9,65535
	oill	%r9,65535
	rllg	%r9,%r6,4095(%r5)
	sam64
	sg	%r9,4095(%r5,%r10)
	sgf	%r9,4095(%r5,%r10)
	sgfr	%r9,%r6
	sgr	%r9,%r6
	slag	%r9,%r6,4095(%r5)
	slbg	%r9,4095(%r5,%r10)
	slbgr	%r9,%r6
	slg	%r9,4095(%r5,%r10)
	slgf	%r9,4095(%r5,%r10)
	slgfr	%r9,%r6
	slgr	%r9,%r6
	sllg	%r9,%r6,4095(%r5)
	srag	%r9,%r6,4095(%r5)
	srlg	%r9,%r6,4095(%r5)
	stcmh	%r9,10,4095(%r5)
	stctg	%c9,%c6,4095(%r5)
	stg	%r9,4095(%r5,%r10)
	stmg	%r9,%r6,4095(%r5)
	stmh	%r9,%r6,4095(%r5)
	stpq	%r9,4095(%r5,%r10)
	strag	4095(%r5),4095(%r9)
	strvg	%r9,4095(%r5,%r10)
	sturg	%r9,%r6
	tmhh	%r9,65535
	tmhl	%r9,65535
	tracg	%r9,%r6,4095(%r5)
	xg	%r9,4095(%r5,%r10)
	xgr	%r9,%r6
