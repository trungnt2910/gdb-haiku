# This should match the stderr output of gas -m68000 on operands.s.
# We don't bother to match the exact error message, but instead just
# look for the statements which should fail.

.*operands.s: Assembler messages:
.*statement `tstl %a0' ignored
.*statement `tstl %a0@\(8,%d0:w:2\)' ignored
.*statement `tstl %a0@\(8,%d0:w:4\)' ignored
.*statement `tstl %a0@\(8,%d0:w:8\)' ignored
.*statement `tstl %a0@\(8,%d0:l:2\)' ignored
.*statement `tstl %a0@\(8,%d0:l:4\)' ignored
.*statement `tstl %a0@\(8,%d0:l:8\)' ignored
.*statement `tstl %a0@\(%d0:w:2\)' ignored
.*statement `tstl \(8,%a0,%d0\*2\)' ignored
.*statement `tstl \(8,%a0,%d0\*4\)' ignored
.*statement `tstl \(8,%a0,%d0\*8\)' ignored
.*statement `tstl \(8,%a0,%d0.w\*2\)' ignored
.*statement `tstl \(8,%a0,%d0.w\*4\)' ignored
.*statement `tstl \(8,%a0,%d0.w\*8\)' ignored
.*statement `tstl \(8,%a0,%d0.l\*2\)' ignored
.*statement `tstl \(8,%a0,%d0.l\*4\)' ignored
.*statement `tstl \(8,%a0,%d0.l\*8\)' ignored
.*statement `tstl \(8,%a1.w\*2,%a0\)' ignored
.*statement `tstl 8\(%a0,%d0.w\*2\)' ignored
.*statement `tstl 8\(%d0.w\*2,%a0\)' ignored
.*statement `tstl 8\(%a1.w\*2,%a0\)' ignored
.*statement `tstl \(%a0,%d0.w\*2\)' ignored
.*statement `tstl \(%d0.w\*2,%a0\)' ignored
.*statement `tstl %a0@\(1000,%d0:w:2\)' ignored
.*statement `tstl @\(1000,%d0:w:2\)' ignored
.*statement `tstl @\(%d0:w:2\)' ignored
.*statement `tstl @\(1000\)' ignored
.*statement `tstl %a0@\(100000\)' ignored
.*statement `tstl \(1000,%a0,%d0.w\*2\)' ignored
.*statement `tstl \(1000,%d0,%a0\)' ignored
.*statement `tstl \(1000,%a1.w\*2,%a0\)' ignored
.*statement `tstl 1000\(%a0,%d0.w\*2\)' ignored
.*statement `tstl 1000\(%d0,%a0\)' ignored
.*statement `tstl \(1000,%d0.w\*2\)' ignored
.*statement `tstl 1000\(%d0.w\*2\)' ignored
.*statement `tstl \(%d0.w\*2\)' ignored
.*statement `tstl \(100000,%a0\)' ignored
.*statement `tstl 100000\(%a0\)' ignored
.*statement `tstl %za1@\(1000,%d0:w:2\)' ignored
.*statement `tstl %za1@\(100000\)' ignored
.*statement `tstl \(1000,%za1,%d0.w\*2\)' ignored
.*statement `tstl \(1000,%d0,%za1\)' ignored
.*statement `tstl \(1000,%a1.w\*2,%za1\)' ignored
.*statement `tstl 1000\(%za1,%d0.w\*2\)' ignored
.*statement `tstl 1000\(%d0,%za1\)' ignored
.*statement `tstl \(100000,%za1\)' ignored
.*statement `tstl 100000\(%za1\)' ignored
.*statement `tstl %a0@\(1000,%zd1:w:2\)' ignored
.*statement `tstl @\(1000,%zd1:w:2\)' ignored
.*statement `tstl @\(%zd1:w:2\)' ignored
.*statement `tstl \(1000,%a0,%zd1.w\*2\)' ignored
.*statement `tstl \(1000,%zd1,%a0\)' ignored
.*statement `tstl \(1000,%za1.w\*2,%a0\)' ignored
.*statement `tstl 1000\(%a0,%zd1.w\*2\)' ignored
.*statement `tstl 1000\(%zd1,%a0\)' ignored
.*statement `tstl \(1000,%zd1.w\*2\)' ignored
.*statement `tstl 1000\(%zd1.w\*2\)' ignored
.*statement `tstl \(%zd1.w\*2\)' ignored
.*statement `tstl %a0@\(1000\)@\(2000,%d0:w:2\)' ignored
.*statement `tstl %a0@\(1000\)@\(%d0:w:2\)' ignored
.*statement `tstl %a0@\(1000\)@\(2000\)' ignored
.*statement `tstl @\(1000\)@\(2000,%d0:w:2\)' ignored
.*statement `tstl @\(1000\)@\(%d0:w:2\)' ignored
.*statement `tstl @\(1000\)@\(2000\)' ignored
.*statement `tstl %a0@\(0\)@\(2000,%d0:w:2\)' ignored
.*statement `tstl %a0@\(0\)@\(%d0:w:2\)' ignored
.*statement `tstl %a0@\(0\)@\(2000\)' ignored
.*statement `tstl @\(0\)@\(2000,%d0:w:2\)' ignored
.*statement `tstl @\(0\)@\(%d0:w:2\)' ignored
.*statement `tstl @\(0\)@\(2000\)' ignored
.*statement `tstl \(\[1000,%a0\],%d0:w:2,2000\)' ignored
.*statement `tstl \(\[1000,%a0\],%d0:w:2\)' ignored
.*statement `tstl \(\[1000,%a0\],2000\)' ignored
.*statement `tstl \(\[1000\],%d0:w:2,2000\)' ignored
.*statement `tstl \(\[1000\],%d0:w:2\)' ignored
.*statement `tstl \(\[1000\],2000\)' ignored
.*statement `tstl \(\[%a0\],%d0:w:2,2000\)' ignored
.*statement `tstl \(\[%a0\],%d0:w:2\)' ignored
.*statement `tstl \(\[%a0\],2000\)' ignored
.*statement `tstl \(\[0\],%d0:w:2,2000\)' ignored
.*statement `tstl \(\[0\],%d0:w:2\)' ignored
.*statement `tstl \(\[0\],2000\)' ignored
.*statement `tstl %a0@\(1000,%d0:w:2\)@\(2000\)' ignored
.*statement `tstl %a0@\(1000,%d0:w:2\)@\(0\)' ignored
.*statement `tstl @\(1000,%d0:w:2\)@\(2000\)' ignored
.*statement `tstl @\(1000,%d0:w:2\)@\(0\)' ignored
.*statement `tstl %a0@\(%d0:w:2\)@\(2000\)' ignored
.*statement `tstl %a0@\(%d0:w:2\)@\(0\)' ignored
.*statement `tstl @\(%d0:w:2\)@\(2000\)' ignored
.*statement `tstl @\(%d0:w:2\)@\(0\)' ignored
.*statement `tstl \(\[1000,%a0,%d0:w:2\],2000\)' ignored
.*statement `tstl \(\[1000,%d0:w:2,%a0\],2000\)' ignored
.*statement `tstl \(\[1000,%d0,%a0\],2000\)' ignored
.*statement `tstl \(\[1000,%a1,%a0\],2000\)' ignored
.*statement `tstl \(\[1000,%a1:w:2,%a0\],2000\)' ignored
.*statement `tstl \(\[1000,%a0,%d0:w:2\]\)' ignored
.*statement `tstl \(\[1000,%d0,%a0\]\)' ignored
.*statement `tstl \(\[1000,%d0:w:2\],2000\)' ignored
.*statement `tstl \(\[1000,%d0:w:2\]\)' ignored
.*statement `tstl \(\[%a0,%d0:w:2\],2000\)' ignored
.*statement `tstl \(\[%d0,%a0\],2000\)' ignored
.*statement `tstl \(\[%a0,%d0:w:2\]\)' ignored
.*statement `tstl \(\[%d0,%a0\]\)' ignored
.*statement `tstl \(\[%d0:w:2\],2000\)' ignored
.*statement `tstl \(\[%d0:w:2\]\)' ignored
.*statement `pea %pc@\(8,%d0:w:2\)' ignored
.*statement `pea %pc@\(%d0:w:2\)' ignored
.*statement `pea \(8,%pc,%d0.w\*2\)' ignored
.*statement `pea 8\(%pc,%d0.w\*2\)' ignored
.*statement `pea \(%pc,%d0.w\*2\)' ignored
.*statement `pea %pc@\(1000,%d0:w:2\)' ignored
.*statement `pea %pc@\(100000\)' ignored
.*statement `pea \(1000,%pc,%d0.w\*2\)' ignored
.*statement `pea \(1000,%d0,%pc\)' ignored
.*statement `pea \(1000,%a1.w\*2,%pc\)' ignored
.*statement `pea \(1000,%a1,%pc\)' ignored
.*statement `pea 1000\(%pc,%d0.w\*2\)' ignored
.*statement `pea 1000\(%d0,%pc\)' ignored
.*statement `pea 1000\(%a1,%pc\)' ignored
.*statement `pea \(100000,%pc\)' ignored
.*statement `pea 100000\(%pc\)' ignored
.*statement `pea %zpc@\(1000,%d0:w:2\)' ignored
.*statement `pea %zpc@\(100000\)' ignored
.*statement `pea \(1000,%zpc,%d0.w\*2\)' ignored
.*statement `pea \(1000,%d0,%zpc\)' ignored
.*statement `pea \(1000,%a1.w\*2,%zpc\)' ignored
.*statement `pea \(1000,%a1,%zpc\)' ignored
.*statement `pea 1000\(%zpc,%d0.w\*2\)' ignored
.*statement `pea 1000\(%d0,%zpc\)' ignored
.*statement `pea 1000\(%a1,%zpc\)' ignored
.*statement `pea \(100000,%zpc\)' ignored
.*statement `pea 100000\(%zpc\)' ignored
.*statement `pea %pc@\(1000\)@\(2000,%d0:w:2\)' ignored
.*statement `pea %pc@\(1000\)@\(%d0:w:2\)' ignored
.*statement `pea %pc@\(1000\)@\(2000\)' ignored
.*statement `pea %pc@\(0\)@\(2000,%d0:w:2\)' ignored
.*statement `pea %pc@\(0\)@\(%d0:w:2\)' ignored
.*statement `pea %pc@\(0\)@\(2000\)' ignored
.*statement `pea \(\[1000,%pc\],%d0:w:2,2000\)' ignored
.*statement `pea \(\[1000,%pc\],%d0:w:2\)' ignored
.*statement `pea \(\[1000,%pc\],2000\)' ignored
.*statement `pea \(\[%pc\],%d0:w:2,2000\)' ignored
.*statement `pea \(\[%pc\],%d0:w:2\)' ignored
.*statement `pea \(\[%pc\],2000\)' ignored
.*statement `pea %zpc@\(1000\)@\(2000,%d0:w:2\)' ignored
.*statement `pea %zpc@\(1000\)@\(%d0:w:2\)' ignored
.*statement `pea %zpc@\(1000\)@\(2000\)' ignored
.*statement `pea %zpc@\(0\)@\(2000,%d0:w:2\)' ignored
.*statement `pea %zpc@\(0\)@\(%d0:w:2\)' ignored
.*statement `pea %zpc@\(0\)@\(2000\)' ignored
.*statement `pea \(\[1000,%zpc\],%d0:w:2,2000\)' ignored
.*statement `pea \(\[1000,%zpc\],%d0:w:2\)' ignored
.*statement `pea \(\[1000,%zpc\],2000\)' ignored
.*statement `pea \(\[%zpc\],%d0:w:2,2000\)' ignored
.*statement `pea \(\[%zpc\],%d0:w:2\)' ignored
.*statement `pea \(\[%zpc\],2000\)' ignored
.*statement `pea %pc@\(1000,%d0:w:2\)@\(2000\)' ignored
.*statement `pea %pc@\(1000,%d0:w:2\)@\(0\)' ignored
.*statement `pea %pc@\(%d0:w:2\)@\(2000\)' ignored
.*statement `pea %pc@\(%d0:w:2\)@\(0\)' ignored
.*statement `pea \(\[1000,%pc,%d0:w:2\],2000\)' ignored
.*statement `pea \(\[1000,%d0:w:2,%pc\],2000\)' ignored
.*statement `pea \(\[1000,%d0,%pc\],2000\)' ignored
.*statement `pea \(\[1000,%a1,%pc\],2000\)' ignored
.*statement `pea \(\[1000,%pc,%a1\],2000\)' ignored
.*statement `pea \(\[1000,%a1:w:2,%pc\],2000\)' ignored
.*statement `pea \(\[1000,%pc,%d0:w:2\]\)' ignored
.*statement `pea \(\[1000,%d0,%pc\]\)' ignored
.*statement `pea \(\[1000,%a1,%pc\]\)' ignored
.*statement `pea \(\[%pc,%d0:w:2\],2000\)' ignored
.*statement `pea \(\[%pc,%a0\],2000\)' ignored
.*statement `pea \(\[%pc,%d0:w:2\]\)' ignored
.*statement `pea \(\[%d0,%pc\]\)' ignored
.*statement `pea %zpc@\(1000,%d0:w:2\)@\(2000\)' ignored
.*statement `pea %zpc@\(1000,%d0:w:2\)@\(0\)' ignored
.*statement `pea %zpc@\(%d0:w:2\)@\(2000\)' ignored
.*statement `pea %zpc@\(%d0:w:2\)@\(0\)' ignored
.*statement `pea \(\[1000,%zpc,%d0:w:2\],2000\)' ignored
.*statement `pea \(\[1000,%d0:w:2,%zpc\],2000\)' ignored
.*statement `pea \(\[1000,%d0,%zpc\],2000\)' ignored
.*statement `pea \(\[1000,%a1,%zpc\],2000\)' ignored
.*statement `pea \(\[1000,%zpc,%a1\],2000\)' ignored
.*statement `pea \(\[1000,%a1:w:2,%zpc\],2000\)' ignored
.*statement `pea \(\[1000,%zpc,%d0:w:2\]\)' ignored
.*statement `pea \(\[1000,%d0,%zpc\]\)' ignored
.*statement `pea \(\[1000,%a1,%zpc\]\)' ignored
.*statement `pea \(\[%zpc,%d0:w:2\],2000\)' ignored
.*statement `pea \(\[%zpc,%a0\],2000\)' ignored
.*statement `pea \(\[%zpc,%d0:w:2\]\)' ignored
.*statement `pea \(\[%d0,%zpc\]\)' ignored
.*statement `cmpib &1,0\(%pc\)' ignored
.*statement `cmpiw &1,0\(%pc\)' ignored
.*statement `cmpil &1,0\(%pc\)' ignored
.*statement `cmpb &1,0\(%pc\)' ignored
.*statement `cmpw &1,0\(%pc\)' ignored
.*statement `cmpl &1,0\(%pc\)' ignored
