# source: start1.s --march=common_v10_v32
# source: move-1.s --march=v32
# as: --em=criself
# ld: -m criself
# objdump: -p

# Test that linking a v32 object to a v10+v32 object
# does work and results in the output marked as a v32 object.

#...
private flags = 3: \[symbols have a _ prefix\] \[v32\]
#pass
