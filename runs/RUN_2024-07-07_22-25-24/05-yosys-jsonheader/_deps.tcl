set ::_synlig_defines [list]
verilog_defines -DPDK_sky130A
lappend ::_synlig_defines +define+PDK_sky130A
verilog_defines "-DSCL_sky130_fd_sc_hd\""
lappend ::_synlig_defines "+define+SCL_sky130_fd_sc_hd\""
verilog_defines -D__openlane__
lappend ::_synlig_defines +define+__openlane__
verilog_defines -D__pnr__
lappend ::_synlig_defines +define+__pnr__
verilog_defines -DUSE_POWER_PINS
lappend ::_synlig_defines +define+USE_POWER_PINS
read_verilog -sv -lib /home/nguyenviet/Downloads/des/runs/RUN_2024-07-07_22-25-24/tmp/b9f201b18a9c49b0981923df12660312.bb.v
set ::env(SYNTH_LIBS) /home/nguyenviet/Downloads/des/runs/RUN_2024-07-07_22-25-24/tmp/46ac9c5e09604a1c8fa98b5cc0fc6e58.lib
