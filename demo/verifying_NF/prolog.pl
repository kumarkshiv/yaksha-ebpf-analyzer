%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").

%%Fact_for_BB2
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet.h_proto").

%%Fact_for_BB3
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"Ethernet").

%%Fact_for_BB4

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"Ethernet").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"Ethernet").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"Ethernet").

%%Fact_for_BB8
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"Ethernet").

%%Fact_for_BB9
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"blocked_ports").

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12

%%Fact_for_BB13

%%Fact_for_BB14
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb14,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb14,"xdp","XDP_PASS").

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb13,xdp_fw_malicious_xdp_bb14).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").

%%Fact_for_BB2
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet.h_proto").

%%Fact_for_BB3
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"Ethernet").

%%Fact_for_BB4

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"Ethernet").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"Ethernet").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"Ethernet").

%%Fact_for_BB8
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"Ethernet").

%%Fact_for_BB9
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"blocked_ports").

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12

%%Fact_for_BB13

%%Fact_for_BB14
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb14,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb14,"xdp","XDP_PASS").

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb13,xdp_fw_malicious_xdp_bb14).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").

%%Fact_for_BB2
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet.h_proto").

%%Fact_for_BB3
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"Ethernet").

%%Fact_for_BB4

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"Ethernet").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"Ethernet").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"Ethernet").

%%Fact_for_BB8
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"Ethernet").

%%Fact_for_BB9
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"blocked_ports").

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12

%%Fact_for_BB13

%%Fact_for_BB14
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb14,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb14,"xdp","XDP_PASS").

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb14).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb13,xdp_fw_malicious_xdp_bb14).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").

%%Fact_for_BB2
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet.h_proto").

%%Fact_for_BB3

%%Fact_for_BB4
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb4,"Ethernet").

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"Ethernet").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"Ethernet").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"Ethernet").

%%Fact_for_BB8
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"blocked_ports").

%%Fact_for_BB9

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12

%%Fact_for_BB13
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_PASS").

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb13).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").

%%Fact_for_BB2
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet.h_proto").

%%Fact_for_BB3

%%Fact_for_BB4
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb4,"Ethernet").

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"Ethernet").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"Ethernet").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"Ethernet").

%%Fact_for_BB8
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"blocked_ports").

%%Fact_for_BB9

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12

%%Fact_for_BB13
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_PASS").

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb13).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").

%%Fact_for_BB2
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet.h_proto").

%%Fact_for_BB3

%%Fact_for_BB4
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb4,"Ethernet").

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"Ethernet").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"Ethernet").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"Ethernet").

%%Fact_for_BB8
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"blocked_ports").

%%Fact_for_BB9

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12

%%Fact_for_BB13
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_PASS").

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb13).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").

%%Fact_for_BB2
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet.h_proto").

%%Fact_for_BB3

%%Fact_for_BB4
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb4,"Ethernet").

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"Ethernet").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"Ethernet").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"Ethernet").

%%Fact_for_BB8
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"blocked_ports").

%%Fact_for_BB9

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12

%%Fact_for_BB13
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_PASS").

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb13).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").

%%Fact_for_BB2
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb2,"Ethernet.h_proto").

%%Fact_for_BB3

%%Fact_for_BB4
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb4,"Ethernet").

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"Ethernet").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"Ethernet").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"Ethernet").

%%Fact_for_BB8
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"blocked_ports").

%%Fact_for_BB9

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12

%%Fact_for_BB13
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb13,"xdp","XDP_PASS").

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb13).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet.h_proto").

%%Fact_for_BB2

%%Fact_for_BB3
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4.protocol").

%%Fact_for_BB4

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP.dest").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP").
write_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP.dest").

%%Fact_for_BB7

%%Fact_for_BB8
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"blocked_ports").

%%Fact_for_BB9

%%Fact_for_BB10

%%Fact_for_BB11
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb11,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb11,"xdp","XDP_PASS").

%%Fact_for_BB12

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb11).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4.protocol").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet.h_proto").

%%Fact_for_BB2

%%Fact_for_BB3
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4.protocol").

%%Fact_for_BB4

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP.dest").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP").
write_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP.dest").

%%Fact_for_BB7

%%Fact_for_BB8
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"blocked_ports").

%%Fact_for_BB9

%%Fact_for_BB10

%%Fact_for_BB11
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb11,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb11,"xdp","XDP_PASS").

%%Fact_for_BB12

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb11).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4.protocol").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet.h_proto").

%%Fact_for_BB2

%%Fact_for_BB3
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4.protocol").

%%Fact_for_BB4

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP.dest").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP").
write_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP.dest").

%%Fact_for_BB7

%%Fact_for_BB8
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb8,"blocked_ports").

%%Fact_for_BB9

%%Fact_for_BB10

%%Fact_for_BB11
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb11,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb11,"xdp","XDP_PASS").

%%Fact_for_BB12

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb12,xdp_fw_malicious_xdp_bb11).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4.protocol").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet.h_proto").

%%Fact_for_BB2

%%Fact_for_BB3
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4.protocol").

%%Fact_for_BB4

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP.dest").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP.check").
write_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP.check").
write_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP.dest").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"TCP").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"TCP.dest").

%%Fact_for_BB8

%%Fact_for_BB9
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"blocked_ports").

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb12,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb12,"xdp","XDP_PASS").

%%Fact_for_BB13

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb13,xdp_fw_malicious_xdp_bb12).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4.protocol").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.check").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.check").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.check").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.check").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.check").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.check").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data_end").

% END OF THE NFG 


%%Facts for xdp_fw_malicious

%%Fact_for_BB0
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data").
read_buffer_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb0,"xdp_md.data_end").

%%Fact_for_BB1
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb1,"Ethernet.h_proto").

%%Fact_for_BB2

%%Fact_for_BB3
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb3,"IPv4.protocol").

%%Fact_for_BB4

%%Fact_for_BB5
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb5,"TCP.dest").

%%Fact_for_BB6
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP.check").
write_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP.check").
write_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb6,"TCP.dest").

%%Fact_for_BB7
protocol_accessed(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"TCP").
read_header_field(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb7,"TCP.dest").

%%Fact_for_BB8

%%Fact_for_BB9
invoked_helper(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"bpf_map_lookup_elem").
read_from_map(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb9,"blocked_ports").

%%Fact_for_BB10

%%Fact_for_BB11

%%Fact_for_BB12
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb12,"xdp","XDP_DROP").
return_action(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_bb12,"xdp","XDP_PASS").

%%Fact_for_BB13

% NFG edges
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb1).
edge(xdp_fw_malicious_xdp_bb0,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb2).
edge(xdp_fw_malicious_xdp_bb1,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb3).
edge(xdp_fw_malicious_xdp_bb2,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb4).
edge(xdp_fw_malicious_xdp_bb3,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb5).
edge(xdp_fw_malicious_xdp_bb4,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb6).
edge(xdp_fw_malicious_xdp_bb5,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb6,xdp_fw_malicious_xdp_bb7).
edge(xdp_fw_malicious_xdp_bb7,xdp_fw_malicious_xdp_bb8).
edge(xdp_fw_malicious_xdp_bb8,xdp_fw_malicious_xdp_bb9).
edge(xdp_fw_malicious_xdp_bb9,xdp_fw_malicious_xdp_bb10).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb11).
edge(xdp_fw_malicious_xdp_bb10,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb12).
edge(xdp_fw_malicious_xdp_bb11,xdp_fw_malicious_xdp_bb13).
edge(xdp_fw_malicious_xdp_bb13,xdp_fw_malicious_xdp_bb12).
% Here goes the facts of the per-path context 
per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp","XDP_PASS").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_0,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_1,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"Ethernet.h_proto").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_2,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"IPv4.protocol").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_3,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_4,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_5,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"IPv4.protocol").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_6,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_7,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_8,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"blocked_ports").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_9,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.check").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.check").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_10,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp","XDP_PASS").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.check").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.check").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_11,"xdp_md.data_end").

per_path_fact(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp","XDP_DROP").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4").
protocol_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"Ethernet.h_proto").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"IPv4.protocol").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.check").
reads_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.check").
writes_header_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"TCP.dest").
calls_helper_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"blocked_ports").
map_accessed_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"true").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data").
reads_buffer_field_per_path(xdp_fw_malicious_xdp,xdp_fw_malicious_xdp_pid_12,"xdp_md.data_end").

% END OF THE NFG 


