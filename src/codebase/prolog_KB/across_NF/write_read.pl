/* This is the .pl for the write_read pattern" */

%Facts for decap_kern : nfg1

%Facts_for_BB0
read_field(nfg1_sec1,nfg1_sec1_bb0,"xdp_md_data").
read_field(nfg1_sec1,nfg1_sec1_bb0,"xdp_md_data_end").


%Facts_for_BB1
protocol_accessed(nfg1_sec1,nfg1_sec1_bb1,"eth").
read_field(nfg1_sec1,nfg1_sec1_bb1,"eth.h_proto").

%Facts_for_BB4
protocol_accessed(nfg1_sec1,nfg1_sec1_bb4,"ipv4").
read_field(nfg1_sec1,nfg1_sec1_bb4,"ipv4.ihl").
%Added for testing recirsive query.
read_field(nfg1_sec1,nfg1_sec1_bb4,"ipv4.saddr").

%Facts_for_BB5
protocol_accessed(nfg1_sec1,nfg1_sec1_bb5,"ipv4").
read_field(nfg1_sec1,nfg1_sec1_bb5,"ipv4.frag_off").

%Facts_for_BB6
protocol_accessed(nfg1_sec1,nfg1_sec1_bb6,"ipv4").
read_field(nfg1_sec1,nfg1_sec1_bb6,"ipv4.protocol").
invoked_helper(nfg1_sec1,nfg1_sec1_bb6,"bpf_map_lookup_elem").
read_from_map(nfg1_sec1,nfg1_sec1_bb6,"decap_counters").
write_to_map(nfg1_sec1,nfg1_sec1_bb6,"ipv4.protocol","decap_counters").


%Facts_for_BB12
protocol_accessed(nfg1_sec1,nfg1_sec1_bb12,"eth").
read_field(nfg1_sec1,nfg1_sec1_bb12,"eth.h_dest").
read_field(nfg1_sec1,nfg1_sec1_bb12,"eth.h_source").

%Facts_for_BB16
protocol_accessed(nfg1_sec1,nfg1_sec1_bb16,"ipv6").
read_field(nfg1_sec1,nfg1_sec1_bb16,"ipv6.nexthdr").

%Facts_for_BB17
invoked_helper(nfg1_sec1,nfg1_sec1_bb17,"bpf_map_lookup_elem").
read_from_map(nfg1_sec1,nfg1_sec1_bb17,"decap_counters").

%Facts_for_BB30
protocol_accessed(nfg1_sec1,nfg1_sec1_bb30,"eth").
read_field(nfg1_sec1,nfg1_sec1_bb30,"eth.h_dest").
read_field(nfg1_sec1,nfg1_sec1_bb30,"eth.h_source").
protocol_accessed(nfg1_sec1,nfg1_sec1_bb30,"ipv6").
read_field(nfg1_sec1,nfg1_sec1_bb30,"ipv6.daddr").
read_field(nfg1_sec1,nfg1_sec1_bb30,"ipv6.saddr").
invoked_helper(nfg1_sec1,nfg1_sec1_bb30,"bpf_xdp_adjust_head").

%Facts_for_BB23
protocol_accessed(nfg1_sec1,nfg1_sec1_bb23,"eth").
read_field(nfg1_sec1,nfg1_sec1_bb23,"eth.h_dest").
read_field(nfg1_sec1,nfg1_sec1_bb23,"eth.h_source").
protocol_accessed(nfg1_sec1,nfg1_sec1_bb23,"ipv6").
read_field(nfg1_sec1,nfg1_sec1_bb23,"ipv6.daddr").
read_field(nfg1_sec1,nfg1_sec1_bb23,"ipv6.saddr").
invoked_helper(nfg1_sec1,nfg1_sec1_bb23,"bpf_xdp_adjust_head").

%Facts_for_BB27
protocol_accessed(nfg1_sec1,nfg1_sec1_bb23,"eth").
read_field(nfg1_sec1,nfg1_sec1_bb23,"eth.h_dest").
read_field(nfg1_sec1,nfg1_sec1_bb23,"eth.h_source").
invoked_helper(nfg1_sec1,nfg1_sec1_bb23,"bpf_xdp_adjust_head").
%return_value(nfg1_sec1, nfg1_sec1_bb27, "tc", "tc_act_shot").
return_value(nfg1_sec1, nfg1_sec1_bb27, "xdp", "xdp_drop").




%Facts for xdp_filter_syn : nfg2

%Facts_for_BB0
update_field(nfg2_sec1,nfg2_sec1_bb0,"xdp_md_data_end").

%Facts_for_BB1
protocol_accessed(nfg2_sec1,nfg2_sec1_bb1,"eth").
read_field(nfg2_sec1,nfg2_sec1_bb1,"eth.h_proto").

%Facts_for_BB4
protocol_accessed(nfg2_sec1,nfg2_sec1_bb4,"vlan").
read_field(nfg2_sec1,nfg2_sec1_bb4,"vlan.h_vlan_tci").
read_field(nfg2_sec1,nfg2_sec1_bb4,"vlan.h_vlan_encapsulated_proto").

%Facts_for_BB8
protocol_accessed(nfg2_sec1,nfg2_sec1_bb8,"vlan").
read_field(nfg2_sec1,nfg2_sec1_bb8,"vlan.h_vlan_tci").
read_field(nfg2_sec1,nfg2_sec1_bb8,"vlan.h_vlan_encapsulated_proto").

%Facts_for_BB11
invoked_helper(nfg2_sec1,nfg2_se1_bb11,"bpf_map_lookup_elem").
read_from_map(nfg2_sec1,nfg2_sec_bb11,"cpus_count").

%Facts_for_BB13
protocol_accessed(nfg2_sec1,nfg2_sec1_bb13,"ipv4").
read_field(nfg2_sec1,nfg2_sec1_bb13,"ipv4.protocol").

%Facts_for_BB15
protocol_accessed(nfg2_sec1,nfg2_sec1_bb15,"ipv4").
read_field(nfg2_sec1,nfg2_sec1_bb15,"ipv4.saddr").
read_field(nfg2_sec1,nfg2_sec1_bb15,"ipv4.daddr").

%Added for testing recirsive query.
update_field(nfg2_sec1,nfg2_sec1_bb15,"ipv4.saddr").

%Facts_for_BB26
protocol_accessed(nfg2_sec1,nfg2_sec1_bb26,"tcp").
read_field(nfg2_sec1,nfg2_sec1_bb26,"tcp.dest").
read_field(nfg2_sec1,nfg2_sec1_bb26,"tcp.source").

%Facts_for_BB27
invoked_helper(nfg2_sec1,nfg2_sec1_bb27,"bpf_map_lookup_elem").
read_from_map(nfg2_sec1,nfg2_sec1_bb27,"flow_table_v4").

%Facts_for_BB29
invoked_helper(nfg2_sec1,nfg2_sec1_bb29,"bpf_map_lookup_elem").
read_from_map(nfg2_sec1,nfg2_sec1_bb29,"tx_peer_int").

%Facts_for_BB45
protocol_accessed(nfg2_sec1,nfg2_sec1_bb45,"ipv4").
read_field(nfg2_sec1,nfg2_sec1_bb45,"ipv4.protocol").
invoked_helper(nfg2_sec1,nfg2_sec1_bb45,"bpf_map_lookup_elem").
read_from_map(nfg2_sec1,nfg2_sec1_bb45,"cpus_available").

%Facts_for_BB31
read_from_map(nfg2_sec1,nfg2_sec1_bb31,"tx_peer").

%Facts_for_BB52
read_from_map(nfg2_sec1,nfg2_sec1_bb52,"cpu_map").

%Facts_for_BB32
invoked_helper(nfg2_sec1,nfg2_sec1_bb32,"bpf_redirect_map").
update_field(nfg2_sec1,nfg2_sec1_bb32,"xdp_md_data").

%Facts_for_BB50
invoked_helper(nfg2_sec1,nfg2_sec1_bb50,"bpf_map_lookup_elem").
read_from_map(nfg2_sec1,nfg2_sec1_bb50,"cpus_available").

%Facts_for_BB40
invoked_helper(nfg2_sec1,nfg2_sec1_bb40,"bpf_map_lookup_elem").
read_from_map(nfg2_sec1,nfg2_sec1_bb40,"tx_peer_int").

%Facts_for_BB38
protocol_accessed(nfg2_sec1,nfg2_sec1_bb38,"ipv6").
protocol_accessed(nfg2_sec1,nfg2_sec1_bb38,"tcp").
read_field(nfg2_sec1,nfg2_sec1_bb38,"ipv6.daddr").
read_field(nfg2_sec1,nfg2_sec1_bb38,"ipv6.saddr").
read_field(nfg2_sec1,nfg2_sec1_bb38,"tcp.dest").
read_field(nfg2_sec1,nfg2_sec1_bb38,"tcp.source").
invoked_helper(nfg2_sec1,nfg2_sec1_bb38,"bpf_map_lookup_elem").
read_from_map(nfg2_sec1,nfg2_sec1_bb38,"flow_table_v6").
write_to_map(nfg2_sec1,nfg2_sec1_bb38,"eth.h_proto","flow_table_v6").

%Facts_for_BB21
protocol_accessed(nfg2_sec1,nfg2_sec1_bb21,"ipv6").
read_field(nfg2_sec1,nfg2_sec1_bb21,"ipv6.nexthdr").

%Facts_for_BB19
invoked_helper(nfg2_sec1,nfg2_sec1_bb19,"bpf_map_lookup_elem").
read_from_map(nfg2_sec1,nfg2_sec1_bb19,"cpus_count").
write_to_map(nfg2_sec1,nfg2_sec1_bb38,"eth.h_proto","cpus_count").
%return_value(nfg2_sec1, nfg2_sec1_bb19, "tc", "tc_act_ok").
return_value(nfg2_sec1, nfg2_sec1_bb19, "xdp", "xdp_pass").


/* NF chain ordering */
edge(nfg2_sec1,nfg1_sec1).
edge(nfg1_sec1,nfg3_sec1).

/* Test NF chain:
nf1 -> nf2 -> nf3 -> nf4
        v      v      v
       nf5    nf6    nf7

edge(nf1, nf2).
edge(nf2, nf3).
edge(nf3, nf4).
edge(nf2, nf5).
edge(nf3, nf6).
edge(nf4, nf7).*/


/* Rules */
% does_read_buffer(ID,X):-read_field(ID,_,X).

does_update_field(ID,X):-update_field(ID,_,X).

does_read_field(ID,X):-read_field(ID,_,X).

does_drop_packet(ID, HOOK) :- return_value(ID, _, HOOK, "tc_act_shot") ; return_value(ID, _, HOOK, "xdp_drop").

does_pass_packet(ID, HOOK) :- return_value(ID, _, HOOK, "tc_act_ok") ; return_value(ID, _, HOOK, "xdp_pass").

/* does_update_pkt_field() */

does_protocol_accessed(ID,X):-protocol_accessed(ID,_,X).

% path(X,Y) :- edge(X,Z).path(Z,Y),edge(X,Y).

/* Predecessor(X,Y) -> predecessor(X) = Y, Y comes before Y */
predecessor_nf(X,Y):-edge(Y,X);edge(Y,Z),predecessor_nf(X,Z).

/* Successor(X,Y) -> successor(X) = Y , Y comes after X */
% successor_nf(A,B):-edge(A,B);edge(A,Z),successor_nf(Z,B).
successor_nf(A,B):-edge(A,Z),successor_nf(Z,B);edge(A,B).

/* For a given eBPF program, is any specific’ header field being copied to any eBPF map? */
does_write_map(Nf,Pkt_field):-write_to_map(Nf,_,Pkt_field,_).
/* does_write_map(Nf,Pkt_field,Map_name):-write_to_map(Nf,_,Pkt_field,Map_name). */
/* does_write_map(Nf,Pkt_field):-write_to_map(Nf,_,Pkt_field,Map_name), print('Map:'), print(Map_name). */ 

/* does_any() :- does_update_field(NF,FL), successor_nf(NF,SU), does_read_field(SU,FL),!. */

/* aggregate_all(count, (does_update_field(NF,FL), successor_nf(NF,SU), does_read_field(SU,FL)), Count). 
        "Count" in a variable that holds the output: i.e., no. of such instance for which the rule computes to true.
*/