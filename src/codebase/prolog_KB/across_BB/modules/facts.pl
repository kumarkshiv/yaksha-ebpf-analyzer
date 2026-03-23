:- module(all_facts,[does_read_header/2, does_drop_packets/2, does_update_header/3, does_update_header/2, does_update_buffer/2, does_accept_syn_packets/2, does_vlan_encapsulation/2]).

/* Facts for deployed NF. */
is_nf_deployed(nfg1_sec1).
is_nf_deployed(nfg2_sec1).

/* Facts related to NF chain. */


/*Query: Does the NF accepts tcp.syn packets.?*/
/*Facts for nfg1_sec1*/
% Facts_for_BB1
does_process_protocol(nfg1_sec1, nfg1_sec1_bb1, "eth").
reads_header_field(nfg1_sec1, nfg1_sec1_bb1,"eth.h_proto").

% Facts_for_BB2
does_process_protocol(nfg1_sec1, nfg1_sec1_bb2,"ipv6").
reads_header_field(nfg1_sec1, nfg1_sec1_bb2,"ipv6.protocol").

% Facts_for_BB3
does_process_protocol(nfg1_sec1, nfg1_sec1_bb3,"ipv4").
reads_header_field(nfg1_sec1, nfg1_sec1_bb3,"ipv4.saddr").
updates_header_field(nfg1_sec1, nfg1_sec1_bb3, "ipv4.saddr").

% Facts_for_BB4
does_process_protocol(nfg1_sec1, nfg1_sec1_bb4,"tcp").
reads_header_field(nfg1_sec1, nfg1_sec1_bb4,"tcp.syn").

% Facts_for_BB5
return_value(nfg1_sec1, nfg1_sec1_bb5,"xdp", "XDP_PASS").

% Facts_for_BB6
return_value(nfg1_sec1, nfg1_sec1_bb6,"xdp", "XDP_DROP").

% Edge_information_for_nfg1_sec1_basic_blocks
edge(nfg1_sec1_bb1,nfg1_sec1_bb2).
edge(nfg1_sec1_bb1,nfg1_sec1_bb3).
edge(nfg1_sec1_bb2,nfg1_sec1_bb4).
edge(nfg1_sec1_bb4,nfg1_sec1_bb5).
edge(nfg1_sec1_bb3,nfg1_sec1_bb6).

% Rule for getting successors of a Basic Block within the NF
is_successor_BB(X,Y):-edge(Y,X);edge(Y,Z),is_successor_BB(X,Z).

/* Rule for Query: Does the NF accepts tcp.syn packets.? */
does_accept_syn_packets(NF, HOOK) :- reads_header_field(NF, X, "tcp.syn"), is_successor_BB(Y, X), return_value(NF, Y, HOOK, "XDP_PASS"),!.




/*Query: Does the NF do VLAN encapsulation?*/
/*Facts for nfg2_sec1*/
% Facts_for_BB1
does_process_protocol(nfg2_sec1, nfg2_sec1_bb1, "eth").
reads_header_field(nfg2_sec1, nfg2_sec1_bb1,"eth.h_proto").

% Facts_for_BB4
does_process_protocol(nfg2_sec1, nfg2_sec1_bb4, "vlan").
reads_header_field(nfg2_sec1, nfg2_sec1_bb4,"vlan.h_vlan_encapsulated_proto").

% Facts_for_BB11
does_process_protocol(nfg2_sec1, nfg2_sec1_bb11, "ipv4").
reads_header_field(nfg2_sec1, nfg2_sec1_bb11,"ipv4.ihl").

% Facts_for_BB13
does_process_protocol(nfg2_sec1, nfg2_sec1_bb13,"ipv4").
reads_header_field(nfg2_sec1, nfg2_sec1_bb13,"ipv4.saddr").
reads_header_field(nfg2_sec1, nfg2_sec1_bb13,"ipv4.daddr").
invoked_helper(nfg2_sec1, nfg2_sec1_bb13, "bpf_map_lookup_elem").
accessed_map(nfg2_sec1, nfg2_sec1_bb13, "mptm_tnl_info_map").

% Facts_for_BB17
reads_header_field(nfg2_sec1, nfg2_sec1_bb17,"eth.h_proto").
/* We need to provide the hookpoint information because few helpers are dependent on eBPF program type.*/
hook_specific_helper("xdp", "bpf_xdp_adjust_head").
invoked_helper(nfg2_sec1, nfg2_sec1_bb17, HOOK, HELPER) :- hook_specific_helper(HOOK, HELPER).


% Facts_for_BB46
updates_header_field(nfg2_sec1, nfg2_sec1_bb46,"eth.h_proto", 129).
updates_header_field(nfg2_sec1, nfg2_sec1_bb46,"eth.h_proto").

/* edges for nfg1_sec1 */
edge(nfg2_sec1_bb1,nfg2_sec1_bb4).
edge(nfg2_sec1_bb4,nfg2_sec1_bb11).
edge(nfg2_sec1_bb11,nfg2_sec1_bb13).
edge(nfg2_sec1_bb13,nfg2_sec1_bb17).
edge(nfg2_sec1_bb17,nfg2_sec1_bb46).


/* Rule for Query: Does the NF do VLAN encapsulation? */
does_vlan_encapsulation(NF, HOOK) :- does_process_protocol(NF, BB, "ipv4"), is_successor_BB(SUCC, BB), invoked_helper(NF, SUCC, HOOK, "bpf_xdp_adjust_head"), is_successor_BB(SUCC1, SUCC), updates_header_field(NF, SUCC1, "eth.h_proto", 129),!.




/*Rule to be exposed to the end users: to checking if a header.field is updated by the program.
    ****************  START ****************
*/
does_update_header(NF, Field, Value) :- updates_header_field(NF,_,Field,Value),!.
does_update_header(NF, Field) :- updates_header_field(NF,_,Field), !.

does_read_header(NF, Field) :- reads_header_field(NF,_,Field).

does_update_buffer(NF, Field) :- updates_buffer_field(NF,_,Field).

does_drop_packets(NF, HOOK) :- return_value(NF, _,HOOK,"XDP_DROP").

/*  ****************  START ****************  */