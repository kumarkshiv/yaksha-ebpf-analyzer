/*Facts for nfg1_sec1*/
% Facts_for_BB1
protocol_accessed(nfg1_sec1, nfg1_sec1_bb1, "eth").
field_accessed(nfg1_sec1,nfg1_sec1_bb1,"eth.h_proto").
read_buffer(nfg1_sec1,nfg1_sec1_bb1,"xdp_md_data_end").

% Facts_for_BB2
protocol_accessed(nfg1_sec1,nfg1_sec1_bb2,"ipv6").
field_accessed(nfg1_sec1,nfg1_sec1_bb2,"ipv6.protocol").

% Facts_for_BB3
protocol_accessed(nfg1_sec1,nfg1_sec1_bb3,"ipv4").
field_accessed(nfg1_sec1,nfg1_sec1_bb3,"ipv4.saddr").
invoked_helper(nfg1_sec1,nfg1_sec1_bb3,"bpf_map_lookup_elem").

% Facts_for_BB4
protocol_accessed(nfg1_sec1,nfg1_sec1_bb4,"tcp").
field_accessed(nfg1_sec1,nfg1_sec1_bb4,"tcp.syn").

% Facts_for_BB5
reads_header_field(nfg1_sec1,nfg1_sec1_bb5,"ipv4.protocol").
reads_header_field(nfg1_sec1,nfg1_sec1_bb5,"ipv4.saddr").
writes_to_header_field(nfg1_sec1,nfg1_sec1_bb5,"ipv4.saddr").
return_value(nfg1_sec1,nfg1_sec1_bb5,"xdp", "XDP_PASS").
updates_buffer_field(nfg1_sec1, nfg1_sec1_bb5, "xdp_md.data").
updates_buffer_field(nfg1_sec1, nfg1_sec1_bb5, "xdp_md.data_end").

% Facts for BB6
return_value(nfg1_sec1,nfg1_sec1_bb5,"xdp", "XDP_DROP").

% Edge_information_for_nfg1_sec1_basic_blocks
edge(nfg1_sec1_bb1,nfg1_sec1_bb2).
edge(nfg1_sec1_bb1,nfg1_sec1_bb3).
edge(nfg1_sec1_bb2,nfg1_sec1_bb4).
edge(nfg1_sec1_bb4,nfg1_sec1_bb5).
edge(nfg1_sec1_bb3,nfg1_sec1_bb6).

/*Query: Does the NF accepts tcp.syn packets.?*/
/*Facts for nfg1_sec2*/
% Facts_for_BB1
protocol_accessed(nfg1_sec2,  nfg1_sec2_bb1, "eth").
field_accessed(nfg1_sec2, nfg1_sec2_bb1,"eth.h_proto").

% Facts_for_BB2
protocol_accessed(nfg1_sec2, nfg1_sec2_bb2,"ipv6").
field_accessed(nfg1_sec2, nfg1_sec2_bb2,"ipv6.protocol").

% Facts_for_BB3
protocol_accessed(nfg1_sec2, nfg1_sec2_bb3,"ipv4").
field_accessed(nfg1_sec2, nfg1_sec2_bb3,"ipv4.saddr").

% Facts_for_BB4
protocol_accessed(nfg1_sec2, nfg1_sec2_bb4,"tcp").
field_accessed(nfg1_sec2, nfg1_sec2_bb4,"tcp.syn").

% Facts_for_BB5
return_value(nfg1_sec2, nfg1_sec2_bb5,"xdp", "XDP_PASS").

% Facts_for_BB6
return_value(nfg1_sec2, nfg1_sec2_bb6,"xdp", "XDP_DROP").

% Edge_information_for_nfg1_sec2_basic_blocks
edge(nfg1_sec2_bb1,nfg1_sec2_bb2).
edge(nfg1_sec2_bb1,nfg1_sec2_bb3).
edge(nfg1_sec2_bb2,nfg1_sec2_bb4).
edge(nfg1_sec2_bb4,nfg1_sec2_bb5).
edge(nfg1_sec2_bb3,nfg1_sec2_bb6).

/********/

% Rule for getting successors of a Basic Block within the NF
is_successor_BB(X,Y):-edge(Y,X);edge(Y,Z),is_successor_BB(X,Z).

/*Rule to be exposed to the end users: to checking if a header.field is updated by the program.
    ****************  START ****************
*/
does_update_header(NF, Field) :- writes_to_header_field(NF,_,Field).

does_read_header(NF, Field) :- reads_header_field(NF,_,Field).

does_update_buffer(NF, Field) :- updates_buffer_field(NF,_,Field).

does_drop_packets(NF, HOOK) :- return_value(NF, _,HOOK,"XDP_DROP").

does_accept_syn_packets(NF, HOOK) :- field_accessed(NF, X, "tcp.syn"), is_successor_BB(Y, X), return_value(NF, Y, HOOK, "XDP_PASS"),!.
/*  does_accept_syn_packets(nfg1_sec1, "xdp").  */

/*does_accept_protocol(NF, PROTO, HOOK) :- protocol_accessed(NF,X,PROTO), is_successor_BB(Y, X), return_value(NF, Y, HOOK, "XDP_PASS"),!.*/
/*  does_accept_protocol(nfg1_sec2, "ipv4", "xdp"). -> false
    does_accept_protocol(nfg1_sec2, "ipv6", "xdp"). -> true  */

/*  ****************  END ****************  */