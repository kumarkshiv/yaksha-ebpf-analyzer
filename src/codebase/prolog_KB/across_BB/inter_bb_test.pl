%Inter BB and Intra BB:
%Facts_for_nfg1_sec1

%Facts_for_BB1
protocol_accessed(nfg1_sec1, nfg1_sec1_bb1, "eth").

field_accessed(nfg1_sec1,nfg1_sec1_bb1,"eth.h_proto").
read_buffer(nfg1_sec1,nfg1_sec1_bb1,"xdp_md_data_end").

%Facts_for_BB2
protocol_accessed(nfg1_sec1,nfg1_sec1_bb2,"vlan").
field_accessed(nfg1_sec1,nfg1_sec1_bb2,"vlan.encap_proto").

%Facts_for_BB3
protocol_accessed(nfg1_sec1,nfg1_sec1_bb3,"ipv4").
field_accessed(nfg1_sec1,nfg1_sec1_bb3,"ipv4.saddr").
invoked_helper(nfg1_sec1,nfg1_sec1_bb3,"bpf_map_lookup_elem").

%Facts_for_BB4
protocol_accessed(nfg1_sec1,nfg1_sec1_bb4,"ipv4").
field_accessed(nfg1_sec1,nfg1_sec1_bb4,"ipv4.saddr").
invoked_helper(nfg1_sec1,nfg1_sec1_bb4,"bpf_map_lookup_elem").

%Facts_for_BB5
does_read_header_field(nfg1_sec1,nfg1_sec1_bb5,"ipv4.protocol").
does_read_header_field(nfg1_sec1,nfg1_sec1_bb5,"ipv4.saddr").
does_update_header_field(nfg1_sec1,nfg1_sec1_bb5,"ipv4.saddr").
return_value(nfg1_sec1,nfg1_sec1_bb5,"xdp", "XDP_DROP").
writes_to_buffer_field(nfg1_sec1, nfg1_sec1_bb5, "xdp_md.data").
writes_to_buffer_field(nfg1_sec1, nfg1_sec1_bb5, "xdp_md.data_end").

%Edge_information_for_nfg1_basic_blocks
edge(nfg1_sec1_bb1,nfg1_sec1_bb2).
edge(nfg1_sec1_bb1,nfg1_sec1_bb3).
edge(nfg1_sec1_bb2,nfg1_sec1_bb4).


/*Rule to be exposed to the end users: to checking if a header.field is updated by the program.
    ****************  START ****************
*/
does_update_header(NF, Field) :- does_update_header_field(NF,_,Field).
does_read_header(NF, Field) :- does_read_header_field(NF,_,Field).
does_update_buffer(NF, Field) :- writes_to_buffer_field(NF,_,Field).

does_drop_packets(NF, HOOK) :- return_value(NF, _,HOOK,"XDP_DROP").
# does_pass_packets(NF, HOOK) :- return_value(NF, _,HOOK,"XDP_PASS").
/*  ****************  END ****************  */

# Rule for getting successors of a Basic Block within the NF
successor_BB(X,Y):-edge(Y,X);edge(Y,Z),successor_BB(X,Z).

# %Rule to check the successor protocol.
# current_protocol_accessed(NF, proto) :- protocol_accessed(nfg1_sec1,Y,"eth"), successor_BB(X,Y), write(X).
# next_protocol_accessed(NF, proto) :- protocol_accessed(nfg1_sec1,X,"ipv4").

# p(NF, PR1, PR2, X) :- protocol_accessed(NF,Y,PR1), successor_BB(X,Y),protocol_accessed(NF,X,PR2),!.
are_protocols_accessed_in_sequence(NF, PR1, PR2) :- protocol_accessed(NF,Y,PR1), successor_BB(X,Y), protocol_accessed(NF,X,PR2),!.

/*
- By using the ";" operator we can actually get all the related facts that are matching the query.
- ";" stands for OR operator
- does_update_buffer(nfg2_sec1,"xdp_md_data"), successor_NF(_, nfg2_sec1), does_read_buffer(_, "xdp_md_data").
    -   
- protocol(nfg1_sec1,Y,"eth"), successor_BB(X,Y),protocol(nfg1_sec1,X,"ipv4").
*/