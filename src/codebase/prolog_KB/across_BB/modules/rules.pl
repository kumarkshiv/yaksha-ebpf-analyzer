:- use_module(facts).

/*Rule to be exposed to the end users: to checking if a header.field is updated by the program.
    ****************  START ****************
*/
/*does_update_header_field(NF, Field) :- does_update_header_field(NF,_,Field).

does_read_header_field(NF, Field) :- reads_header_field(NF,_,Field).

does_update_buffer(NF, Field) :- writes_to_buffer_field(NF,_,Field).

does_drop_packets(NF, HOOK) :- return_value(NF, _,HOOK,"XDP_DROP"). 

does_accept_syn_packets(NF, HOOK) :- header_field_read(NF, X, "tcp.syn"), is_successor_BB(Y, X), return_value(NF, Y, HOOK, "XDP_PASS"),!. */
/*  does_accept_syn_packets(nfg1_sec1, "xdp").  */

/*does_accept_protocol(NF, PROTO, HOOK) :- protocol_accessed(NF,X,PROTO), is_successor_BB(Y, X), return_value(NF, Y, HOOK, "XDP_PASS"),!.*/
/*  does_accept_protocol(nfg1_sec2, "ipv4", "xdp"). -> false
    does_accept_protocol(nfg1_sec2, "ipv6", "xdp"). -> true  */

/*  ****************  END ****************  */