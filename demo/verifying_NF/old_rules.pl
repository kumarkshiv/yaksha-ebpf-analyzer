:- include(prolog).
:- include(nf_chain).
:- use_module(library(statistics)).
:- style_check(-discontiguous).
:- style_check(-singleton).

:- dynamic read_header_field/3, read_buffer_field/3, write_header_field/3, write_buffer_field/3, return_action/4, read_from_map/3, write_into_map/4, protocol_accessed/3, writes_header_field_per_path/3, map_updated_per_path/3.
:- use_module(library(statistics)).

%Returns True if the protocol field FieldName is being read in the NFG 
readsField(NFG,FieldName):-read_header_field(NFG,_,FieldName) ; read_buffer_field(NFG,_,FieldName).   

%Returns True if the protocol field FieldName is being updated in the NFG 
updatesField(NFG,FieldName):- write_header_field(NFG,_,FieldName) ; write_buffer_field(NFG,_,FieldName).

%Returns True if the buffer field BufferFieldName is being read in the NFG 
%readsBuffer(NFG,BufferFieldName):-read_buffer_field(NFG,_,BufferFieldName).  

%Returns True if the buffer field BufferFieldName is being updated in the NFG 
%updatesBuffer(NFG,BufferFieldName):-write_buffer_field(NFG,_,BufferFieldName).  

%Returns True if SuccNFG is the successor NFG of the CurrNFG
successor_nf(CurrNFG, SuccNFG):- edge_nf(CurrNFG, SuccNFG); edge_nf(CurrNFG,IntNFG),successor_nf(IntNFG,SuccNFG).

%Returns True if PredNFG is the predecessor NFG of the CurrNFG
predecessor_nf(CurrNFG, PredNFG):- edge_nf(PredNFG, CurrNFG); edge_nf(PredNFG,IntNFG),predecessor_nf(CurrNFG,IntNFG).

%Returns True if the Current NFG passes the packet
passesPacket(NFG, HookPoint):- return_action(NFG,_,HookPoint,"XDP_PASS").

%Returns True if the Current NFG passes the packet
dropsPacket(NFG, HookPoint):- return_action(NFG,_,HookPoint,"XDP_DROP").

%Returns True if the Current NFG writes given header field "FieldName" into some map "MapName"
writesToMap(NFG, MapName, FieldName):- write_into_map(NFG, _ ,FieldName, MapName).

%looksUpMap(NFG, MapName, FieldName):- read_from_map(NFG, _, MapName).
%mapLookup(NFG, MapName):- read_from_map(NFG, _, MapName).
%mapLookup(NFG, MapName):- all(NFG, Hook, [(Fld, Val)]), map_accessed_per_path(NFG, PID, MapName); read_from_map(NFG, _, MapName).
% If the paths have any maps passed as parameters, then it will call all() and gets PID, then every path (PID) will be checked for the map name.
%mapLookup(NFG, MapName):- (
 %   all(NFG, Hook, [("var", "var")]), 
 %   nb_getval(pid, PID),
 %   map_accessed_per_path(NFG, PID, MapName)
 %   ); read_from_map(NFG, _, MapName).

mapLookup(NFG, MapName) :-
    % Case 1: all drop PIDs access MapName
    ( nb_getval(pids, PIDs),
      PIDs \= [],  % make sure we actually have some PIDs
      forall(member(PID, PIDs),
             map_accessed_per_path(NFG, PID, MapName))
    ).

mapWrite(NFG, MapName) :-
    % Case 1: all drop PIDs access MapName
    ( nb_getval(pids, PIDs),
      PIDs \= [],  % make sure we actually have some PIDs
      forall(member(PID, PIDs),
             map_updated_per_path(NFG, PID, MapName))
    ).

%Returns True if the Current NFG reads the given header field "FieldName" and writes it into the Map
is_writing_to_map(NFG, MapName, FieldName):- readsField(NFG, FieldName),writesToMap(NFG, MapName ,FieldName).

callsHelper(Nf, Helper) :- invoked_helper(Nf,_,Helper).
accessesProtocol_bb(Nf, Proto) :- protocol_accessed(Nf,_,Proto).
dropsPacket(NFG, HookPoint):- return_action(NFG,_,HookPoint,"XDP_DROP").

%redirects predicate on Flg = Var returns all the Path IDs with return action as XDP_REDIRECT
%all(NFG, Hook, [(Fld, Val)]) :-
%    ( Fld = "accessesProtocol" ->
%        nb_getval(pid, PID),
%        per_path_fact(NFG, PID, Hook, "XDP_REDIRECT"),
%        protocol_accessed_per_path(NFG, PID, Val)
%    ; Fld = "accessesHelper" ->
%        nb_getval(pid, PID),
%        per_path_fact(NFG, PID, Hook, "XDP_REDIRECT"),
%        helper_accessed_per_path(NFG, PID, Val)
%    ; Fld = "var" ->
%        per_path_fact(NFG, PID, Hook, "XDP_REDIRECT"),
%        nb_setval(pid, PID)    
%    ).

all(NFG, Hook, [(Fld, Val)]) :-
    % Always find the matching PID first
    per_path_fact(NFG, PID, Hook, "XDP_REDIRECT"),
    nb_setval(pid, PID),  % Set PID globally for consistency

    % Then perform field-specific logic
    (
        Fld = "accessesProtocol" ->
            protocol_accessed_per_path(NFG, PID, Val)
    ;   Fld = "accessesHelper" ->
            helper_accessed_per_path(NFG, PID, Val)
    ;   Fld = "var" ->
            true  % No extra check — just setting PID was enough
    ).

% protocol_in_path(NFG, Proto) :-
%     nb_getval(pid, PID),
%     format("Read PID: ~w~n", [PID]),
%     protocol_accessed_per_path(NFG, PID, Proto).



% accessesProtocol(NFG, Proto) :-
%     (   nb_current(pid, PID)
%     ->  format("Read PID: ~w~n", [PID]),
%         protocol_accessed_per_path(NFG, PID, Proto),
%         nb_delete(pid),
%         format("deleted pid")
%     ;  format("accessesProtocol was called"),
%         accessesProtocol_bb(NFG, Proto)
%     ).

% Since accessesProtocol predicate can be used on path as well as basic block level, so if PID is given with the by
% packet_action_predicates like redirects, then protocol_accessed_per_path predicate will be called, else
% accessesProtocol_bb predicate will be called.

% accessesProtocol(NFG, Proto) :-
%     (   nb_current(pid, PID)
%     ->  format("Read PID: ~w~n", [PID]),
%         setup_call_cleanup(     % this function removes the PID after checking the predicate "protocol_accessed_per_path" on that. Reason to do this, can hold some PIDs from some previous query. So its better to delete the PID after using it.
%             true,
%             protocol_accessed_per_path(NFG, PID, Proto),
%             (nb_delete(pid), format("Deleted PID~n"))
%         )
%     ;   format("accessesProtocol was called~n"),
%         accessesProtocol_bb(NFG, Proto)
%     ).


%accessesProtocol(NFG, Proto) :-
%    (   nb_current(pid, PID)
%    ->      setup_call_cleanup(     % this function removes the PID after checking the predicate "protocol_accessed_per_path" on that. Reason to do this, can hold some PIDs from some previous query. So its better to delete the PID after using it.
%            true,
%            protocol_accessed_per_path(NFG, PID, Proto),
%            nb_delete(pid)
%        )
%    ;   accessesProtocol_bb(NFG, Proto)
%    ).

%accessesProtocol(NFG, Proto) :-
%    (   nonvar(NFG)
%    ->  protocol_accessed_per_path(NFG, _, Proto)
%    ;   nb_current(pid, PID)
%    ->  setup_call_cleanup(
%            true,
%            protocol_accessed_per_path(_, PID, Proto),
%            nb_delete(pid)
%        )
%    ;   accessesProtocol_bb(_, Proto)
%    ).

%accessesProtocol(NFG, Proto) :-
%    nb_current(pid, PID),
%    protocol_accessed_per_path(_, PID, Proto); accessesProtocol_bb(NFG, Proto).

%%%% WORKING RULE %%%%
%accessesProtocol(NFG, Proto) :-
%    (   %format("Fetched PID (accessesProtocol111): ~w~n", [PID]),
%        nb_current(pid, PID)
%    ->      setup_call_cleanup(     % this function removes the PID after checking the predicate "protocol_accessed_per_path" on that. Reason to do this, can hold some PIDs from some previous query. So its better to delete the PID after using it.
%            true,
%            protocol_accessed_per_path(NFG, PID, Proto),
%            nb_delete(pid)
%        )
%    ;   accessesProtocol_bb(NFG, Proto)
%    ).

%accessesProtocol(NFG, Proto) :-
%    (   nb_current(pid, PID)
%    ->  protocol_accessed_per_path(NFG, PID, Proto)
%    ;   accessesProtocol_bb(NFG, Proto)
%    ).

accessesProtocol(NFG, Proto) :-
    (   nb_current(pid_list, PIDs)      % if passes() has set pid_list
    ->  member(PID, PIDs),
        protocol_accessed_per_path(NFG, PID, Proto)
    ;   accessesProtocol_bb(NFG, Proto) % fallback if pid_list not set
    ).

%passes(NFG, Hook, [(Fld, Val)]) :-
%    ( Fld = "accessesProtocol" ->
%        nb_getval(pid, PID),
%        format("Fetched PID (accessesProtocol): ~w~n", [PID]),
%        per_path_fact(NFG, PID, Hook, "XDP_PASS"),
%        protocol_accessed_per_path(NFG, PID, Val)
%    ; Fld = "accessesHelper" ->
%        nb_getval(pid, PID),
%        per_path_fact(NFG, PID, Hook, "XDP_PASS"),
%        helper_accessed_per_path(NFG, PID, Val)
%    ; Fld = "var" ->
%        format("Fetched PID (accessesProtocol): ~w~n", [PID]),
%        per_path_fact(NFG, PID, Hook, "XDP_PASS"),
%        nb_setval(pid, PID)    
%    ).

passes(NFG, Hook, [(Fld, Val)]) :-
    (   Fld = "var"
    ->  % Collect all PIDs that have XDP_REDIRECT
        findall(PID,
                per_path_fact(NFG, PID, Hook, "XDP_PASS"),
                PIDList),
        PIDList \= [],           % ensure at least one PID exists
        nb_setval(pids, PIDList)
    ;   Fld = "accessesProtocol"
    ->  nb_getval(pids, PIDs),
        member(PID, PIDs),
        per_path_fact(NFG, PID, Hook, "XDP_PASS"),
        protocol_accessed_per_path(NFG, PID, Val)
    ;   Fld = "accessesHelper"
    ->  nb_getval(pids, PIDs),
        member(PID, PIDs),
        per_path_fact(NFG, PID, Hook, "XDP_PASS"),
        helper_accessed_per_path(NFG, PID, Val)
    
    ;   Fld = "accessesHelper"
    ->  nb_getval(pids, PIDs),
        member(PID, PIDs),
        per_path_fact(NFG, PID, Hook, "XDP_DROP"),
        helper_accessed_per_path(NFG, PID, Val)
    ).

passes(NFG, Hook, [("var","var"),("bufferRead",Field)]) :-
    % Collect all drop PIDs
    findall(PID,
        per_path_fact(NFG, PID, Hook, "XDP_PASS"),
        PIDs),
    nb_setval(pids, PIDs),

    % Collect all PIDs (among the drops) that also read the given field
    include(pid_reads_field(NFG, Field), PIDs, BufferReadPIDs),
    nb_setval(buffer_read_pids, BufferReadPIDs).

    pid_reads_field(NFG, Field, PID) :-
    reads_buffer_field_per_path(NFG, PID, Field).


redirects(NFG, Hook, [(Fld, Val)]) :-
    (   Fld = "var"
    ->  % Collect all PIDs that have XDP_REDIRECT
        findall(PID,
                per_path_fact(NFG, PID, Hook, "XDP_REDIRECT"),
                PIDList),
        PIDList \= [],           % ensure at least one PID exists
        nb_setval(pids, PIDList)
    ;   Fld = "accessesProtocol"
    ->  nb_getval(pids, PIDs),
        member(PID, PIDs),
        per_path_fact(NFG, PID, Hook, "XDP_REDIRECT"),
        protocol_accessed_per_path(NFG, PID, Val)
    ;   Fld = "accessesHelper"
    ->  nb_getval(pids, PIDs),
        member(PID, PIDs),
        per_path_fact(NFG, PID, Hook, "XDP_REDIRECT"),
        helper_accessed_per_path(NFG, PID, Val)
    ).

% drops(nat_xdpV2_xdp, "xdp", [("var", "var")]), reads_buffer_field_per_path(nat_xdpV2_xdp, "xdp_md.ingress_ifindex"), mapLookup(nat_xdpV2_xdp, "flow_table").
drops(NFG, Hook, [(Fld, Val)]) :-
    (   Fld = "var"
    ->  % Collect all PIDs that have XDP_REDIRECT
        findall(PID,
                per_path_fact(NFG, PID, Hook, "XDP_DROP"),
                PIDList),
        PIDList \= [],           % ensure at least one PID exists
        nb_setval(pids, PIDList)
    ;   Fld = "accessesProtocol"
    ->  nb_getval(pids, PIDs),
        member(PID, PIDs),
        per_path_fact(NFG, PID, Hook, "XDP_DROP"),
        protocol_accessed_per_path(NFG, PID, Val)
    ;   Fld = "accessesHelper"
    ->  nb_getval(pids, PIDs),
        member(PID, PIDs),
        per_path_fact(NFG, PID, Hook, "XDP_DROP"),
        helper_accessed_per_path(NFG, PID, Val)
    
    ;   Fld = "accessesHelper"
    ->  nb_getval(pids, PIDs),
        member(PID, PIDs),
        per_path_fact(NFG, PID, Hook, "XDP_DROP"),
        helper_accessed_per_path(NFG, PID, Val)
    ).

    % drops(nat_xdpV2_xdp, "xdp", [("var","var"),("bufferRead","xdp_md.ingress_ifindex")]), mapLookup(nat_xdpV2_xdp, "flow_table").
    drops(NFG, Hook, [("var","var"),("bufferRead",Field)]) :-
    % Collect all drop PIDs
    findall(PID,
        per_path_fact(NFG, PID, Hook, "XDP_DROP"),
        PIDs),
    nb_setval(pids, PIDs),

    % Collect all PIDs (among the drops) that also read the given field
    include(pid_reads_field(NFG, Field), PIDs, BufferReadPIDs),
    nb_setval(buffer_read_pids, BufferReadPIDs).

    pid_reads_field(NFG, Field, PID) :-
    reads_buffer_field_per_path(NFG, PID, Field).

   
   %drops(NFG, Hook, [(Fld, Val)]) :-
   % ( Fld = "var" ->
   %     per_path_fact(NFG, PID, Hook, "XDP_DROP"),
   %     % format("Fetched PID (var): ~w~n", [PID]),
   %     nb_setval(pid, PID)
   %
   % ; % generic fallback
   %     per_path_fact(NFG, PID, Hook, "XDP_DROP"),
   %     % format("Fetched PID (generic): ~w~n", [PID]),
   %     nb_setval(pid, PID),
   %     reads_buffer_field_per_path(NFG, PID, Fld)
   % ).

      
   %reads_buffer_field_per_path(NFG, Fld) :- nb_getval(pid, PID), reads_buffer_field_per_path(NFG, PID, Fld).

   %callsHelper_per_path(NFG, Helper) :- nb_getval(pid, PID), calls_helper_per_path(NFG, PID, Helper).

readsBufferField(NFG, Fld) :-
    %nb_getval(pid_list, PIDs),
    nb_getval(pids, PIDs),
    forall(member(PID, PIDs),
           reads_buffer_field_per_path(NFG, PID, Fld)).

%reads_header_field_per_path(NFG, Fld) :-
%    %nb_getval(pid_list, PIDs),
%    nb_getval(pids, PIDs),
%    forall(member(PID, PIDs),
%           reads_header_field_per_path(NFG, PID, Fld)).

readsHeaderField(NFG, Fld) :-
    (   nb_current(pids, _)                     % check if variable exists
    ->  nb_getval(pids, PIDList),
        (   PIDList \= []                       % only run case 1 if not empty
        ->  forall(
                member(PID, PIDList),
                reads_header_field_per_path(NFG, PID, Fld)
            )
        ;   readsField(NFG, Fld) % fall back if empty
        )
    ;   readsField(NFG, Fld)     % case 2: no pids at all
    ).


updatesBufferField(NFG, Fld) :-
    %nb_getval(pid_list, PIDs),
    nb_getval(pids, PIDs),
    forall(member(PID, PIDs),
           writes_buffer_field_per_path(NFG, PID, Fld)).

callsHelper(NFG, Helper) :-
    %nb_getval(pid_list, PIDs),
    nb_getval(pids, PIDs),
    forall(member(PID, PIDs),
           calls_helper_per_path(NFG, PID, Helper)).

updatesHeaderField(NFG, Fld) :-
    %nb_getval(pid_list, PIDs),
    nb_getval(pids, PIDs),
    forall(member(PID, PIDs),
           writes_header_field_per_path(NFG, PID, Fld));
    updatesField(NFG, Fld).



%%% Query execution time for Router NF (Klint)

run_router_queries :-
    get_time(T1),

    % List of queries to run in sequence
    Q1 = (passes(router_xdpV2_xdp_packet_parser, "xdp", [("var", "var")]),
          accessesProtocol(router_xdpV2_xdp_packet_parser, "Ethernet"),
          accessesProtocol(router_xdpV2_xdp_packet_parser, "IPv4")),

    Q2 = (passes(router_xdpV2_xdp_packet_parser, "xdp", [("var", "var")]),
          readsHeaderField(router_xdpV2_xdp_packet_parser, "IPv4.ttl")),

    Q3 = (passes(router_xdpV2_xdp_packet_parser, "xdp", [("var", "var")]),
          readsHeaderField(router_xdpV2_xdp_packet_parser, "IPv4.ihl")),

    Q4 = (passes(router_xdpV2_xdp_packet_parser, "xdp", [("var", "var")]),
          updatesHeaderField(router_xdpV2_xdp_packet_parser, "IPv4.ttl")),

    Q5 = (passes(router_xdpV2_xdp_packet_parser, "xdp", [("var", "var")]),
          readsHeaderField(router_xdpV2_xdp_packet_parser, "IPv4.check")),

    Q6 = (redirects(router_xdp_xdp, "xdp", [("var","var")]),
          mapLookup(router_xdp_xdp, "lpm_map")),

    % Run them all one by one, ignoring failure
    forall(member(Q, [Q1,Q2,Q3,Q4,Q5,Q6]), ignore(call(Q))),

    get_time(T2),
    TotalMS is (T2 - T1) * 1000,
    format('Total execution time: ~3f ms~n', [TotalMS]).


run_nat_queries :-
    get_time(T1),

    Q1 = (passes(nat_xdpV2_xdp, "xdp", [("var", "var")]),
          accessesProtocol(nat_xdpV2_xdp, "IPv4"),
          (accessesProtocol(nat_xdpV2_xdp, "TCP"); accessesProtocol(nat_xdpV2_xdp, "UDP"))),

    Q2 = (drops(nat_xdpV2_xdp, "xdp", [("var", "var")]),
          readsBufferField(nat_xdpV2_xdp, "xdp_md.ingress_ifindex"),
          mapLookup(nat_xdpV2_xdp, "flow_table")),

    Q3 = (passes(nat_xdpV2_xdp, "xdp", [("var","var"),("bufferRead","xdp_md.ingress_ifindex")]),
          updatesHeaderField(nat_xdpV2_xdp, "IPv4.saddr"),
          (updatesHeaderField(nat_xdpV2_xdp, "TCP.source"); updatesHeaderField("nf_id", "UDP.source"))),

    Q4 = (drops(nat_xdpV2_xdp, "xdp", [("var","var"),("bufferRead","xdp_md.ingress_ifindex")]),
          mapLookup(nat_xdpV2_xdp, "flow_table")),

    % Run all queries one by one; ignore success/failure
    forall(member(Q, [Q1,Q2,Q3,Q4]),
           (call(Q) -> true ; true)),

    get_time(T2),
    TotalMS is (T2 - T1) * 1000,
    format('Total execution time: ~3f ms~n', [TotalMS]).


run_maglev_queries :-
    get_time(T1),

    % Define each query
    Q1 = (passes(maglev_xdp_xdp, "xdp", [("var", "var")]),
          accessesProtocol(maglev_xdp_xdp, "IPv4"),
          (accessesProtocol(maglev_xdp_xdp, "TCP");
           accessesProtocol(maglev_xdp_xdp, "UDP"))),

    Q2 = (not(updatesHeaderField(maglev_xdp_xdp, _))),

    Q3 = (redirects(maglev_xdp_xdp, "xdp", [("var", "var")]),
          readsBufferField(maglev_xdp_xdp, "xdp_md.ingress_ifindex"),
          callsHelper(maglev_xdp_xdp, "bpf_ktime_get_ns")),

    % Run them all one by one
    forall(member(Q, [Q1, Q2, Q3]), call(Q)),

    get_time(T2),
    TotalMS is (T2 - T1) * 1000,
    format('Total execution time: ~3f ms~n', [TotalMS]).


run_firewall_queries :-
    get_time(T1),

    % Define each query
    Q1 = (passes(firewall_xdp_xdp_fw, "xdp", [("var", "var")]),
          accessesProtocol(firewall_xdp_xdp_fw, "IPv4"),
          (accessesProtocol(firewall_xdp_xdp_fw, "TCP");
           accessesProtocol(firewall_xdp_xdp_fw, "UDP"))),

    Q2 = (drops(firewall_xdp_xdp_fw, "xdp", [("var","var")]),
          readsBufferField(firewall_xdp_xdp_fw, "xdp_md.ingress_ifindex")),

    Q3 = (not(updatesField(firewall_xdp_xdp_fw, _))),

    % Run all queries, ignore success/failure
    forall(member(Q, [Q1, Q2, Q3]), ignore(call(Q))),

    get_time(T2),
    TotalMS is (T2 - T1) * 1000,
    format('Total execution time: ~3f ms~n', [TotalMS]).


run_bridge_queries :-
    get_time(T1),

    % Define query
    Q1 = (redirects(bridge_xdp_xdp, "xdp", [("var", "var")]),
          accessesProtocol(bridge_xdp_xdp, "Ethernet")),

    % Run it, ignoring success/failure
    ignore(call(Q1)),

    get_time(T2),
    TotalMS is (T2 - T1) * 1000,
    format('Total execution time: ~3f ms~n', [TotalMS]).


run_policer_queries :-
    get_time(T1),

    % Define queries
    Q1 = (redirects(policer_xdp_xdp_policer, "xdp", [("var", "var")]),
          accessesProtocol("policer_xdp_xdp_policer", "IPv4")),

    Q2 = (drops(policer_xdp_xdp_policer, "xdp", [("var", "var")]),
          accessesProtocol(policer_xdp_xdp_policer, "Ethernet"),
          readsBufferField(policer_xdp_xdp_policer, "xdp_md.ingress_ifindex")),

    % Run all queries, ignoring whether they succeed or fail
    forall(member(Q, [Q1, Q2]), ignore(call(Q))),

    get_time(T2),
    TotalMS is (T2 - T1) * 1000,
    format('Total execution time: ~3f ms~n', [TotalMS]).
