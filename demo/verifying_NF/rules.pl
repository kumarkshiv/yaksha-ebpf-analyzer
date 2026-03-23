:- include(prolog).
:- include(nf_chain).
:- use_module(library(statistics)).

:- dynamic read_header_field/3, read_buffer_field/3, write_header_field/3, write_buffer_field/3, return_action/4, updatesField/2.
:- use_module(library(statistics)).
:- dynamic updatesField/2.

:- dynamic read_header_field/3, read_buffer_field/3, write_header_field/3, write_buffer_field/3, return_action/4.

%Returns True if the protocol field FieldName is being read in the NFG 
does_read_field(NFG,FieldName):-read_header_field(NFG,_,FieldName) ; read_buffer_field(NFG,_,FieldName).  
does_read_field(NFG,FieldName):-read_header_field(NFG,_,FieldName) ; read_buffer_field(NFG,_,FieldName).  

%Returns True if the protocol field FieldName is being updated in the NFG 
updatesField(NFG,FieldName):- write_header_field(NFG,_,FieldName) ; write_buffer_field(NFG,_,FieldName).





%Returns True if the buffer field BufferFieldName is being read in the NFG 
%does_read_buffer(NFG,BufferFieldName):-read_buffer_field(NFG,_,BufferFieldName).  
%does_read_buffer(NFG,BufferFieldName):-read_buffer_field(NFG,_,BufferFieldName).  

%Returns True if the buffer field BufferFieldName is being updated in the NFG 
%does_update_buffer(NFG,BufferFieldName):-write_buffer_field(NFG,_,BufferFieldName).  
%does_update_buffer(NFG,BufferFieldName):-write_buffer_field(NFG,_,BufferFieldName).  

%Returns True if SuccNFG is the successor NFG of the CurrNFG
successor_nf(CurrNFG, SuccNFG):- edge_nf(CurrNFG, SuccNFG); edge_nf(CurrNFG,IntNFG),successor_nf(IntNFG,SuccNFG).
successor_nf(CurrNFG, SuccNFG):- edge_nf(CurrNFG, SuccNFG); edge_nf(CurrNFG,IntNFG),successor_nf(IntNFG,SuccNFG).

%Returns True if PredNFG is the predecessor NFG of the CurrNFG
predecessor_nf(CurrNFG, PredNFG):- edge_nf(PredNFG, CurrNFG); edge_nf(PredNFG,IntNFG),predecessor_nf(CurrNFG,IntNFG).
predecessor_nf(CurrNFG, PredNFG):- edge_nf(PredNFG, CurrNFG); edge_nf(PredNFG,IntNFG),predecessor_nf(CurrNFG,IntNFG).

%Returns True if the Current NFG passes the packet
does_pass_packet(NFG, HookPoint):- return_action(NFG,_,HookPoint,"XDP_PASS").

%Returns True if the Current NFG passes the packet
does_drop_packet(NFG, HookPoint):- return_action(NFG,_,HookPoint,"XDP_DROP").

%Returns True if the Current NFG writes given header field "FieldName" into some map "MapName"
does_write_map(NFG, MapName, FieldName):- write_into_map(NFG, _ ,FieldName, MapName).

%Returns True if the Current NFG reads the given header field "FieldName" and writes it into the Map
is_writing_to_map(NFG, MapName, FieldName):- does_read_field(NFG, FieldName),does_write_map(NFG, MapName ,FieldName).