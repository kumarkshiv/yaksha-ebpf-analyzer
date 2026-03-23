#include <string.h>
#include <set>
#include <vector>
#include <stack>
#include <queue>
#include <list>
#include <bits/stdc++.h>

using namespace std;

#ifndef NETCXT_STRUCTS_HPP
#define NETCXT_STRUCTS_HPP

/* The below structure is used for capturing protocol related network context information...!!! */
// struct header_fields_updated_info
// {
//     string name_of_header_field; /* Name of the header field that was updated */
//     string value_updated_with; /* Value with which this header field was updated */
// };

struct protocol_network_context
{
    string protocol_name;
    vector<string> header_fields_accessed;  /* This vector will have the header fields that are only read in the bytecode */
    pair<string, string> action_criteria_and_action;
    vector<pair<string, string>> header_fields_updated; /* This vector will have the header fields that were updated in the code */
};

struct argument_tag
{
    string tag_of_argument = "NULL";
    string value_of_argument = "NULL";
};

struct helper_network_context
{
    string name_of_helper_function; /* Name of the helper function */
    int helper_id;	            /* ID of the helper function */		 
    string does_packet_manipulation; /* Can this helper funtion be used to do packet header manipulation? */
    vector<argument_tag> argument_values; /* Details of the arguments that are passed to this helper function */
    helper_network_context() : argument_values(5){}; /* Maximum of 5 arguments can be passed in any helper function */
};

struct map_network_context
{
    string name_of_map;
    int size_of_key;
    string tag_of_the_key; /* This tag will store what is being passed as the key into the map, whether it is the source_port or the dest_port? */
    int size_of_value;
    string tag_of_the_value; /* Similarly, what is the information that is being written into the map, here, this info will be relevant when the value is being written into the map*/
};

struct network_context
{
    protocol_network_context protocol;
    helper_network_context helper;
    map_network_context map_information;
};

struct protocol_network_context_cfg
{
    set<string> protocol_names;
    set<string> header_fields_accessed;
    set<pair<string, string>> action_criteria_and_action;
    set<pair<string, string>> header_fields_updated;
};

struct helper_network_context_cfg
{
    set<tuple<string, int, string>> helper_function_info;
};

struct map_network_context_cfg
{
    set<tuple<string, int, string, int, string>> map_info;
};

struct network_context_cfg
{
    protocol_network_context_cfg protocol;
    helper_network_context_cfg helper;
    map_network_context_cfg map_information;
};

struct VertexProps { 
	std::string name; 
	int bb_first;
	int bb_last;
	int s_no;
	struct network_context_cfg context_info;
	};

struct EdgeProps   { std::string name; };

struct edge
{
    int src;
    int dst;
};

/* This struct will contain the information related to the edges of the CFG */
struct edge_information
{
    int source;             /* Source instruction of the edge */
    int destination;        /* Destination instruction _of the edge */
    string action_criteria; /* What was the Tag of the Jump statement, was it Sanity_check or next_protocol_check */
    string action;          /* What is the action that was taken on the Jump statement, Pass/Drop/Abort? */
};

struct JMP_statements_info
{
    /* Most of the "IF" statements is either Sanity check or Next Protocol Check*/
    int tag;           // Tags can be SANITY_CHECK, NEXT_PROTOCOL, SOME OTHER CHECKS like source_port = 1234 etc
    int proto_info;    // If this "IF" statement is for IPV4's sanity check, then this field have "IPV4" as proto_info
    string field_info; // If the condition is "tcp.source_port == 1234 " then the field will have field_info as "source_port" and proto_info as "TCP"
};

struct tag_information
{
    string tag_name; /* If the field of any protocol has been accessed, then the field name will be the tag*/
    int protocol;    /* The protocol whose field was accessed will be stored here */
    /* Example : In xdp_filter.c, there is a function that checks if the nexthdr is IPv6, then it accesses TCP's source port,
    it again accessed nextprotocol field of Ipv6, but now the current_protocol_back contains TCP and parser is not
    able to figure out the field, that is, nextprotocol of IPv6 */
};

/* This struct contains the type of value that the register contains in the "Tag" field and the value that it conatains  */
struct reg_state
{
    tag_information tag; /* Since, we will get the tags from the spec file as strings so the datatype of the Tag field should be string */
    int value;
};

#endif
