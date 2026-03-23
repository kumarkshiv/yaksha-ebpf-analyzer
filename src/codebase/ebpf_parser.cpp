#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/libbpf_common.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include "netcxt_structs.hpp"
#include "l2_utils.hpp"
#include "elfio/elfio.hpp"
#include "map_context_util.hpp"

#define PRINT_DEBUG 0
#define ETH -1
#define garbage_value 0 /* For the registers like r0, intially, it contains garbage_value */

using namespace std;
using namespace ELFIO;
int total_number_of_instruction;

/*This enum values are realted to protocols */
enum protocol
{
    NONE = 0,
    ETHERNET,
    IPV4,
    IPV6,
    TCP,
    UDP,
    VLAN,
    GRE
};

enum protocol_checks_states
{
    /* These enum values represents the state of the 2 checks we evaluate to take the decisions on the protocols accessed */
    true_state,
    false_state,
    null_state

};

enum JMP_statements_tags
{
    SANITY_CHECK,        /* If the JMP statement is actually doing a Sanity Check, then the t*/
    NEXT_PROTOCOL_CHECK, /* If the JMP stmt is having check1 which is for Next_protocol_check, then this will be the tag */
    FIELD_CHECK,         /* If the JMP stmt is basically check on some field value of a protocol, like tcp.source_port = 1234, then here
                        tag will be FIELD_CHECK*/
    OTHER_CHECKS         /* This will be for other miscalleneous checks */

};

map<int, JMP_statements_info> JMP_statements_state; /* This map is for keeping the state of each Jump statement. Here, instruction number of the JUMP stmt will be
sent to  as the Key */

map<int, pair<bool, bool>> protocol_checks; /* This map will hold the state of the 2 checks, which will be used to take the decisions on protocols accessed */
stack<map<int, pair<bool, bool>>> protocol_checks_stack;
int number_of_vlan = 0;

vector<int> protocol_accessed(7, 0); /*To handle the query: Which snippet is dropping TCP packet, we need to use this vector.
If protocol_check is 1 but the protocol is not accessed that means the protocol will be dropped
0: ethernet, 1: IPV4, 2: IPV6, 3: TCP, 4: UDP, 5 : VLAN, 6 : GRE  */
vector<int> protocol_check(6);       // 0 : IPv4, 1 : IPv6, 2 : TCP, 3 : UDP , 4 : VLAN, 5 : GRE

vector<int> current_protocol_id;              /* This variable contains the id of the current protocol, initially as per the assumption
                                               we will start with the ETH[We can't initialize it with ETH as that
                                               decision will be taken at the sanity checks]. Problem can happen during the Tunneling part */
stack<vector<int>> current_protocol_id_stack; /* This stack keeps the track of current_protocol_id of each path */

int this_protocol_maybe; /* This variable is used keep the track of the current protocol id whose Check1 has been passed, else put -1 as it's value .
                                    This stack will be relevant only when we are evaluating the check2 */

stack<int> this_protocol_maybe_stack; /* Keeps the track of the this_protocol_maybe variable */

stack<int> stack_protocol;         // As soon as we get the protocol confirmation on the if statements, we push it into the stack
bool exit_condition = false;       // This will be used to stop the while loop when all the edges have been processed
stack<int> stack_jump_instruction; // This stack will hold the index of the JUMP instruction currently being processed

/* This vector is used to verify if the protocol is actually accessed or not */
vector<reg_state> state_array(11);             /* This vector will hold the tag and the value of each of the register */
stack<vector<reg_state>> register_state_stack; /* Whenever we encounter a JMP instruction, we push the current register states into the stack
                                                and continue the execution */

vector<reg_state> ebpf_memory_stack(512); /* This is the memory where the values of the registers are stored and fetched back for the reuse */

/* This function will take the tag of the register and return TRUE if tag is amongst the tags in the vector */
bool check_reg_tag(string tag)
{
    // cout << "Check_register_tag func was called " << endl;
    vector<string> reg_tag_values;
    reg_tag_values.emplace_back("garbage_value");
    reg_tag_values.emplace_back("integer_value");
    reg_tag_values.emplace_back("ptr_to_ctx");
    reg_tag_values.emplace_back("ptr_to_packet_start");
    reg_tag_values.emplace_back("ptr_to_packet_end");
    reg_tag_values.emplace_back("ptr_to_frame");
    reg_tag_values.emplace_back("value_from_map");             /* Whenever any map related helper function is called, the value from that helper function is stored in the r0, so this tag will be used when map related helper function is called */
    reg_tag_values.emplace_back("value_from_helper_function"); /* When helper function other than map helper function will be called, then we will update the r0.tag with this tag */
    // cout << "Not seg fault here 1 " << endl;

    int size = reg_tag_values.size();
    for (int i = 0; i < size; i++)
    {
        if (tag == reg_tag_values[i])
            return false;
    }
    return true;
}

/* After one path have been executed, we need re-initialize the array which stores the tag and value of each registers. This work is done by this function*/
void re_initialize_state_array()
{
    state_array[0].tag.tag_name = "integer_value";
    state_array[0].value = garbage_value;
    state_array[10].tag.tag_name = "ptr_to_frame";
    state_array[10].value = garbage_value;
    state_array[1].tag.tag_name = "ptr_to_ctx";
    state_array[1].value = garbage_value;
    for (int i = 2; i < 10; i++)
    {
        state_array[i].tag.tag_name = "NULL";
        state_array[i].value = garbage_value;
    }
}

vector<vector<int>> all_paths; // This vector contains all the possible paths in the a code

class parse_inst
{
public:
    struct bpf_object *obj;
    struct bpf_program *bpf_prog;
    const struct bpf_insn *orig_insns;
    vector<bpf_insn> inst_list;
    size_t inst_count;
    // vector<reg_state> state_array[11]; // This vector will hold the tag and value of all the 11 registers

    // Getters
    size_t get_inst_count()
    {
        return inst_count;
    }

    vector<bpf_insn> get_inst_list()
    {
        return inst_list;
    }

    bpf_object *get_bpf_object()
    {
        return obj;
    }

    /* Prototype of the Constructor */
    parse_inst(const char *filename, const char *prog_name);
};

/* Constructor of class "parse_inst" */
parse_inst ::parse_inst(const char *filename, const char *prog_name)
{
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
    {
        // cout << stderr, "ERROR: opening BPF object file failed\n";
        // return 0;
        exit;
    }

    bpf_prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!bpf_prog)
    {
        // cout << "finding a prog in obj file failed\n";
        // return 0 ;
        exit;
    }
    orig_insns = bpf_program__insns(bpf_prog);
    inst_count = bpf_program__insn_cnt(bpf_prog);
    for (int i = 0; i < inst_count; i++)
    {
        /* REVIEW:  */
        /* Review: We can directly use 'orig_insns' instead of creating a new vector.*/
        inst_list.push_back(bpf_insn());
        inst_list[i].code = (orig_insns + i)->code;
        inst_list[i].dst_reg = (orig_insns + i)->dst_reg;
        inst_list[i].src_reg = (orig_insns + i)->src_reg;
        inst_list[i].off = (orig_insns + i)->off;
        inst_list[i].imm = (orig_insns + i)->imm;
    }
}

class flow_prop
{
public:
    int instr_no;
    Specification spec;

    vector<network_context> network_context_per_inst;

    vector<edge_information> edge_context;

    vector<network_context> get_network_context_per_inst()
    {
        return network_context_per_inst;
    }

    vector<edge_information> get_edge_context()
    {
        return edge_context;
    }

    void intialize_protocol_check(int key)
    {
        /* This function is used to initialize a Protocol as "Key" in the map "protocol_checks" when Check 1 is encountered */
        protocol_checks[key].first = null_state;
        protocol_checks[key].second = null_state;
    }

    /* The pair gives the relative offset and the protocol we're referring to  */
    pair<int, int> get_relative_offset(int total_offset)
    {

        /* Given offset can be from the start of the packet or start of the protocol header itself.
        So we must compute the relative offset, that is, from the start of the current protocol header */
        /* Use case : for a field of IPV4 at offset 9, the bytecode can have off = 9 or off = 14(size of ETH) + 9 */
        int size = current_protocol_id.size();
        size -= 2;
        int offset = 0;
        int final_offset = total_offset;
        int protocol_id = -1;
        int net_difference;
        string string_offset;
        int int_offset;
        for (int i = 0; i <= size; i++)
        {
            string dummy_current_protocol = to_string(current_protocol_id[i]);
            string_offset = spec.get_header_size_bytes(dummy_current_protocol);
            int_offset = stoi(string_offset);
            offset += int_offset;
            net_difference = total_offset - offset;
            if (net_difference < 0)
            {
                break;
            }
            final_offset = net_difference;
            protocol_id = current_protocol_id[i + 1];
        }
        return make_pair(final_offset, protocol_id); /* The pair gives the relative offset and the protocol we're referring to  */
    }

    int get_relative_header_size()
    {
        /*For Check2[Sanity check], header size is added to the register, and then checked if it exceeds packet_end or not.
        Now this header_size can be relative to the previous protocol or start from the start itself, so we need to get the relative
        header size  */
        /* UseCase : For sanity check of TCP , r3+=8 can also be there or r3+= 14 + 20 + 8 can also be there,
        But we handled this scenario by adding all the header sizes as data propagation as suggested by Venkat anna */
        int size = current_protocol_id.size();
        int offset = 0;
        string string_offset;
        int int_offset;
        for (int i = 0; i < size; i++)
        {
            string dummy_current_protocol = to_string(current_protocol_id[i]);
            string_offset = spec.get_header_size_bytes(dummy_current_protocol);
            int_offset = stoi(string_offset);

            offset += int_offset;
        }
        return offset;
    }

    /* Creating a dummy function that takes the header size the returns the protocol name */

    /* This function handles the instruction of JMP class  */ // tobi
    void parse_JMP(int mode, char src_reg[20], char dst_reg[20], int imm, int off, int instruction_number, int parent)
    {
        /* Handled OPs in JMP Class : BPF_EXIT, BPF_JEQ, BPF_JNE, BPF_JGT */
        network_context new_context;
        int local_src_reg = find_reg(src_reg);
        int local_dst_reg = find_reg(dst_reg);
        if (mode == BPF_EXIT)
        {
            /*
             * Only used in Classic BPF and reserved in eBPF:
             * https://www.kernel.org/doc/Documentation/networking/filter.txt
             */
            // cout << "This is an exit instruction" << endl;
            // cout << "Status of stack " << stack_jump_instruction.empty() << endl; // debug
            /* Here, code to accumulates the register states will take place */
            /* Note : EXIT stmts can have multiple parent node */
            /* Logic : We just need to push the register states of the parent node in this node , parent node is already
            available as parent in passed in the argument of this parse_JMP function */
        }
        else if (mode == BPF_CALL)
        {
            /* This else if is used ot populate the information related to the helper functions */
            string name_of_the_helper = spec.get_helper_function_name(to_string(imm));
            network_context_per_inst[instruction_number].helper.helper_id = imm;
            network_context_per_inst[instruction_number].helper.name_of_helper_function = name_of_the_helper;
            network_context_per_inst[instruction_number].helper.does_packet_manipulation = spec.get_does_packet_manipulation(to_string(imm));
            int size_of_arg = spec.get_arguments(to_string(imm)).size();
            if (imm != 1 and imm != 2 and imm != 3 and imm != 53 and imm != 87 and imm != 88 and imm != 89 and imm != 164 and imm != 195)
            {
                for (int i = 0; i < size_of_arg; i++)
                {
                    network_context_per_inst[instruction_number].helper.argument_values[i].tag_of_argument = state_array[i + 1].tag.tag_name;
                    network_context_per_inst[instruction_number].helper.argument_values[i].value_of_argument = to_string(state_array[i + 1].value);
                }
                state_array[0].tag.tag_name = "value_from_helper_function"; /* Check the description of this Tag */
            }
            else
            {
                // cout << "Map related args will be populated later" << endl;
                state_array[0].tag.tag_name = "value_from_map"; /* Check the description of this Tag */
            }
        }
        else if (mode == BPF_JGT) /* for check 2 */
        {

            // cout << "IF stmt : Mostly for Sanity check " << endl;
            if (spec.get_header_size_bytes(to_string(this_protocol_maybe)).size())
            {
                /* In case of R1 > R8, R1(Dest Reg):data, R8(Src Reg):data_end*/
                if (state_array[local_src_reg].tag.tag_name == "ptr_to_packet_end" && state_array[local_dst_reg].tag.tag_name == "ptr_to_packet_start" && (stoi(spec.get_header_size_bytes(to_string(this_protocol_maybe))) == (state_array[local_dst_reg].value) - get_relative_header_size()))
                /*Logic : Since, get_header_size_bytes returns size in string, so we converted the string size into Integer by using stoi()
                On RHS : The value at the local_dst_reg is the summation of the size of all the current protocols, so we subtracted the relative_header size to compare */
                {
                    JMP_statements_state[instruction_number].tag = SANITY_CHECK;
                    JMP_statements_state[instruction_number].proto_info = this_protocol_maybe;
                    JMP_statements_state[instruction_number].field_info = "NULL";
                }
                else
                {
                    /*Review: Can we remove this block.?*/

                    // cout << "Can't figure out this statement" << endl;
                    for (int i = 0; i < 6; i++)
                    {
                        // cout << "Register R" << i << " Tag : " << state_array[i].tag.tag_name << " Value : " << state_array[i].value << endl;
                    }
                }
            }
                
            else
            {
                /*Review: Can we remove this block.?*/
                // cout << "This sanity check was not handled " << endl;
            }
        }
        else if (mode == BPF_JEQ || mode == BPF_JNE)
        {
            /* Since we're only storing the condition at this "IF" statement and the decision is not being taken here, so we can combine the logic
            of both these modes */

            // cout << "This is IF stmt : < == > or < != >" << endl;

            /*Review: Can we remove unnecessary IF blocks. */
            if (current_protocol_id.size() > 0)
            {
                // cout << "THIS >>>> " << current_protocol_id.back() << " :: " << state_array[local_dst_reg].tag.tag_name << endl;
            }

            if (state_array[local_dst_reg].tag.tag_name == "integer_value" or state_array[local_dst_reg].tag.tag_name == "value_from_map" or state_array[local_dst_reg].tag.tag_name == "value_from_helper_function")
            {
                // cout << "Check on Register " << local_dst_reg << " with immediate value " << imm << endl;
            }

            else if (is_tail_offset(state_array[local_dst_reg].tag.protocol, state_array[local_dst_reg].tag.tag_name)) /* is_tail_offset() will return TRUE if the tag is it h_proto/ip_proto etc */
            {
                /*Review: Can we remove the variable "imm_string" and "local_proto_name" */

                string imm_string = to_string(imm); /* Given the immediate value in int, we need to first convert it to string for the getter function */
                string local_proto_name;
                local_proto_name = spec.get_protocol_name(imm_string); /* This function returns the name of the protocol in string */
                // cout << "Check1 for " << local_proto_name << endl;
                JMP_statements_state[instruction_number].tag = NEXT_PROTOCOL_CHECK;
                JMP_statements_state[instruction_number].proto_info = imm;                                     /* I guess this is used to see on which value the check was performed */
                JMP_statements_state[instruction_number].field_info = state_array[local_dst_reg].tag.tag_name; /* Though this value will not be used, but still keeping it for future use*/
            }
            /* Need to write the else case, where the tag of the register is not proto_field, it can be something like
            source_port or the ip_address */
            else if (!(is_tail_offset(state_array[local_dst_reg].tag.protocol, state_array[local_dst_reg].tag.tag_name)))
            {
                /* Example : iph->protocol == IPPROTO_GRE */
                /* Now we have to check if it a normal field or some other Tag like integer */
                /* here, we have to make our own function that takes the tag and says whether it falls in
                garbage_value
                integer,
                ptr_to_ctx,
                ptr_to_packet_start,
                ptr_to_packet_end,
                ptr_to_frame, these values or not ,
                If not then it is a field tag */
                if (!(check_reg_tag(state_array[local_dst_reg].tag.tag_name)))
                {
                    /* That means the tag is definitely a field tag */
                    /* if (source_port == 1234) goto xyz */
                    // cout << "Check on " << state_array[local_dst_reg].tag.tag_name << " with " << imm << " value " << endl;
                    JMP_statements_state[instruction_number].tag = FIELD_CHECK;
                    JMP_statements_state[instruction_number].proto_info = current_protocol_id.back(); // This getter function will convert the id into the name of that protocol
                    JMP_statements_state[instruction_number].field_info = state_array[local_dst_reg].tag.tag_name;
                    /* In context of the above example: proto_info will have TCP and the field_info will have source_port, and
                    we can get the value on which this IF was performed by taking the IMM value of this JMP instruction */
                }
                else
                {
                    /* Here, the tag of the register is one of the fixed tag we have in our code like Integer_value, ptr_to_pkt_start etc*/
                    /* Here, the tag of the JMP instruction will be OTHER_CHECKS */
                    // cout << "Some other check being being performend " << endl;
                    JMP_statements_state[instruction_number].tag = OTHER_CHECKS;
                    JMP_statements_state[instruction_number].field_info = "NULL";
                    JMP_statements_state[instruction_number].proto_info = -1;
                }
            }
            else
            {
                /* Review: Can we remove this ELSE block. */
                // cout << "This case is not yet handled " << endl;
            }
        }

        else if(mode == BPF_JA)
        {
        JMP_statements_state[instruction_number].tag = OTHER_CHECKS;
        JMP_statements_state[instruction_number].field_info = "NULL";
        JMP_statements_state[instruction_number].proto_info = -2;
        }

    }

    /* As the registers are in char format, and we wanted the integer associated to the register, so we use this function*/
    int find_reg(char reg[20])
    {
        int n_reg = atoi(reg);
        // BPF_REG_0

        if (reg[0] == 'A')
        { // If the register is r10, then we handle this case to return 10.
            return 10;
        }
        return n_reg;
    }

    /* This function is used to handle the "ALU and ALU64" instruction */
    void parse_ALU(int mode, char src_reg[20], char dst_reg[20], int imm, int source)
    {
        int local_src_reg = find_reg(src_reg);
        int local_dst_reg = find_reg(dst_reg);

        if (mode == BPF_MOV)
        { /* BPF_MOV : dst = src, now based on the Source(BPF_K or BPF_X) the dst reg can take imm
            value or the value stored in the src register */
            if (source == BPF_K)
            {
                state_array[local_dst_reg].value = imm;
                state_array[local_dst_reg].tag.tag_name = "integer_value";
            }
            else if (source == BPF_X)
            {
                state_array[local_dst_reg].tag = state_array[local_src_reg].tag;
                state_array[local_dst_reg].value = state_array[local_src_reg].value;
            }
        }
        else if (mode == BPF_ADD)
        {
            if (source == BPF_K)
            {
                /* Instruction type : r4 += 4 */
                state_array[local_dst_reg].value += imm;
            }
            else if (source == BPF_X)
            {
                if (state_array[local_src_reg].tag.tag_name == "ptr_to_packet_start")
                {
                    state_array[local_dst_reg].tag = state_array[local_src_reg].tag;
                    state_array[local_dst_reg].value += state_array[local_src_reg].value;
                }
                /* Review: ElseIF and Else blocks can be merged. */
                else if (state_array[local_dst_reg].tag.tag_name == "ptr_to_packet_start")
                {
                    state_array[local_dst_reg].value += state_array[local_src_reg].value;
                }
                else
                {
                    /* Instr type : r4 += r2 */
                    state_array[local_dst_reg].value += state_array[local_src_reg].value;
                    // state_array[local_dst_reg].tag = state_array[local_src_reg].tag;
                    /* The above line was removed coz when the bytecode performs r4+=r2, it only copies the value of the src_reg, and not the tag of the src_reg. The tag of the dst_reg remains intact*/
                }
            }
            /* Review: Remove unnecessary ELSe blocks. */
            else
            {
                // cout << "This is not handled yet :: 1" << endl;
            }
        }
        else
        {
            // cout << "No Action taken" << endl;
        }
    }
    /* This function is used to handle "LD" instructions */
    void parse_LD(char dst_reg[20], char src_reg[20], int size, int off, int imm, int mode, int instruction_number)
    {
        /* We don't want src register as in LOAD operations, register won't be used, It is a
        simple load operation */
        int local_dst_reg = find_reg(dst_reg);

        if (mode == BPF_IMM)
        {
            if (size != BPF_DW)
            {
                /* Date : 18/11/2023 : Not sure what is the usecase of this IF stmt */
                state_array[local_dst_reg].value = imm;
                state_array[local_dst_reg].tag.tag_name = "integer_value";
            }
            else if (size == BPF_DW) /* For, r1 = 0ll kindof instructions*/
            {
                if (local_dst_reg == 1 and imm == 0)
                {
                    /* As per our observation ; If some reference of the map is being passed then it must be passed to register R1 */
                    // cout << "Reference of MAP passed to R : " << local_dst_reg << endl;
                    network_context_per_inst[instruction_number].map_information.name_of_map = "true";
                    /* Need to add the information related to this map reference, but how that I don't know */
                }
                else
                {
                    // cout << "This is not a map reference" << endl;
                    state_array[local_dst_reg].value = imm;
                }
                // cout << "This is a 64bit instruction " << endl;
            }
            else
            {
                // cout << "This is not handled yet" << endl;
            }
        }
    }

    /* This function is used to handle "LDX" instructions */
    void parse_LDX(char dst_reg[20], char src_reg[20], int size, int off, int imm, int mode, int i)
    {
        Specification spec;
        int local_src_reg = find_reg(src_reg);
        int local_dst_reg = find_reg(dst_reg);

        network_context new_context;
        if (mode == BPF_MEM && (state_array[local_src_reg].tag.tag_name != "ptr_to_frame"))
        {
            if ((state_array[local_src_reg].tag.tag_name == "ptr_to_ctx") && (size == BPF_W) && (off == 4))
            {
                state_array[local_dst_reg].tag.tag_name = "ptr_to_packet_end";

                state_array[local_dst_reg].value = 0;
            }
            else if ((state_array[local_src_reg].tag.tag_name == "ptr_to_ctx") && (size == BPF_W) && (off == 0))
            {
                state_array[local_dst_reg].tag.tag_name = "ptr_to_packet_start";
                /* Since packet start was accessed, so as per our assumptions first protocol will be ethernet */
                /* Also, in case of GRE decapsulation, when the GRE header is removed, then data pointers are readjusted and again ethernet is accessed */
                protocol_checks[ETH].first = true_state;
                this_protocol_maybe = ETH;
                state_array[local_dst_reg].value = 0; // Reason to make it 0; when gre header was removed and packet start was accessed, the register contained the some value from previous computations, so we must make it zero so that this new packet can be accessed correctly.
                current_protocol_id.clear();
                /* Here we may have to empty the stack current_protocol_id_stack */
                // cout << "Size of current_protocol_id is after new packet was encountered is : " << current_protocol_id.size() << endl;
            }
            /* This is the newly added logic : Date : 10-11-2023 */
            else if (state_array[local_src_reg].tag.tag_name == "ptr_to_packet_start")
            {
                int total_offset = state_array[local_src_reg].value + off;
                pair<int, int> net_offset = get_relative_offset(total_offset);
                int relative_offset = net_offset.first;


                if (size == BPF_B)
                {
                    /* BPF_B is for size 1 Byte */
                    /* This if stmt will be executed for h_proto, ip_proto, ipv6_proto as there the next_header field is of 1 byte */
                    state_array[local_dst_reg].tag.tag_name = get_header_field_name(net_offset.second, relative_offset);
                    state_array[local_dst_reg].tag.protocol = net_offset.second;
                    if (state_array[local_dst_reg].tag.tag_name.size() > 0)
                    {
                        network_context_per_inst[i].protocol.header_fields_accessed.emplace_back(state_array[local_dst_reg].tag.tag_name);
                    }
                    network_context_per_inst[i].protocol.protocol_name = spec.get_protocol_name(to_string(net_offset.second));
                }
                else if (size == BPF_H or size == BPF_W)
                {
                    /* Size BPF_H = 2 Bytes, BPF_W = 4 Bytes*/
                    /* This else if stmt will be executed for vlan_proto as it's next_header size is 2 bytes */
                    state_array[local_dst_reg].tag.tag_name = get_header_field_name(net_offset.second, relative_offset);
                    state_array[local_dst_reg].tag.protocol = net_offset.second; /* Attaching the header field with it's protocol */
                    if (state_array[local_dst_reg].tag.tag_name.size() > 0)
                    {
                        network_context_per_inst[i].protocol.header_fields_accessed.emplace_back(state_array[local_dst_reg].tag.tag_name);
                    }
                    network_context_per_inst[i].protocol.protocol_name = spec.get_protocol_name(to_string(net_offset.second));
                }
                else
                {
                    // cout << "this size is not yet handled" << endl;
                }
            }
        }
        else if (mode == BPF_MEM && (state_array[local_src_reg].tag.tag_name == "ptr_to_frame"))
        {
            /* type of instr : r1 = *(u32 *)(r10 - 40)     */
            /* Here, I'm not handling the size coz the tag and value at all the index from the offset till the size will be same, so just returning
            the tag and value present at the offset will be enough */
            int index = -1 * off;
            state_array[local_dst_reg].tag = ebpf_memory_stack[index].tag;
            state_array[local_dst_reg].value = ebpf_memory_stack[index].value;
        }
    }
    void parse_STX(char dst_reg[20], char src_reg[20], int size, int off, int imm, int mode, int i)
    {
        /* This function will perform the store operations, and will mostly populate the ebpf_memory */
        int local_src_reg = find_reg(src_reg);
        int local_dst_reg = find_reg(dst_reg);
        if ((mode == BPF_MEM) && (state_array[local_dst_reg].tag.tag_name == "ptr_to_frame"))
        {
            /*  *(u32*)(r10 - 8) = r2 type of instructions   */
            if (size == BPF_W) /* *(u32 *)  */
            {
                /* Review: Use #define for BPF_W size. Eg: # define BPF_W_SIZE 4*/
                int op_size = 4;      /* as the size of BPF_W is 4Bytes */
                int index = -1 * off; /* For making the offset +ve */
                int i = index;
                for (i; i > index - op_size; i--)
                {
                    ebpf_memory_stack[i].tag = state_array[local_src_reg].tag;
                    ebpf_memory_stack[i].value = state_array[local_src_reg].value;
                }
            }
            else if (size == BPF_H)
            {
                /* Review: Use #define for BPF_H size. Eg: # define BPF_H_SIZE 2*/
                int op_size = 2;      /* as the size of BPF_W is 2Bytes */
                int index = -1 * off; /* For making the offset +ve */
                int i = index;
                for (i; i > index - op_size; i--)
                {
                    ebpf_memory_stack[i].tag = state_array[local_src_reg].tag;
                    ebpf_memory_stack[i].value = state_array[local_src_reg].value;
                }
            }
            else if (size == BPF_B)
            {
                /* Review: Use #define for BPF_B size. Eg: # define BPF_B_SIZE 1*/
                int op_size = 1;      /* as the size of BPF_W is 1Bytes */
                int index = -1 * off; /* For making the offset +ve */
                int i = index;
                for (i; i > index - op_size; i--)
                {
                    ebpf_memory_stack[i].tag = state_array[local_src_reg].tag;
                    ebpf_memory_stack[i].value = state_array[local_src_reg].value;
                }
            }
            else if (size == BPF_DW)
            {
                /* Review: Use #define for BPF_DW size. Eg: # define BPF_DW_SIZE 8*/
                int op_size = 8;      /* as the size of BPF_W is 8Bytes */
                int index = -1 * off; /* For making the offset +ve */
                int i = index;
                for (i; i > index - op_size; i--)
                {
                    ebpf_memory_stack[i].tag = state_array[local_src_reg].tag;
                    ebpf_memory_stack[i].value = state_array[local_src_reg].value;
                }
            }
            else
            {
                cout << "Can't handle this STX operation" << endl;
            }
        }
        else if ((mode == BPF_MEM) && (state_array[local_dst_reg].tag.tag_name == "ptr_to_packet_start"))
        {
            /*  *(u32*)(r1 + 8) = r2 type of instructions where the tag of the register is ptr_to_packet_start and something in the packet has been updated */
            int total_offset = state_array[local_dst_reg].value + off;
            pair<int, int> net_offset = get_relative_offset(total_offset);
            int relative_offset = net_offset.first;

            if (size == BPF_B or size == BPF_H or size == BPF_W) /* BPF_B is for size 1 Byte */
            {
                /* This if stmt will be executed for h_proto, ip_proto, ipv6_proto as there the next_header field is of 1 byte */
                string header_name = get_header_field_name(net_offset.second, relative_offset);
                // state_array[local_dst_reg].tag.protocol = net_offset.second;
                if (header_name.size() > 0)
                {
                    // header_fields_updated_info hd;
                    pair<string, string> hd;
                    hd.first = header_name;
                    hd.second = to_string(state_array[local_src_reg].value);
                    network_context_per_inst[i].protocol.header_fields_updated.emplace_back(hd); /* pushed the information of the updated header feild */
                }

                network_context_per_inst[i].protocol.protocol_name = spec.get_protocol_name(to_string(net_offset.second));
            }
            else
            {
                cout << "this size is not yet handled" << endl;
            }
        }
    }

    /* This function has the logic based on which we take decisions and update the states of the registers.
    Based on the class and mode/code for each instruction we call the corresponding function, and that function uses the information
    passed as the arguments,processes it, takes decision and updates the register's states */
    void parse_linebyline(char src_reg[20], char dst_reg[20], int mode, int ins_class, int imm, int off, int size, int source, int instruction_number, int parent)
    {
        /* Here, the mode holds the value of operation for corresponding Instruction class.
        Example, for JMP/JMP32, mode will hold the value we got from BPF_OP(code)
        For LD/ST, mode will hold the value we got from BPF_MODE(code)
        */

        if (ins_class == BPF_JMP || ins_class == BPF_JMP32)
        {
            parse_JMP(mode, src_reg, dst_reg, imm, off, instruction_number, parent); /*Here, inorder to say whether the
             condition is TRUE or FALSE. we need the next instruction*/
        }
        else if (ins_class == BPF_LDX)
        {
            parse_LDX(dst_reg, src_reg, size, off, imm, mode, instruction_number);
        }
        else if (ins_class == BPF_ALU || ins_class == BPF_ALU64)
        {
            parse_ALU(mode, src_reg, dst_reg, imm, source);
        }
        else if (ins_class == BPF_LD)
        {
            parse_LD(dst_reg, src_reg, size, off, imm, mode, instruction_number);
        }
        else if (ins_class == BPF_STX)
        {
            parse_STX(dst_reg, src_reg, size, off, imm, mode, instruction_number);
        }
        else
        {
            // cout << "Non Matching class" << endl;
        }
    }

    /* This function is used to get relevant information from the hexadecimal part of the bytecode,
    like source/dest register, code/mode, class, size, immediate value, offset value */
    void initialize_network_context(parse_inst p)
    {
        for (int i = 0; i < p.inst_count; i++)
        {
            network_context new_context;

            /*
                Review: Why we cannot use "" instead of " "
                Review: Use "emplace_back" instead of "push_back" everywhere.
            */

            new_context.protocol.protocol_name = " ";
            // new_context.protocol.header_fields_updated.emplace_back(" ");
            new_context.protocol.header_fields_accessed.emplace_back("");
            pair<string, string> dummy_tuple(" ", " ");
            // header_fields_updated_info dummy_info;
            pair<string, string> dummy_info;
            dummy_info.first = "";
            dummy_info.second = "";
            new_context.protocol.header_fields_updated.emplace_back(dummy_info);

            new_context.protocol.action_criteria_and_action = dummy_tuple;
            new_context.helper.helper_id = -1;
            new_context.helper.name_of_helper_function = " ";
            new_context.helper.does_packet_manipulation = " ";
            new_context.map_information.name_of_map = " ";
            new_context.map_information.size_of_key = -1;
            new_context.map_information.tag_of_the_key = " ";
            new_context.map_information.size_of_value = -1;
            new_context.map_information.tag_of_the_value = " ";
            network_context_per_inst.push_back(new_context);
        }
    }
    string get_JMP_statements_tags(int tag)
    {
        /* While populating the action_criteria_and_action field, we need to insert the Type of JUMP stmt as string, but since we had the tags of the JMP stmts as ENUM, so this function converts the
        given enum value into the corresponding string */
        if (tag == 0)
            return "SANITY_CHECK";
        else if (tag == 1)
            return "NEXT_PROTOCOL_CHECK";
        else if (tag == 2)
            return "FIELD_CHECK";
        else
            return "OTHER_CHECKS";
    }

    string get_xdp_action(int action)
    {
        /* This function converts the value present in the R0 register into the Action in the string */
        if (action == 0)
            return "XDP_ABORTED";
        else if (action == 1)
            return "XDP_DROP";
        else if (action == 2)
            return "XDP_PASS";
        else if (action == 3)
            return "XDP_TX";
        else if (action == 4)
            return "XDP_REDIRECT";
        else
            return "Undefined action ";
    }

    void get_information(parse_inst p1, int i, int parent)
    {
        /* Here, we will populate the information of the edges */
        edge_information edge_info;
        edge_info.source = parent;
        edge_info.destination = i;

        /* Here, there will be a code that will be taking care of the parent nodes that were JMP statements */
        if (BPF_CLASS(p1.inst_list[parent].code) == BPF_JMP || BPF_CLASS(p1.inst_list[parent].code) == BPF_JMP32)
        {

            /* Logic for this "IF" statement : We have to check if the parent node was "JMP" statement or not. If it was then
            whether the current index that we will be processing is the true branch/false branch of that parent. Because. based on
            the branch we have to update the context of this current instruction */
            string string_tag = get_JMP_statements_tags(JMP_statements_state[parent].tag);
            get<0>(network_context_per_inst[parent].protocol.action_criteria_and_action) = string_tag;

            /* action_criteria specifies the Tag of the Jump Statement */
            edge_info.action_criteria = string_tag;

            /* Review: We can merge the IF sections for BPF_JEQ and BPF_JNE */
            if (BPF_OP(p1.inst_list[parent].code) == BPF_JEQ)
            {
                if (JMP_statements_state[parent].tag == NEXT_PROTOCOL_CHECK)
                {

                    /* So the parent node of the current instruction was Check1 of a protcol*/
                    if (i == parent + 1)
                    {
                        protocol_checks[JMP_statements_state[parent].proto_info].first = false_state;
                        /* In the above line, we made the value of Check1 for the protocol on which the check was performed
                        at the parent node as FALSE */

                        /* Populating the edge information */
                        edge_info.action = "false";
                    }
                    else
                    {
                        protocol_checks[JMP_statements_state[parent].proto_info].first = true_state;
                        this_protocol_maybe = JMP_statements_state[parent].proto_info;

                        /* In the above line, we made the value of Check1 for the protocol on which the check was performed
                        at the parent node as TRUE */

                        /* Populating the edge information */
                        edge_info.action = "true";
                    }
                }
                else if (JMP_statements_state[parent].tag == FIELD_CHECK)
                {
                    /* instruction type : if(source_port == 1234 )*/
                    if (i == parent + 1)
                    {
                        /* Populating the edge information */
                        edge_info.action = "false";
                    }
                    else
                    {
                        edge_info.action = "true";
                    }
                }
                else if (JMP_statements_state[parent].tag == OTHER_CHECKS)
                {
                    /* instruction type : if(r4 == 89 )*/
                    if (i == parent + 1)
                    {
                        /* Populating the edge information */
                        edge_info.action = "false";
                    }
                    else
                    {
                        /* Populating the edge information */
                        edge_info.action = "true";
                    }
                }
            }
            else if (BPF_OP(p1.inst_list[parent].code) == BPF_JNE)
            {
                /* Here, since we are looking <!=> so the logic will be reversed that we used for <==> */
                if (JMP_statements_state[parent].tag == NEXT_PROTOCOL_CHECK)
                {
                    /* So the parent node of the current instruction was Check1 of a protcol*/
                    if (i == parent + 1)
                    {
                        protocol_checks[JMP_statements_state[parent].proto_info].first = true_state;
                        this_protocol_maybe = JMP_statements_state[parent].proto_info;
                        /* In the above line, we made the value of Check1 for the protocol on which the check was performed
                        at the parent node as FALSE */

                        /* Populating the edge information */
                        edge_info.action = "false";
                    }
                    else
                    {
                        protocol_checks[JMP_statements_state[parent].proto_info].first = false_state;
                        /* In the above line, we made the value of Check1 for the protocol on which the check was performed
                        at the parent node as TRUE */

                        /* Populating the edge information */
                        edge_info.action = "true";
                    }
                }
                /* Below conditions are for lines like if source_port != 1234 */
                else if (JMP_statements_state[parent].tag == OTHER_CHECKS)
                {
                    /* instruction type : if(r4 != 89 )*/
                    if (i == parent + 1)
                    {
                        /* Populating the edge information */
                        edge_info.action = "false";
                    }
                    else
                    {
                        /* Populating the edge information */
                        edge_info.action = "true";
                    }
                }
                else if (JMP_statements_state[parent].tag == FIELD_CHECK)
                {
                    /* Dummy instruction : source_port != 1234 */

                    if (i = parent + 1)
                    {
                        /* Populating the edge information */
                        edge_info.action = "false";
                    }
                    else
                    {
                        /* Populating the edge information */
                        edge_info.action = "true";
                    }
                }
            }
            else if (BPF_OP(p1.inst_list[parent].code) == BPF_JGT)
            {
                /* This OP is generally used to SANITY CHECKS */
                /* Need to handle BPF_JLT, eg r3<r4 where r3 and r4 have some tags */

                if (JMP_statements_state[parent].tag == SANITY_CHECK)
                {
                    /* which branch is being operated now, i + 1 and offset wala */
                    /* Here, updation of check2 will take place */
                    if (spec.get_protocol_name(to_string(JMP_statements_state[parent].proto_info)) != "")
                    {
                        if (i == parent + 1)
                        {
                            /* Populating the edge information */
                            edge_info.action = "Sanity check passed ";
                            protocol_checks[JMP_statements_state[parent].proto_info].second = true_state;
                            /* Here, since the Second check has been passed, so we can take decision on which protocol will be accessed */
                            if (protocol_checks[JMP_statements_state[parent].proto_info].first == true_state and protocol_checks[JMP_statements_state[parent].proto_info].second == true_state)
                            { /* if both the checks for a protocol is true, then display the name of the protocol and
                            add that information to the context of this instruction */
                                current_protocol_id.emplace_back(JMP_statements_state[parent].proto_info);
                                network_context_per_inst[i].protocol.protocol_name = spec.get_protocol_name(to_string(JMP_statements_state[parent].proto_info)); /* Added the name of the protocol here */
                                /* Now since the protocol has been accessed, we must make the flags "Null" */
                                /* Scenario were things may go wrong if the flags are not restored, if the second vlan is being accessed, for that both the flags will
                                be in true_state as the first Vlan has already been discussed */
                                protocol_checks[JMP_statements_state[parent].proto_info].first = null_state;
                                protocol_checks[JMP_statements_state[parent].proto_info].second = null_state;
                            }
                        }
                        else
                        {
                            /* REVIEW: Handelling the Sanity check(Check 2) FAIL case */
                            /* Populating the edge information */
                            edge_info.action = "Sanity Check failed ";

                            protocol_checks[JMP_statements_state[parent].proto_info].second = false_state;
                            /* Here, since the check2 fails, so there is no need to check the status of the Check1 */
                        }
                    }
                    else
                    {
                        edge_info.action = "Sanity Check but details of this is not present";
                    }
                }
            }
        }
        /* Pushing the edge information in the vector */
        edge_context.emplace_back(edge_info);

        /*Review: We can use character, Why char array of size 20.*/
        char hex_src_reg[20], hex_dst_reg[20], hex_op[20], hex_code[20], hex_mode[20], hex_class[20], hex_size[20], hex_imm[20], hex_off[20];
        /* Information about the above variables :
        hex_op : is used to get the Operations to be performed in JMP and ALU class
        hex_mode : is used to get the functionality of the LD/ST operations
        hex_class : is used to get the class
        hex_code : Operation for Arithe and JMP instruction class
        */

        sprintf(hex_src_reg, "%X", p1.inst_list[i].src_reg);
        sprintf(hex_dst_reg, "%X", p1.inst_list[i].dst_reg);
        // // cout << i << "th instruction" << endl;
        instr_no = i;

        /*
         * This section extracts information from the LOAD(BPF_LD and BPF_LDX)
         * and STORE(BPF_ST and BPF_STX) class of instructions.
         */

        if (BPF_CLASS(p1.inst_list[i].code) == BPF_LD || BPF_CLASS(p1.inst_list[i].code) == BPF_LDX || BPF_CLASS(p1.inst_list[i].code) == BPF_ST || BPF_CLASS(p1.inst_list[i].code) == BPF_STX)
        {
            sprintf(hex_mode, "%X", BPF_MODE(p1.inst_list[i].code));
            // sprintf(hex_class, "%X", BPF_CLASS(p1.inst_list[i].code));
            sprintf(hex_size, "%X", BPF_SIZE(p1.inst_list[i].code));

            int imm = p1.inst_list[i].imm;
            int off = p1.inst_list[i].off;
            int ins_class = BPF_CLASS(p1.inst_list[i].code);
            int mode = BPF_MODE(p1.inst_list[i].code);
            int size = BPF_SIZE(p1.inst_list[i].code);
            int source = -1; /* For Load/Store insts, source is not needed, and here Source is not
           the source register, this source is used in ALU class. Since we have a variable in parse_linebyine so we need
           to pass value to that argument */
            parse_linebyline(hex_src_reg, hex_dst_reg, mode, ins_class, imm, off, size, source, i, parent);
        }
        /*
         * This section extracts information from instructions other than LOAD
         * and STORE class of instructions, that is, BPF_JMP, BPF_JMP32, BPF_ALU, BPF_ALU64(Jump and Arithmetic instructions)
         */

        else if (BPF_CLASS(p1.inst_list[i].code) == BPF_JMP || BPF_CLASS(p1.inst_list[i].code) == BPF_JMP32) // tobi
        {
            /* If the class is JMP or JMP32 then the OPs should be handled differently */
            /* OPs can be BPF_EXIT, BPF_JEQ, BPF_JNE, BPF_JGT etc */
            sprintf(hex_op, "%X", BPF_OP(p1.inst_list[i].code));
            sprintf(hex_class, "%X", BPF_CLASS(p1.inst_list[i].code));
            sprintf(hex_size, "%X", BPF_SIZE(p1.inst_list[i].code));
            int src_reg = p1.inst_list[i].src_reg;
            int dst_reg = p1.inst_list[i].dst_reg;
            int imm = p1.inst_list[i].imm;
            int off = p1.inst_list[i].off;
            int source = -1; /* For JMP instr, source is not needed, and here Source is not
            the source register, this source is used in ALU class. Since we have a variable in parse_linebyine so we need
            to pass value to that argument */
            int ins_class = BPF_CLASS(p1.inst_list[i].code);
            int op = BPF_OP(p1.inst_list[i].code); /* Here, op can have BPF_JA, BPF_JEQ kindof values */
            int size = BPF_SIZE(p1.inst_list[i].code);
            parse_linebyline(hex_src_reg, hex_dst_reg, op, ins_class, imm, off, size, source, i, parent);
        }
        else if (BPF_CLASS(p1.inst_list[i].code) == BPF_ALU || BPF_CLASS(p1.inst_list[i].code) == BPF_ALU64)
        {
            sprintf(hex_op, "%X", BPF_OP(p1.inst_list[i].code));
            sprintf(hex_class, "%X", BPF_CLASS(p1.inst_list[i].code));
            sprintf(hex_size, "%X", BPF_SIZE(p1.inst_list[i].code));
            int src_reg = p1.inst_list[i].src_reg;
            int dst_reg = p1.inst_list[i].dst_reg;
            int imm = p1.inst_list[i].imm;
            int off = p1.inst_list[i].off;
            int source = BPF_SRC(p1.inst_list[i].code); /* Here,source doen't mean that it is source register, Source
            determines that whether we need to take value from the immediate part of the instr, or from the src register */
            int ins_class = BPF_CLASS(p1.inst_list[i].code);
            int op = BPF_OP(p1.inst_list[i].code); /* Here, op can have BPF_ADD, BPF_SUB, BPF_AND kindof values */
            int size = BPF_SIZE(p1.inst_list[i].code);
            parse_linebyline(hex_src_reg, hex_dst_reg, op, ins_class, imm, off, size, source, i, parent);
        }
        else
        {

            /*Review: Better to have scenario for this Else block.*/

            sprintf(hex_mode, "%X", BPF_MODE(p1.inst_list[i].code));
            sprintf(hex_class, "%X", BPF_CLASS(p1.inst_list[i].code));
            sprintf(hex_size, "%X", BPF_SIZE(p1.inst_list[i].code));
            int src_reg = p1.inst_list[i].src_reg;
            int dst_reg = p1.inst_list[i].dst_reg;
            int imm = p1.inst_list[i].imm;
            int off = p1.inst_list[i].off;
            int source = -1;
            int ins_class = BPF_CLASS(p1.inst_list[i].code);
            int mode = BPF_MODE(p1.inst_list[i].code); /* BPF_MODE is something that should be used with Load and Store operations, with JMP and ALU we have to use BPF_OP */
            int size = BPF_SIZE(p1.inst_list[i].code);
            parse_linebyline(hex_src_reg, hex_dst_reg, mode, ins_class, imm, off, size, source, i, parent);
        }
    }
};

class get_next_instruction
{
public:
    /* Here, instead of taking the index, we can also take the whole bytcode and the index as well
    This IF stmt handles the JMP instructions that are not EXIT stmt and not unconditional jumps
    Is also returns the parent node of the next instruction to be processed */
    pair<int, int> next_instruction(parse_inst p, int index)
    {
        /* Here, instead of taking the index, we can also take the whole bytcode and the index as well*/
        /* This IF stmt handles the JMP instructions that are not EXIT stmt and not unconditional jumps */
        /* Is also returns the parent node of the next instruction to be processed */
        int parent_index;
        if (((BPF_CLASS(p.inst_list[index].code) == BPF_JMP) or (BPF_CLASS(p.inst_list[index].code) == BPF_JMP32)) and ((BPF_OP(p.inst_list[index].code) != BPF_EXIT) and (BPF_OP(p.inst_list[index].code) != BPF_JA) and (BPF_OP(p.inst_list[index].code) != BPF_CALL)))
        {
            // cout << "This is a JMP statement at index : " << index << endl;
            /* write a logic to push the line number and the register states comehere*/
            stack_jump_instruction.push(index);                  // pushed the current JMP instr
            register_state_stack.push(state_array);              // pushed the current register states
            current_protocol_id_stack.push(current_protocol_id); /* All the protocols accessed till now are pushed */
            this_protocol_maybe_stack.push(this_protocol_maybe); /* current_protocol whose check1 was passed is pushed */
            // adjust_head_flag_stack.push(adjust_head_flag);  /* To keep the track of adjust_head flag, more detail example has been given where this stack has been defined */
            protocol_checks_stack.push(protocol_checks); /* Need to keep track of the status of all the check 1 and check 2 */

            return make_pair(index + p.inst_list[index].off + 1, index); // This is when the condition will be TRUE
        }
        // else if (((p.inst_list[index].code == BPF_JMP or p.inst_list[index].code == BPF_JMP32)) and (BPF_OP(p.inst_list[index].code) == BPF_JA))
        else if (((BPF_CLASS(p.inst_list[index].code) == BPF_JMP) or ((BPF_CLASS(p.inst_list[index].code) == BPF_JMP32))) and (BPF_OP(p.inst_list[index].code) == BPF_JA))
        {
            /* This is an Unconditional jump */
            return make_pair(index + p.inst_list[index].off + 1, index);
        }
        else if (((BPF_CLASS(p.inst_list[index].code) == BPF_JMP) or ((BPF_CLASS(p.inst_list[index].code) == BPF_JMP32))) and (BPF_OP(p.inst_list[index].code) == BPF_CALL))
        {
            // cout << "This is a call instruction" << endl;
            return make_pair(index + 1, index);
        }
        else if (((BPF_CLASS(p.inst_list[index].code) == BPF_JMP or BPF_CLASS(p.inst_list[index].code) == BPF_JMP32)) and (BPF_OP(p.inst_list[index].code) == BPF_EXIT))
        {
            // cout << "This is an EXIT statement " << endl;

            /* Now if the stack is empty when EXIT stmt is hit, then all the edges have been touched */
            if (stack_jump_instruction.empty())
            {
                // cout << "All instructions touched" << endl;
                exit_condition = true;
                // cout << "made exit_condition True" << endl;
                return make_pair(-1, index); /* Here, index will be the last parent instruction of EXIT statement */
            }
            /* If the stack is non-empty then one of the branch of some JUMP instr. was being processed */
            else
            {
                /* We will pop the current jump inst. and add 1 to it to get the next inst to process */
                // cout << "All instrs not touched " << endl;
                int next_index = stack_jump_instruction.top();
                stack_jump_instruction.pop();

                /* Restoring the register states */
                vector<reg_state> restore_state_array(11);
                restore_state_array = register_state_stack.top();
                register_state_stack.pop();
                state_array = restore_state_array;

                /* Restoring the current_protocol_id that were accessed */
                vector<int> dummy_current_protocol_id = current_protocol_id_stack.top();
                current_protocol_id_stack.pop();
                current_protocol_id = dummy_current_protocol_id;

                /* Restoring the this_protocol_maybe value */
                int dummy_this_protocol_maybe = this_protocol_maybe_stack.top();
                this_protocol_maybe_stack.pop();
                this_protocol_maybe = dummy_this_protocol_maybe;

                /* Restoring the protocol_checks map */
                map<int, pair<bool, bool>> dummy_protocol_checks = protocol_checks_stack.top();
                protocol_checks_stack.pop();
                protocol_checks = dummy_protocol_checks;

                return make_pair(next_index + 1, next_index);
            }
        }
        else
        {
            /* This "else" snippet should handle all Non-JUMP instructions */
            return make_pair(index + 1, index);
        }
    }
};

int parse_main(const char *filename, string selected_prog_name, string selected_prog_func_name, vector<bpf_insn> *inst_list_ptr, vector<network_context> *network_context_ptr)
{

    // Specification spec;  // Removed as part of Review: Not in use
    this_protocol_maybe = ETH;               /* As per our assumption, ETH will be there, the current_protocol_id will updated when the
                                                Check2 for ETH will be passed */
    protocol_checks[ETH].first = true_state; /* As per our assumptions, Check1 of the Ethernet will be passed */

    state_array[0].tag.tag_name = "integer_value";
    state_array[0].value = garbage_value;
    state_array[10].tag.tag_name = "ptr_to_frame";
    state_array[10].value = garbage_value;
    state_array[1].tag.tag_name = "ptr_to_ctx";
    state_array[1].value = garbage_value;

    for (int o = 2; o < 10; o++)
    {
        state_array[o].tag.tag_name = "NULL";
    }
    for (int imp = 0; imp < 10; imp++)
        state_array[imp].tag.protocol = -2; /*Reason to keep default value as "-2" is because, "-1" is for ethernet in spec and we're not taking 0, just to use it in future. */

    parse_inst p1(filename, selected_prog_func_name.c_str());
    flow_prop fp;
    fp.initialize_network_context(p1); /* Using this function, the size of the network_context vector is intialized to the total_number_of_instructions present in the bytecode */
    get_next_instruction get_next_inst;

    pair<int, int> index; /* This pair has first element as Current node, and second element as Parent node */
    index.first = 0;      // current node
    index.second = 0;     // parent node

    /* The CORE part of Static Analysis (Register Tagging Algorithm.) */
    while (!exit_condition)
    {
        fp.get_information(p1, index.first, index.second);
        index = get_next_inst.next_instruction(p1, index.first);
    }


    vector<network_context> network_context = fp.get_network_context_per_inst();

    /* Populating the Map related details*/
    Map_context map_info;
    vector<string> maps_used = map_info.get_map_access_sequence(filename, ".rel" + selected_prog_name);

    if (maps_used.size() == 0)
    {
        // cout << "No map is there in the code " << endl;
    }
    else
    {
        int num_of_maps = 0;
        for (auto it : maps_used)
        {
            num_of_maps++;
        }
    }

    vector<bpf_insn> inst_list = p1.get_inst_list();
    int maps_in_obj = 0;
    int map_index = 0;
    for (int i = 0; i < network_context.size(); i++)
    {
        if (network_context[i].map_information.name_of_map == "true")
        {
            if (maps_used[map_index].size() > 0 and map_index < maps_used.size())
            {
                network_context[i].map_information.name_of_map = maps_used[map_index];
            }
            else
            {
                network_context[i].map_information.name_of_map = "";
            }
            map_index++;
            maps_in_obj++;
        }
    }

    *inst_list_ptr = inst_list;
    *network_context_ptr = network_context;

    return 0;
}
