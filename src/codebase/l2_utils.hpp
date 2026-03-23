#include "spec.hpp"
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <bits/stdc++.h>
#include <sstream>

namespace spec
{
    Specification spec;
}

// Specific implementation to handle ETHERNET protocol ID
std::string get_header_field_name(long protocol_id, unsigned int offset_number)
{

    std::string _protocol_id = std::to_string(protocol_id);

    std::map<std::string, my_struct> field_offsets = spec::spec.get_field_offsets(_protocol_id);
    unsigned int header_size_bytes;

    if (spec::spec.get_header_size_bytes(_protocol_id).size() > 0)
    {
        header_size_bytes = stoi(spec::spec.get_header_size_bytes(_protocol_id));
    }
    if (offset_number >= header_size_bytes)
    {
        // std::cout << "Offset number " << offset_number << " not found in protocol ID " << protocol_id << std::endl;
        return "";
    }

    // Convert map keys to integer vector
    std::vector<long> keys;
    for (auto x : field_offsets)
    {
        keys.push_back(stoi(x.first));
    }

    // Sort the keys in ascending order
    std::sort(keys.begin(), keys.end());

    // Find the nearest previous offset to the given offset number
    unsigned int nearest_previous_offset = 0;
    for (auto x : keys)
    {
        if (x <= offset_number)
        {
            nearest_previous_offset = x;
        }
    }

    return field_offsets[std::to_string(nearest_previous_offset)].string_data;
}

// Specific implementation to handle ETHERNET protocol ID
bool is_tail_offset(long protocol_id, std::string field_name)
{

    std::string _protocol_id = std::to_string(protocol_id);

    std::map<std::string, my_struct> field_offsets = spec::spec.get_field_offsets(_protocol_id);
    std::string _tail_offset = spec::spec.get_tail_offset(_protocol_id);
    std::replace(_tail_offset.begin(), _tail_offset.end(), '_', '-');

    int tail_offset;
    if (_tail_offset.size() > 0)
    {
        tail_offset = stoi(_tail_offset);
    }
    else
    {
        tail_offset = -1;
        // Need to assigng some valid value for "tail_offset"
    }

    // // std::cout << "HEREEEEEE:" << spec::spec.get_header_size_bytes(_protocol_id) << ".\n";

    // int header_size_bytes = stoi(spec::spec.get_header_size_bytes(_protocol_id)); // This line of code is not required.
    long offset_number = -1;
    for (auto x : field_offsets)
    {
        if (x.second.string_data == field_name)
        {
            offset_number = stol(x.first);
        }
    }

    if (offset_number == -1)
    {
        // std::cout << "Field name " << field_name << " not found in protocol ID " << protocol_id << std::endl;
        return false;
    }
    else if (offset_number == tail_offset)
    {
        // std::cout << "Field name " << field_name << " is the tail offset in protocol ID " << protocol_id << std::endl;
        return true;
    }
    else
    {
        // std::cout << "Field name " << field_name << " is not tail offset in protocol ID " << protocol_id << std::endl;
        return false;
    }
}

std::string exec(const char *cmd)
{
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe)
        return "ERROR";
    char buffer[128];
    std::string result = "";
    while (!feof(pipe.get()))
    {
        if (fgets(buffer, 128, pipe.get()) != NULL)
            result += buffer;
    }
    return result;
}

// Extract map information by loading the program using the bpftool shell commands
std::string load_program(std::string program_name)
{
    std::string object_fs_name = program_name;
    std::replace(object_fs_name.begin(), object_fs_name.end(), '.', '_');

    std::string command = "sudo bpftool prog load " + program_name + " /sys/fs/" + object_fs_name;
    std::string return_string = exec(command.c_str());

    return return_string;
}

std::string unload_program(std::string program_name)
{

    std::replace(program_name.begin(), program_name.end(), '.', '_');
    std::string command = "sudo rm /sys/fs/" + program_name;

    std::string return_string = exec(command.c_str());

    return return_string;
}

std::string get_prog_info()
{
    std::string command = "sudo bpftool prog show";

    std::string return_string = exec(command.c_str());
    return return_string;
}

std::string get_map_info()
{
    std::string command = "sudo bpftool map show";

    std::string return_string = exec(command.c_str());
    return return_string;
}

std::string get_verified_bytecode(std::string program_id)
{
    std::string command = "sudo bpftool prog dump xlated id " + program_id;

    std::string return_string = exec(command.c_str());
    return return_string;
}

std::string extract_prog_id(std::string program_name, std::string diff_prog_info)
{
    std::string program_id = diff_prog_info.substr(0, diff_prog_info.find(":"));
    return program_id;
}

std::map<std::string, std::string> extract_prog_info_bpftool(std::string program_name)
{
    std::map<std::string, std::string> prog_info;
    std::string return_string;

    std::string prior_prog_info = get_prog_info();
    std::string prior_map_info = get_map_info();

    return_string = load_program(program_name);

    std::string post_prog_info = get_prog_info();
    std::string post_map_info = get_map_info();

    return_string = unload_program(program_name);

    std::string diff_prog_info = post_prog_info.substr(prior_prog_info.length());
    std::string diff_map_info = post_map_info.substr(prior_map_info.length());

    std::string program_id = extract_prog_id(program_name, diff_prog_info);

    std::string verified_bytecode = get_verified_bytecode(program_id);

    prog_info["diff_prog_info"] = diff_prog_info;
    prog_info["diff_map_info"] = diff_map_info;
    prog_info["verified_bytecode"] = verified_bytecode;

    return prog_info;
}

std::map<int, std::map<std::string, std::string>> extract_map_info_bpftool(std::string program_name, std::string diff_prog_info, std::string diff_map_info)
{

    if (diff_prog_info.find("map_ids ") == std::string::npos)
    {
        // std::cout << "No map IDs found in diff_prog_info" << std::endl;
        return std::map<int, std::map<std::string, std::string>>();
    }

    std::string map_ids = diff_prog_info.substr(diff_prog_info.find("map_ids ") + 8);
    map_ids = map_ids.substr(0, map_ids.find("\n"));

    std::vector<int> map_ids_vector;
    std::stringstream ss(map_ids);
    std::string item;

    while (std::getline(ss, item, ','))
    {
        map_ids_vector.push_back(std::stoi(item));
    }

    std::sort(map_ids_vector.begin(), map_ids_vector.end());

    std::map<int, std::pair<int, int>> map_id_to_indices;

    for (auto i = 0; i < map_ids_vector.size(); i++)
    {
        int index = diff_map_info.find(std::to_string(map_ids_vector[i]));
        if (index == std::string::npos)
        {
            map_id_to_indices[i].first = -1;
            map_id_to_indices[i].second = -1;
            continue;
        }

        map_id_to_indices[i].first = index;

        if (i > 0)
        {
            map_id_to_indices[i - 1].second = index - 1;
        }

        if (i == map_ids_vector.size() - 1)
        {
            map_id_to_indices[i].second = diff_map_info.length() - 1;
        }
    }

    for (auto x : map_id_to_indices)
    {
        // std::cout << "Map ID " << map_ids_vector[x.first] << " found in diff_map_info at index " << x.second.first << " to " << x.second.second << std::endl;
    }

    std::map<int, std::map<std::string, std::string>> map_information;

    for (auto map : map_id_to_indices)
    {
        std::string map_info = diff_map_info.substr(map.second.first, map.second.second - map.second.first + 1);

        std::string map_name = map_info.substr(map_info.find("name ") + 5);
        map_name = map_name.substr(0, map_name.find(" "));

        std::string key_size = map_info.substr(map_info.find("key") + 4);
        key_size = key_size.substr(0, key_size.find(" "));

        std::string value_size = map_info.substr(map_info.find("value") + 6);
        value_size = value_size.substr(0, value_size.find(" "));

        map_information[map_ids_vector[map.first]]["name"] = map_name;
        map_information[map_ids_vector[map.first]]["key_size"] = key_size;
        map_information[map_ids_vector[map.first]]["value_size"] = value_size;
    }

    return map_information;
}

std::vector<std::string> extract_map_sequence(std::string program_name, std::string verified_bytecode)
{

    std::vector<std::string> map_sequence;

    int index = verified_bytecode.find("map[id:", 0);

    if (index == std::string::npos)
    {
        // std::cout << "No map IDs found in verified_bytecode" << std::endl;
        return map_sequence;
    }

    while (index != std::string::npos)
    {
        std::string map_id = verified_bytecode.substr(index + 7);
        map_id = map_id.substr(0, map_id.find("]"));

        map_sequence.push_back(map_id);

        index = verified_bytecode.find("map[id:", index + 1);
    }

    for (auto x : map_sequence)
    {
        // std::cout << x << std::endl;
    }

    return map_sequence;
}
