#include <iostream>
#include <vector>
#include <map>
#include <bpf/libbpf.h>
#include "elfio/elfio.hpp"

using namespace std;
using namespace ELFIO;

class Map_context
{
private:
    struct map_information
    {
        string name;
        int key_size;
        int value_size;
        string map_type;
        int max_entries;
    };
    map<string, struct map_information> map_definitions;

public:
    map<string, struct map_information> get_map_definitions(bpf_object *obj)
    {
        /*
        Input: bpf_object
        Output: map<string, struct map_info>
        */

        bpf_map *map_ptr;
        bpf_object__for_each_map(map_ptr, obj)
        {
            struct map_information map_context;
            map_context.name = bpf_map__name(map_ptr);
            map_context.key_size = bpf_map__key_size(map_ptr);
            map_context.value_size = bpf_map__value_size(map_ptr);
            map_context.map_type = libbpf_bpf_map_type_str(bpf_map__type(map_ptr));
            map_context.max_entries = bpf_map__max_entries(map_ptr);

            map_definitions.insert({map_context.name, map_context});
        }
        return map_definitions;
    }

    vector<string> get_map_access_sequence(string object_file, string section_name)
    {
        vector<string> map_access_sequence;
        ELFIO::elfio reader;
        // Load ELF data
        if (!reader.load(object_file))
        {
            std::cout << "Can't find or process ELF file " << object_file << std::endl;
        }

        /* reader.sections[section_name] give '0' if their is no section for map. This means their are no maps in the bytecode.*/
        if (reader.sections[section_name] != 0)
        {
            const ELFIO::relocation_section_accessor relsec(reader, reader.sections[section_name]);
            int relo_count = relsec.get_entries_num();

            for (int i = 0; i < relo_count; ++i)
            {
                ELFIO::Elf64_Addr offset;
                ELFIO::Elf_Word symbol;
                ELFIO::Elf64_Addr symbolValue;
                std::string symbolName;
                ELFIO::Elf_Word type;
                ELFIO::Elf_Sxword addend;
                ELFIO::Elf_Sxword calcValue;
                relsec.get_entry(i, offset, symbolValue, symbolName, type, addend, calcValue);

                // if (symbolName != ".rodata" && symbolName != "")
                // {
                map_access_sequence.push_back(symbolName);
                // }
                /*Commented because at bytecode level difficult to differentiate between Actual map access and Printk() helper call...!!!*/
            }
        }
        else
        {
            return map_access_sequence;
        }

        

        
        return map_access_sequence;
    }
};