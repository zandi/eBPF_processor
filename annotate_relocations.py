# IDA Python script to annotate all references to maps
# with a comment of the map name.
#
# requires pyelftools, since that does all the ELF parsing for us
#
# Also requires the eBPF ELF file to examine directly

# general strategy: parse ELF to determine relocation info & locations,
# replicate how IDA maps sections to addresses, use this replicated
# loading/addressing to add drefs (ida_xref.add_dref) from each
# relocated location (an instruction) to a defined map.
#
# Then, add repeatable comments on each defined map. This should at least
# cause those repeatable comments to appear alongside instructions which
# have relocations applied to them for those particular maps

from idaapi import *
import ida_xref
import ida_nalt

# just copied these, may not need them
import idautils
import idc

# elftools are required
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection, StringTableSection
from elftools.elf.enums import ENUM_SH_TYPE_BASE

def get_symtab_strtab(elffile):
    symtab = None
    strtab = None
    for s in elffile.iter_sections():
        if isinstance(s, SymbolTableSection):
            symtab = s
        elif isinstance(s, StringTableSection):
            strtab = s
    return (symtab, strtab)

# find all map sections, returning id/name tuples
# we've seem maps sections named ".maps", "maps", and "maps/[name]"
# ".maps" contains multiple maps, "maps" likely does as well, "maps/[name]" may be individual maps
def get_map_sections(elffile):
    i = 0
    map_sections = []
    for s in elffile.iter_sections():
        if s.name.startswith(".maps") \
            or s.name.startswith("maps/") \
            or s.name.startswith("maps"):
                map_sections.append((i, s.name))
        i+=1
    return map_sections

# determine which symbols refer to maps, return an array of them
def get_maps(elffile):
    maps = []
    (symtab, strtab) = get_symtab_strtab(elffile)
    map_sections = get_map_sections(elffile)

    map_section_ids = [s[0] for s in map_sections]
    for sym in symtab.iter_symbols():
        # check if the symbol is in a map section
        if sym['st_shndx'] in map_section_ids:
            maps.append(sym)
    return maps

# constants in libbpf-bootstrap binaries have GLOBAL binding and OBJECT type, and a section index pointing to the resident section (.bss/.rodata).
# ebpfkit's constants (http_server_port, ebpfkit_pid) are different, with NOTYPE type and no certainly defined resident section
# IDA appears to treat these like extern symbols, since they're referenced in the symbol table & relocations, but aren't given a section to reside in
# name: 4228 -> ebpfkit_pid, info: Container({'bind': 'STB_GLOBAL', 'type': 'STT_NOTYPE'}), value:      0x0, size:      0x0, resident section: SHN_UNDEF
def get_possible_globals(elffile):
    (symtab, strtab) = get_symtab_strtab(elffile)

    maps = get_maps(elffile)
    map_names = [s.name for s in maps]

    possible_globals = []

    for s in symtab.iter_symbols():
        if s['st_info']['bind'] == 'STB_GLOBAL' and (s['st_info']['type'] == 'STT_OBJECT' or s['st_info']['type'] == 'STT_NOTYPE'):
            if s.name != 'LICENSE' and s.name not in map_names:
                # guess: want global binding, type of 'object'
                possible_globals.append(s)

    return possible_globals

# get program sections and their associated address ranges
# This will make dealing with relocations easier, since we
# can match a relocation section to its program section, and
# have the 'loaded' address range for the section to determine
# the full address of the bytes which are to be relocated,
# based on the offset within the section
#
# for convention, tuples are (section, base_address, end_address)
# where the address range is [base_address, end_address)
#
# We do our best to replicate how IDA maps these sections
# into memory, and it seems to be correct, but this may be
# fragile. Future fix is to do this in the loader, where we'll
# also control how sections are mapped into memory
def get_program_sections_with_address_ranges(elffile):
    i=0
    program_sections = []
    (symtab, strtab) = get_symtab_strtab(elffile)
    cur_addr = 0
    for s in elffile.iter_sections():
        if s['sh_type'] == 'SHT_PROGBITS' or s['sh_type'] == 'SHT_NOBITS':
            # let's try our hand at 'mapping' sections into memory similar to how IDA does.
            # it seems to just be linear starting at 0, and up to alignment
            # Also, no overlapping sections; if .text is 0-length, the next section doesn't start at 0 as well
            # This algorithm seems to match IDA, though IDA additionally creates an 'extern' section
            # note: PROGBITS have bits to be loaded in. NOBITS don't have bits, the loader supplies 0 bytes.
            section_name = strtab.get_string(s['sh_name'])
            if section_name.startswith(".BTF"):
                continue # skip BTF map; IDA doesn't map it

            if s['sh_addr'] != 0:
                print("WARNING: non-zero address in section, this interferes with our loading assumptions")

            if cur_addr % s['sh_addralign']:
                cur_addr += (s['sh_addralign'] - (cur_addr % s['sh_addralign']))

            program_sections.append((s, cur_addr, cur_addr + s['sh_size']))

            # gross hack so the next section can't overlap us, and will likely be fixed up for alignment reasons
            if s['sh_size'] == 0:
                cur_addr += 1

            cur_addr += s['sh_size']
        i+=1
    return program_sections

# print sections containing programs (ideally they'll also have relocations)
# note: they don't seem to have an address, it seems like IDA assumes that PROGBITS sections
# (that have the alloc flag?) are allocated linearly based on alignment (often 8; width of nearly all eBPF instructions)
def print_program_sections(elffile):

    (symtab, strtab) = get_symtab_strtab(elffile)
    program_sections = get_program_sections_with_address_ranges(elffile)

    for (s, base_addr, end_addr) in program_sections:
        section_name = strtab.get_string(s['sh_name'])
        print(f"\t[{base_addr:#8x}, {end_addr:#8x}): align {s['sh_addralign']:#8x} size {s['sh_size']:#8x} {section_name}")

# Process map and global relocations.
# Maps have a repeatable comment put on their definition, and a dref added to the relocation area
# Globals are processed the same if their definition resides in another section.
# If not, they're an extern symbol, and we just comment each individual without a xref.
# This is a lazy hack because the IDA loader creates and extern section for these symbols, and I
# just don't feel like replicating that addressing for adding those drefs right now
def process_relocations(elffile):
    # first, get symbol/string tables, we'll use them a lot
    # next, collect info on which symbols are maps
    #  copy the whole symbol object, build other metadata/lookup objects
    # next, collect info on symbols which may be globals
    # next, collect info on address ranges for program sections
    #  need section's name, and correlated address range. Other info currently irrelevant (align, etc.)
    #  name to match relocation sections to the program section they apply to, and address for offset + address calculation
    # next, iterate through relocation sections for each program section
    #  combine info on relocation's offset in its section, with the symbol relocation, to print address of map relocations
    #  Additionally if a relocation is for a global, add a dref or comment as appropriate

    # get symbol & string tables
    (symtab, strtab) = get_symtab_strtab(elffile)

    # get possible global symbols
    possible_globals = get_possible_globals(elffile)
    possible_global_names = [s.name for s in possible_globals]

    # get symbols which are maps
    maps = get_maps(elffile)
    map_sections = get_map_sections(elffile)
    map_section_ids = [s[0] for s in map_sections]

    # get program section info
    program_sections = get_program_sections_with_address_ranges(elffile)
    program_section_names = [s[0].name for s in program_sections]
    program_sections_by_name = {s[0].name: s for s in program_sections}

    # determine address for map definitions
    map_location_by_name = {}
    for sym in maps:
        sec = elffile.get_section(sym['st_shndx'])
        (_, begin_addr, _) = program_sections_by_name[sec.name]
        print(f"{begin_addr + sym['st_value']:#8x}: map '{sym.name}'")
        map_location_by_name[sym.name] = begin_addr + sym['st_value']
        idc.set_cmt(map_location_by_name[sym.name], f"map {sym.name}", True)

    # determine address for global definitions, if they exist
    global_location_by_name = {}
    for sym in possible_globals:
        if sym['st_shndx'] != 'SHN_UNDEF':
            # definition exists in this binary. Easy case, use repeatable comment
            sec = elffile.get_section(sym['st_shndx'])
            (_, begin_addr, _) = program_sections_by_name[sec.name]
            def_location = begin_addr + sym['st_value']
            print(f"global definition location: {def_location:#8x}")
            global_location_by_name[sym.name] = def_location
            idc.set_cmt(def_location, f"{sym.name} (possible global)", True)
    del(sym) # got bit by an annoying silly bug

    # get each program section's corresponding relocation section (if it exists)
    # and process the relocations, looking only for map or global relocations
    i = 0
    for section in elffile.iter_sections():
        if isinstance(section, RelocationSection):
            if ".BTF" in section.name:
                # skip BTF related things for now, deal with that can of worms later
                break

            # relocation sections are named ".rel[section]" where [section] is the section name
            # they contain relocations for
            relocated_section_name = section.name[4:]
            if not relocated_section_name in program_section_names:
                # only do program sections, our probes live there
                break

            print(f"{i}: {section.name} at {section['sh_offset']:#8x} has {section.num_relocations()} relocations for {relocated_section_name}")
            for r in section.iter_relocations():
                if not r.is_RELA(): # haven't seen any RELA yet
                    symbol = symtab.get_symbol(r['r_info_sym'])
                    if symbol:
                        resident_section_ndx = symbol['st_shndx']
                        if resident_section_ndx in map_section_ids:
                            # found a map relocation
                            resident_section = elffile.get_section(resident_section_ndx)
                            # get base address of relocated section, apply relocation offset
                            (s, begin_addr, end_addr) = program_sections_by_name[relocated_section_name]
                            relocated_address = begin_addr + r['r_offset'] # note: subject to relocation type, may be calculated differently
                            print(f"\tmap relocation at {relocated_address:#8x}: {symbol.name} -> {map_location_by_name[symbol.name]:#8x}")
                            ida_xref.add_dref(relocated_address, map_location_by_name[symbol.name], ida_xref.dr_R)
                        elif symbol.name in possible_global_names:
                            # found possible global relocation
                            (s, begin_addr, end_addr) = program_sections_by_name[relocated_section_name]
                            relocated_address = begin_addr + r['r_offset'] # note: subject to relocation type, may be calculated differently
                            print(f"\tpossible global relocation {relocated_address:#8x} -> {symbol.name}")
                            # if there is a resident section, add dref and count on the repeated comment. If no section, extern, directly comment
                            if symbol['st_shndx'] == 'SHN_UNDEF':
                                # extern, just comment location
                                idc.set_cmt(relocated_address, f"{symbol.name} (possible global)", False)
                            else:
                                # have a resident section, add data xref to link
                                ida_xref.add_dref(relocated_address, global_location_by_name[symbol.name], ida_xref.dr_R)
                    else:
                        print(f"ERROR: relocation has no symbol?")
                else:
                    print("ERROR: RELA type relocation unsupported; only REL supported")
        i+=1
    pass

def process_file(elf_filename):
    with open(elf_filename, 'rb') as f:
        elffile = ELFFile(f)

        # just printing info
        print("PROGBITS Sections with our assumed mapping")
        print("  If this differs from how IDA maps sections, annotation will give incorrect results!")
        print_program_sections(elffile)

        # convert to actually creating xrefs and making comments
        print("Adding repeatable comments to map definitions, adding drefs for map relocations")
        print("Also adding repeatable comments to possible global definitions and drefs for their relocations")
        print("  (If a possible global definition is an extern, we just comment the relocations, no xrefs are added)")
        process_relocations(elffile)

        print("Done. Happy Reversing!")


source_file = ida_nalt.get_input_file_path()
process_file(source_file)
