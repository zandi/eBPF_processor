# eBPF IDA Proc

This is an IDA Processor and supporting scripts that can be used to disassemble
eBPF bytecode. It was originally developed for a challenge, but since expanded
and updated. It still needs testing against more eBPF ELF files and comparison
with output from other tools like eBPF-supporting objdump, and bpftool.

It was developed primarily against eBPF ELFs produced as part of libbpf
toolchains, where the ELF is opened/loaded by libbpf. If your ELF differs from
the conventions that libbpf expects, you may get inaccurate results or other
failures.

## Requirements

Currently IDA 7.4+ using Python3 is necessary.

the `pyelftools` python package is necessary for annotating map references.

## Installation

You just need to place `ebpf.py` in your `IDA_ROOT\procs` folder.

If you want map relocation annotation to work, you additionally need to install
the `pyelftools` package from pip, and ensure your IDA knows about it (look at
`sys.path` in your IDA python interpreter, and try `import elftools`).

## Use

1. Open the eBPF ELF file in IDA, using the standard ELF loader, but selecting the eBPF processor
2. Wait for autoanalysis to complete
3. Go to File > Script file ... (Alt + F7) to select a script file to run
4. Select the "annotate_ebpf_helpers.py" script
5. Wait for it to finish
6. Following the same process, run the "annotate_map_relocations.py" script
7. Wait for it to finish

Auto-analysis should at least mark bytes in code segments as instructions and
disassemble them, though may not mark them as functions proper. Currently the
bpf helper annotating script only inspects instructions belonging to functions,
not all instructions present in the program. You may need to manually define
functions so the helper annotation script sees them.

The map annotating script requires the original ELF file because it requires the
section headers, relocation sections, string and symbol tables to function. As
mentioned above it also depends on the pyelftools package.

Now you have all your eBPF programs disassembled, with helper calls annotated
with the helper's full signature, and with data references to maps added
including repeatable comments to annotate where maps are referenced.

## Testing

This has been tested against eBPF ELF objects from
https://github.com/vbpf/ebpf-samples, 
https://github.com/libbpf/libbpf-bootstrap, and from
https://github.com/Gui774ume/ebpfkit

This should be a good starting point for making sure we can handle some
reasonably real-world eBPF ELF files, but could easily miss more specialized
programs that use less common instructions, or have a more customized loading
process that's significantly different from libbpf's methods.

Currently all instructions in these eBPF ELF files are recognized and
disassembled. IDA's built-in ELF loader does an acceptable job loading these
files, but does not interpret some eBPF-specific sections like BTF and maps.
We've included scripts for annotating helper calls and map references, but these
have been less rigorously tested.

If you think anything is amiss, please compare the output you're seeing against
output from something like `llvm-objdump -dr ebpf_elf_object.o`. The
instruction syntax is different but should get the same point across. A more
significant difference may indicate a problem. Relatively recent llvm is
necessary to disassemble eBPF and handle eBPF specific things, but you should
have it if you can build libbpf projects.

## Issues

There are a number of unsupported instructions that simply have not been
encountered during development & testing yet. If you run across an unsupported
instruction you'll likely have autonalysis break with sections of code left as
`db` or `dq` bytes. Manually marking unrecognized instruction bytes as code
fails with a "MakeCode failed" kind of error.

There is no custom loader so BTF related sections simply aren't handled. The
map relocation annotating script tries to replicate how IDA loads sections, so
if your object differs from this when loaded in IDA, the map annotation will
give wrong results.

Global and static variable references are not currently annotated.

## Author

- Original author: Clément Berthaux - clement (dot) berthaux (at) synacktiv (dot) com
- Fixes, Expansions & Updates: Michael Zandi - the (dot) zandi (at) gmail (dot) com


![Example of filter opened in IDA](img/bpf_ida.png)
