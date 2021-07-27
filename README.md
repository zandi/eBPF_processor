# eBPF IDA Proc

This is an IDA Processor that can be used to disassemble eBPF bytecode. It was
originally developed for a challenge, but since expanded and updated. It still
needs testing against more eBPF ELF files and comparison with output from other
tools like eBPF-supporting objdump, and bpftool.

## Requirements

Currently IDA 7.4+ using Python3 is necessary.

## Installation

You just need to place `ebpf.py` in your `IDA_ROOT\procs` folder.

## Use

Once installed, simply open an eBPF ELF (machine type 247) using the standard
IDA ELF loader, but manually selecting the eBPF processor module. Auto-analysis
should at least mark bytes in code segments as instructions and disassemble
them, though may not mark them as functions proper.

Currently the bpf helper annotating script only inspects instructions belonging
to functions, not all instructions present in the program.

## Testing

This has been tested against eBPF ELF objects from
https://github.com/vbpf/ebpf-samples and from
https://github.com/libbpf/libbpf-bootstrap

This should be a good starting point for making sure we can handle some
reasonably real-world eBPF ELF files, but could easily miss more specialized
programs that use less common instructions.

Currently all instructions in these eBPF ELF files are recognized and
disassembled. IDA's built-in ELF loader does an acceptable job loading these
files, but does not interpret some eBPF-specific sections like BTF and maps.

## Issues

There are a number of unsupported instructions that simply have not been
encountered during development & testing yet. If you run across an unsupported
instruction you'll likely have autonalysis break with sections of code left as
`db` bytes. Manually marking unrecognized instruction bytes as code fails with
a "MakeCode failed" kind of error.

There is no custom loader so BTF related sections simply aren't handled, and
maps sections are present but not interpreted or referenced in any particular way.
Things are still a bit manual.

## Author

- Original author: Clément Berthaux - clement (dot) berthaux (at) synacktiv (dot) com
- Fixes, Expansions & Updates: Michael Zandi - the (dot) zandi (at) gmail (dot) com


![Example of filter opened in IDA](img/bpf_ida.png)
