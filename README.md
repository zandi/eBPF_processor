# eBPF IDA Proc

This is an IDA Processor that can be used to disassemble eBPF bytecode. It was
originally developed for a challenge, but since expanded and updated. It still
needs testing against more eBPF ELF files and comparison with output from other
tools like eBPF-supporting objdump, and bpftool.

## Requirements

Currently IDA 7.4 using Python3 is necessary.

## Author

- Original author: Clément Berthaux - clement (dot) berthaux (at) synacktiv (dot) com
- Fixes, Expansions & Updates: Michael Zandi - the (dot) zandi (at) gmail (dot) com

## Installation

You just need to place `ebpf.py` in your `IDA_ROOT\procs` folder.

![Example of filter opened in IDA](img/bpf_ida.png)
