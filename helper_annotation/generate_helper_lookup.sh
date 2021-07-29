#!/bin/sh

# get source files if we don't have them already
# defaulting to 5.13, the most recent non-rc release at time of writing.
# If you need a newer version, specify it via the KERNEL_VERSION variable.
# for example, $KERNEL_VERSION="5.14-rc1" would fetch the file versions from that tag
# 
# Unless you know what you're doing, stick with stable kernel releases

KERNEL_VERSION="${KERNEL_VERSION:-v5.13}"

if [ ! -f bpf_doc.py ]; then
	curl -o bpf_doc.py https://raw.githubusercontent.com/torvalds/linux/${KERNEL_VERSION}/scripts/bpf_doc.py
fi

if [ ! -f bpf.h ]; then
	curl -o bpf.h https://raw.githubusercontent.com/torvalds/linux/${KERNEL_VERSION}/include/uapi/linux/bpf.h
fi

echo "put this dictionary definition in the bpf helper annotation python script:"
echo

python3 ./bpf_doc.py --filename bpf.h --header | grep '^static' | ./parse_helper_header.py

