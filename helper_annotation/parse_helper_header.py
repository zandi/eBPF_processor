#!/usr/bin/env python3
#
# takes signatures generated by the linux kernel source bpf_doc.py script with the --header
# flag for c syntax header. Parses to build python dictionary suitable for looking up
# helper function signature by id, which is supplied directly as the immediate in the 
# eBPF call instruction
#
# run this, then put the dictionary in the bpf helper annotation script

import re
import sys

if __name__ == '__main__':
	# split deref patterns so we only remove the first *
	deref_pattern_1 = re.compile('[()]')
	deref_pattern_2 = re.compile('\*')

	split_pattern = re.compile('^static (.+) = \(void \*\) (\d+);')

	helpers = {}

	for l in sys.stdin:
		# split up signature and identifier integer
		m = split_pattern.match(l)

		# transform '(*name)' to 'name' to make function pointer into bare signature
		s = m.group(1)
		s2 = deref_pattern_1.sub('', s, count=2)
		signature = deref_pattern_2.sub('', s2, count=1)

		identifier = int(m.group(2).strip())

		# add this signature to lookup dict
		helpers[identifier] = signature

	
	# don't bother putting in unspec/max fields, we can just let the exception/warning happen
	# skip any 'verification' steps against actual enum in source, since the bpf_doc.py script in
	# kernel source can provide id values with the signatures in its output. If we get wrong results,
	# it's a bug in that script, not this one :)

	print(f"helper_id_to_signature = {repr(helpers)}")

