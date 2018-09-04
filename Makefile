all: genaddrs genpubkey
genaddrs: src/genaddrs.cr
	crystal build $^
genpubkey: src/genpubkey.cr
	crystal build $^
