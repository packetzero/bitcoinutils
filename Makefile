all: genaddrs genpubkey
genaddrs: src/genaddrs.cr src/bitcoinutil/*
	crystal build src/genaddrs.cr
genpubkey: src/genpubkey.cr src/bitcoinutil/*
	crystal build src/genpubkey.cr
