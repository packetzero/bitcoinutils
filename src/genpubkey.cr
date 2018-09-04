require "./bitcoinutil/*"
require "./bitcoinutil.cr"

module BitcoinUtil

  # generates public key for private key

  if ARGV.size < 1
    puts "usage: genpubkey <private_key_hex_string> "
    exit 2
  end



  privkey = get_intval ARGV[0]

  end_point = SecP256K1.sequence SecP256K1::EC_GP, privkey
  pubKey4 = SecP256K1.pubkey_format4 end_point

  puts "#{SecP256K1.pubkey_format end_point}"
  puts "#{pubKey4}"

  addr = BC.make_address pubKey4
  puts "#{addr}"
end
