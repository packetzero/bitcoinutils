require "./bitcoinutil/*"
require "big/big_int"

if ARGV.size < 1
  puts "usage: genpubkey <private_key_hex_string> "
  exit 2
end

def get_intval (str)
  str = str.downcase
  if str.size >= 3
    if str.starts_with? ("0x")
      return BigInt.new str[2..-1] # skip first two chars indicating hex
    end
    # is it hex or decimal?
    is_hex = false
    str.each_char do |c|
      is_hex = true if c.ord >= 'a'.ord || c.ord <= 'f'.ord
    end
    if is_hex
      return BigInt.new str, 16
    else
      return BigInt.new str
    end
  else
    return BigInt.new str
  end
end

privkey = get_intval ARGV[0]

end_point = SecP256K1.sequence EC_GP, privkey
pubkey = SecP256K1.pubkey_format end_point
puts "#{pubkey}"
