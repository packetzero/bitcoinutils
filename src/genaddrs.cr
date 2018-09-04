require "./bitcoinutil/*"
require "./bitcoinutil.cr"

module BitcoinUtil

  io = File.open("out.csv", "w+")
  i = 0_u64
  while true
    puts "#{Time.now} #{i}" if i % 1000 == 0

    privKey = SecP256K1.rand

    begin
      end_point = SecP256K1.sequence SecP256K1::EC_GP, privKey
      pubKey4 = SecP256K1.pubkey_format4 end_point
      addr = BC.make_address pubKey4

      io.puts "#{addr},#{privKey},#{pubKey4}"
    rescue ex
      puts "#{ex} #{privKey}"
    end
    i += 1
  end

end
