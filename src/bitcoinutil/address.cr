require "openssl"

module BC

  BASE58S="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  def self.concat(a : Bytes, b : Bytes)
    tmp = Bytes.new(a.size + b.size)
    tmp.copy_from(a)
    (tmp + a.size).copy_from(b)
    tmp
  end

  def self.prepend(byte : UInt8, bytes : Bytes)
    tmp = Bytes.new(bytes.size + 1)
    tmp[0] = byte
    (tmp + 1).copy_from(bytes)
    tmp
  end

  def self.make_address(pubkey : String)

    raise Exception.new "Needs to be in uncompressed point format with '04' prefix" if pubkey.size != (2+64+64) || pubkey[1] != '4'

    bytes = pubkey.hexbytes
    tmp =  OpenSSL::Digest.new("SHA256").update(bytes).digest
    hash = prepend(0_u8, OpenSSL::Digest.new("RIPEMD160").update(tmp).digest)

    first = OpenSSL::Digest.new("SHA256").update(hash).digest
    tmp = OpenSSL::Digest.new("SHA256").update(first).digest
    checksum = tmp[0,4]
    data = concat(hash, checksum)

    num = BigInt.new data.hexstring, 16
    s = ""
    while num > 0
      num, idx = num.divmod 58
      s += BASE58S[idx]
    end

    "1#{s.reverse}"

  end

end
