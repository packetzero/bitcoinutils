require "openssl"

module BC

  #-----------------------------------------------------------------------
  # make_address
  # returns 
  #-----------------------------------------------------------------------
  def self.make_address(pubkey : String)

    raise Exception.new "Needs to be in uncompressed point format with '04' prefix" if pubkey.size != (2+64+64) || pubkey[1] != '4'

    tmp =  sha256(pubkey.hexbytes)
    hash = prepend(0_u8, ripe160(tmp))

    tmp = sha256(sha256(hash))
    checksum = tmp[0,4]
    data = concat(hash, checksum)

    "1#{base58(data)}"
  end

  def self.sha256(bytes : Bytes)
    OpenSSL::Digest.new("SHA256").update(bytes).digest
  end
  def self.ripe160(bytes : Bytes)
    OpenSSL::Digest.new("RIPEMD160").update(bytes).digest
  end

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

  BASE58S="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  def self.base58(bytes : Bytes)
    base58 bytes.hexstring
  end

  def self.base58(hexstr : String)
    num = BigInt.new hexstr, 16
    s = ""
    while num > 0
      num, idx = num.divmod 58
      s += BASE58S[idx]
    end
    s.reverse
  end


end
