require "big/big_int"

# Below are the public specs for Bitcoin's curve - the secp256k1
# Based on https://github.com/wobine/blackboard101
# Spec Info: https://en.bitcoin.it/wiki/Secp256k1

module SecP256K1

EC_PRIME = BigInt.new "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16 # 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime
EC_FIELD_SIZE=BigInt.new "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16 # Number of points in the field
EC_A = 0
EC_B = 7 # These two defines the elliptic curve. y^2 = x^3 + EC_A * x + EC_B

EC_GX = BigInt.new "55066263022277343669578718895168534326250603453777594175500187360389116729240"
EC_GY = BigInt.new "32670510020758816978083085130507043184471273380659243275938904335757337482424"

EC_VERBOSE=false

  struct Point
    property x : BigInt
    property y : BigInt
    def initialize(@x, @y)
    end
    def initialize(a : BitInt[2])
      @x = a[0]
      @y = a[1]
    end
  end

  EC_GP = Point.new(EC_GX, EC_GY) # Generator Point

  #--------------------------------------------------------------
  # Extended Euclidean Algorithm/'division' in elliptic curves
  #--------------------------------------------------------------
  def self.modinv(a,n=EC_PRIME)
    #puts "MODINV a:#{a} n:#{n}"
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1
        ratio = high/low
        nm, nnew = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, nnew, lm, low
    end
    return lm % n
  end

  #--------------------------------------------------------------
  # jive() - Implementation of EC 'addition', which has nothing to
  # do with addition.
  # Draw line between pointA and pointB, and it will intersect
  # curve in one other point -R.  Reflect point -R over X-axis
  # to end up at R, which is the result.
  #--------------------------------------------------------------
  def self.jive(pointA, pointB)
    puts "JIVE [#{pointA.x},#{pointA.y}] -> GENPOINT" if EC_VERBOSE

    slope = ((pointB.y-pointA.y) * modinv(pointB.x-pointA.x,EC_PRIME)) % EC_PRIME
    x = (slope*slope-pointA.x-pointB.x) % EC_PRIME
    y = (slope*(pointA.x-x)-pointA.y) % EC_PRIME

    return Point.new x,y
  end

  #--------------------------------------------------------------
  # juke() - Implementation of EC 'point doubling', which is a
  # special case of EC Addition, where pointA and pointB are same.
  # Draw tangent line at point, and it will intersect curve at
  # point -R.  Reflect point -R over X-axis to end up at R, which
  # is the result.
  #--------------------------------------------------------------
  def self.juke(point)
    puts "JUKE [#{point.x},#{point.y}]" if EC_VERBOSE

    slope = ((3*point.x*point.x+EC_A) * modinv((2*point.y),EC_PRIME)) % EC_PRIME
    x = (slope*slope-2*point.x) % EC_PRIME
    y = (slope*(point.x-x)-point.y) % EC_PRIME

    return Point.new x,y
  end

  #--------------------------------------------------------------
  # sequence() - Implementation of 'EC Multiplication', which is really
  # hopping around the elliptic curve N times.
  #--------------------------------------------------------------
  def self.sequence(gen_point,scalar)

    raise Exception.new ("Invalid Scalar/Private Key") if scalar == 0 || scalar >= EC_FIELD_SIZE

    # convert 'scalar' to binary and make it a string.  e.g. "10101010101010101"
    binstr = scalar.to_s 2  # make binary string.

    current_point=gen_point

    # for each bit in scalar

    binstr.each_char_with_index do |c,i|

      next if i == 0  # leading '1' is skipped

      # there are two options for next hop
      # - juke(current) # e.g. EC Double of current point
      # - jive (juke(current), generatorPoint) # e.g. EC Addition of juke(current) and generatorPoint

      current_point=SecP256K1.juke(current_point)
      if c == '1'
        current_point=SecP256K1.jive(current_point,gen_point)
      end
    end
    return current_point
  end

  #--------------------------------------------------------------
  # returns compact public key format for point
  # Consists of 2-char prefix '02' or '03' if odd
  # followed by 64-char hex string of point.x
  #--------------------------------------------------------------
  def self.pubkey_format(point)
    prefix = "02"
    prefix = "03" if point.y % 2 == 1  # e.g. odd

    "#{prefix}#{coord_hex64(point.x)}"
  end

  #--------------------------------------------------------------
  # return hex string of bigint. prepend '0' until 64-chars long
  #--------------------------------------------------------------
  def self.coord_hex64(x : BigInt)
    hexval = x.to_s 16

    # prepend '0' chars until 64 chars in length
    while (hexval.size < 64)
      hexval = '0' + hexval
    end

    hexval
  end

  #--------------------------------------------------------------
  # long point format
  #--------------------------------------------------------------
  def self.pubkey_format4(point)
    "04#{coord_hex64(point.x)}#{coord_hex64(point.y)}"
  end

  #--------------------------------------------------------------
  # Return a random number up to 160 bits
  #--------------------------------------------------------------
  def self.rand()
    s = ""
    r = Random.new
    5.times do
      s += r.next_u.to_s(2)
    end
    val = BigInt.new s,2
    val % EC_FIELD_SIZE
  end

  #--------------------------------------------------------------
  # Returns BigInt signature of datahash
  # Note: rando needs to be same value for sign() and verify()
  #--------------------------------------------------------------
  def self.sign(datahash : BigInt, privKey : BigInt, rando : BigInt)
    randPoint = SecP256K1.sequence(EC_GP, rando)
    r = randPoint.x % EC_FIELD_SIZE
    sig = ((datahash + r * privKey)*(modinv(rando, EC_FIELD_SIZE))) % EC_FIELD_SIZE;
  end

  #--------------------------------------------------------------
  # Verify that 'sig' was computed from datahash and rando using
  # the private key that pubkeyPoint was derived from.
  # @returns true if valid signature
  #--------------------------------------------------------------
  def self.verify(sig : BigInt, datahash : BigInt, pubkeyPoint : Point, rando : BigInt)
    randPoint = SecP256K1.sequence(EC_GP, rando)
    r = randPoint.x % EC_FIELD_SIZE
    w = modinv(sig,EC_FIELD_SIZE)
    point1 = SecP256K1.sequence(EC_GP,(datahash * w) % EC_FIELD_SIZE)
    point2 = SecP256K1.sequence(pubkeyPoint,(r * w) % EC_FIELD_SIZE)
    endPoint = SecP256K1.jive(point1, point2)
    endPoint.x == r
  end
end
