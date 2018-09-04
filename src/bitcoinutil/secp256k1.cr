
# Below are the public specs for Bitcoin's curve - the secp256k1

EC_PRIME = BigInt.new "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16 # 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime
EC_FIELD_SIZE=BigInt.new "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16 # Number of points in the field
EC_A = 0
EC_B = 7 # These two defines the elliptic curve. y^2 = x^3 + Acurve * x + Bcurve

EC_GX = BigInt.new "55066263022277343669578718895168534326250603453777594175500187360389116729240"
EC_GY = BigInt.new "32670510020758816978083085130507043184471273380659243275938904335757337482424"
EC_GP = [EC_GX, EC_GY] # Generator Point

EC_VERBOSE=false

module SecP256K1

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

  #Extended Euclidean Algorithm/'division' in elliptic curves
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

  # Not true addition, invented for EC. Could have been called anything.
  def self.jive(point,b)
    puts "JIVE [#{point[0]},#{point[1]}] -> GENPOINT" if EC_VERBOSE
    a = point
      slope = ((b[1]-a[1]) * modinv(b[0]-a[0],EC_PRIME)) % EC_PRIME
      x = (slope*slope-a[0]-b[0]) % EC_PRIME
      y = (slope*(a[0]-x)-a[1]) % EC_PRIME
      return [x,y]
  end

  # This is called point doubling, also invented for EC.
  def self.juke(point)
    a = point
    puts "JUKE [#{point[0]},#{point[1]}]" if EC_VERBOSE
      slope = ((3*a[0]*a[0]+EC_A) * modinv((2*a[1]),EC_PRIME)) % EC_PRIME
      x = (slope*slope-2*a[0]) % EC_PRIME
      y = (slope*(a[0]-x)-a[1]) % EC_PRIME
      return [x,y]
  end

  # Double & add. Not true multiplication
  def self.sequence(gen_point,scalar)

    raise Exception.new ("Invalid Scalar/Private Key") if scalar == 0 || scalar >= EC_FIELD_SIZE

    binstr = scalar.to_s 2  # make binary string. e.g. "10101010101010101"
    current_point=gen_point
    binstr.each_char_with_index do |c,i|

      next if i == 0  # leading '1' is skipped

      current_point=SecP256K1.juke(current_point)
      if c == '1'
        current_point=SecP256K1.jive(current_point,gen_point)
      end
    end
    return current_point
  end

  def self.pubkey_format(point)
    prefix = "02"
    prefix = "03" if point[1] % 2 == 1  # e.g. odd

    # prepend '0' chars until 64 chars in length
    hexval = point[0].to_s 16
    [0..(64-hexval.size)].each { hexval = '0' + hexval }

    "#{prefix}#{hexval}"
  end

  # TODO: make reliable BigInt random numbers
  def self.rand()
    r = Random.new
    val = EC_FIELD_SIZE / (r.rand(57) + 1) * r.next_u / Int32::MAX
  end

  def self.sign(datahash, privKey, rando = 0)
    rando = rand() if rando == 0
    xRandSignPoint, yRandSignPoint = SecP256K1.sequence(EC_GP, rando)
    r = xRandSignPoint % EC_FIELD_SIZE
    sig = ((datahash + r * privKey)*(modinv(rando, EC_FIELD_SIZE))) % EC_FIELD_SIZE;
  end

  def self.verify(sig, datahash, pubkeyPoint, rando)
    xRandSignPoint, yRandSignPoint = SecP256K1.sequence(EC_GP, rando)
    r = xRandSignPoint % EC_FIELD_SIZE
    w = modinv(sig,EC_FIELD_SIZE)
    point1 = SecP256K1.sequence(EC_GP,(datahash * w) % EC_FIELD_SIZE)
    point2 = SecP256K1.sequence(pubkeyPoint,(r * w) % EC_FIELD_SIZE)
    x,y = SecP256K1.jive(point1, point2)
    x == r
  end
end
