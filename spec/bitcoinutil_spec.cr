require "./spec_helper"
require "big/big_int"

TEST_KEY1_PRIV_HEX = "A0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E"
TEST_KEY1_PUB_HEX = "020791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a"
TEST_KEY2_PRIV_HEX = "75263518707598184987916378021939673586055614731957507592904438851787542395619"

describe Bitcoinutil do

  it "generates public key" do

    num = BigInt.new TEST_KEY1_PRIV_HEX,16
    end_point = SecP256K1.sequence EC_GP, num
    #puts "#{end_point[0].to_s 16},#{end_point[1].to_s 16}"
    pubkey = SecP256K1.pubkey_format end_point
    pubkey.should eq TEST_KEY1_PUB_HEX
  end

  it "signs and verifies" do
    datahash = BigInt.new "86032112319101611046176971828093669637772856272773459297323797145286374828050"
    privKey = BigInt.new TEST_KEY2_PRIV_HEX

    pubKeyPoint = SecP256K1.sequence EC_GP, privKey

    rando = BigInt.new "28695618543805844332113829720373285210420739438570883203839696518176414791234"

    sig = SecP256K1.sign datahash, privKey, rando
    status = SecP256K1.verify sig, datahash, pubKeyPoint, rando
    status.should eq true
  end

end
