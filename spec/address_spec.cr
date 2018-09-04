require "./spec_helper"
require "big/big_int"

describe Bitcoinutil do

  it "point to address" do
    addr = BC.make_address "040791DC70B75AA995213244AD3F4886D74D61CCD3EF658243FCAD14C9CCEE2B0AA762FBC6AC0921B8F17025BB8458B92794AE87A133894D70D7995FC0B6B5AB90"
    addr.should eq "1JryTePceSiWVpoNBU8SbwiT7J4ghzijzW"

    # http://rosettacode.org/wiki/Bitcoin/public_point_to_address
    pubkey = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6"
    addr = BC.make_address pubkey
    addr.should eq "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
  end
end
