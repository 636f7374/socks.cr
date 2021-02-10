struct SOCKS::Address
  property host : String
  property port : Int32

  def initialize(@host : String, @port : Int32)
  end
end
