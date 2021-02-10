struct SOCKS::TimeOut
  property read : Int32
  property write : Int32
  property connect : Int32

  def initialize
    @read = 30_i32
    @write = 30_i32
    @connect = 10_i32
  end

  def self.udp_default
    timeout = new
    timeout.read = 2_i32
    timeout.write = 2_i32
    timeout.connect = 2_i32

    timeout
  end
end
