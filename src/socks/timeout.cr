struct SOCKS::TimeOut
  property read : Int32
  property write : Int32
  property connect : Int32

  def initialize
    @read = 30_i32
    @write = 30_i32
    @connect = 10_i32
  end
end
