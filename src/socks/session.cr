class SOCKS::Session < IO
  property inbound : IO
  getter options : Options
  property exchangeFrames : Set(Frames)
  property outbound : IO?
  property holding : IO?

  def initialize(@inbound : IO, @options : Options)
    @exchangeFrames = Set(Frames).new
  end

  def read_timeout=(value : Int | Time::Span | Nil)
    _io = inbound
    _io.read_timeout = value if value if _io.responds_to? :read_timeout=
  end

  def read_timeout
    _io = inbound
    _io.read_timeout if _io.responds_to? :read_timeout
  end

  def write_timeout=(value : Int | Time::Span | Nil)
    _io = inbound
    _io.write_timeout = value if value if _io.responds_to? :write_timeout=
  end

  def write_timeout
    _io = inbound
    _io.write_timeout if _io.responds_to? :write_timeout
  end

  def local_address : Socket::Address?
    _io = inbound
    _io.responds_to?(:local_address) ? _io.local_address : nil
  end

  def remote_address : Socket::Address?
    _io = inbound
    _io.responds_to?(:remote_address) ? _io.remote_address : nil
  end

  def read(slice : Bytes) : Int32
    return 0_i32 if slice.empty?
    inbound.read slice
  end

  def write(slice : Bytes) : Nil
    return if slice.empty?
    inbound.write slice
  end

  def close
    inbound.close rescue nil
    outbound.try &.close rescue nil
    holding.try &.close rescue nil

    true
  end

  def closed?
    inbound.closed?
  end

  def upgrade_websocket
    HTTP::WebSocket.accept inbound

    protocol = HTTP::WebSocket::Protocol.new io: inbound
    @inbound = Enhanced::WebSocket.new io: protocol, options: options
  end
end
