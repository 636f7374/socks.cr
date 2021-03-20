class SOCKS::Session < IO
  property inbound : IO
  getter options : Options
  property outbound : IO?
  property holding : IO?
  property exchangeFrames : Set(Frames)
  property syncCloseOutbound : Bool

  def initialize(@inbound : IO, @options : Options)
    @outbound = nil
    @holding = nil
    @exchangeFrames = Set(Frames).new
    @syncCloseOutbound = true
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

  def source_tls_socket=(value : OpenSSL::SSL::Socket::Server)
    @sourceTlsSocket = value
  end

  def source_tls_socket
    @sourceTlsSocket
  end

  def source_tls_context=(value : OpenSSL::SSL::Context::Server)
    @sourceTlsContext = value
  end

  def source_tls_context
    @sourceTlsContext
  end

  def destination_tls_socket=(value : OpenSSL::SSL::Socket::Client)
    @destinationTlsSocket = value
  end

  def destination_tls_socket
    @destinationTlsSocket
  end

  def destination_tls_context=(value : OpenSSL::SSL::Context::Client)
    @destinationTlsContext = value
  end

  def destination_tls_context
    @destinationTlsContext
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
    holding.try &.close rescue nil

    if syncCloseOutbound
      outbound.try &.close rescue nil
    end

    true
  end

  def cleanup : Bool
    close
    free_tls!
    reset reset_tls: true

    true
  end

  private def free_tls!
    source_tls_socket.try &.skip_finalize = true
    source_tls_socket.try &.free

    source_tls_context.try &.skip_finalize = true
    source_tls_context.try &.free

    destination_tls_socket.try &.skip_finalize = true
    destination_tls_socket.try &.free

    destination_tls_context.try &.skip_finalize = true
    destination_tls_context.try &.free
  end

  def set_transfer_tls(transfer : Transfer, reset : Bool)
    _source_tls_socket = source_tls_socket
    transfer.source_tls_socket = _source_tls_socket if _source_tls_socket
    _source_tls_context = source_tls_context
    transfer.source_tls_context = _source_tls_context if _source_tls_context

    _destination_tls_socket = destination_tls_socket
    transfer.destination_tls_socket = _destination_tls_socket if _destination_tls_socket
    _destination_tls_context = destination_tls_context
    transfer.destination_tls_context = _destination_tls_context if _destination_tls_context

    if reset
      @sourceTlsSocket = nil
      @sourceTlsContext = nil
      @destinationTlsSocket = nil
      @destinationTlsContext = nil
    end
  end

  def reset(reset_tls : Bool)
    closed_memory = IO::Memory.new 0_i32
    closed_memory.close

    @inbound = closed_memory
    @holding = closed_memory
    @outbound = closed_memory

    if reset_tls
      @sourceTlsSocket = nil
      @sourceTlsContext = nil
      @destinationTlsSocket = nil
      @destinationTlsContext = nil
    end
  end

  def reset_peer(side : Transfer::Side, reset_tls : Bool)
    closed_memory = IO::Memory.new 0_i32
    closed_memory.close

    case side
    in .source?
      @inbound = closed_memory

      if reset_tls
        @sourceTlsSocket = nil
        @sourceTlsContext = nil
      end
    in .destination?
      @outbound = closed_memory

      if reset_tls
        @destinationTlsSocket = nil
        @destinationTlsContext = nil
      end
    end
  end

  def closed?
    inbound.closed?
  end

  private def upgrade_websocket!
    HTTP::WebSocket.accept socket: inbound

    protocol = HTTP::WebSocket::Protocol.new io: inbound, masked: false, sync_close: true
    @inbound = Enhanced::WebSocket.new io: protocol, options: options
  end

  def process_upgrade!
    _wrapper = options.server.wrapper

    case _wrapper
    in Options::Server::Wrapper::WebSocket
      upgrade_websocket!
    in SOCKS::Options::Server::Wrapper
    in Nil
    end
  end
end
