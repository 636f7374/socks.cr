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

  def add_source_tls_socket(value : OpenSSL::SSL::Socket::Server)
    source_tls_sockets = @sourceTlsSockets ||= Set(OpenSSL::SSL::Socket::Server).new
    source_tls_sockets << value
    @sourceTlsSockets = source_tls_sockets
  end

  def source_tls_sockets
    @sourceTlsSockets ||= Set(OpenSSL::SSL::Socket::Server).new
  end

  def add_source_tls_context=(value : OpenSSL::SSL::Context::Server)
    source_tls_contexts = @sourceTlsContexts ||= Set(OpenSSL::SSL::Context::Server).new
    source_tls_contexts << value
    @sourceTlsContexts = source_tls_contexts
  end

  def source_tls_contexts
    @sourceTlsContexts ||= Set(OpenSSL::SSL::Context::Server).new
  end

  def add_destination_tls_socket(value : OpenSSL::SSL::Socket::Client)
    destination_tls_sockets = @destinationTlsSockets ||= Set(OpenSSL::SSL::Socket::Client).new
    destination_tls_sockets << value
    @destinationTlsSockets = destination_tls_sockets
  end

  def destination_tls_sockets
    @destinationTlsSockets ||= Set(OpenSSL::SSL::Socket::Client).new
  end

  def add_destination_tls_context(value : OpenSSL::SSL::Context::Client)
    destination_tls_contexts = @destinationTlsContexts ||= Set(OpenSSL::SSL::Context::Client).new
    destination_tls_contexts << value
    @destinationTlsContexts = destination_tls_contexts
  end

  def destination_tls_contexts
    @destinationTlsContexts ||= Set(OpenSSL::SSL::Context::Client).new
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
    source_tls_sockets.each do |source_tls_socket|
      source_tls_socket.skip_finalize = true
      source_tls_socket.free
    end

    source_tls_contexts.each do |source_tls_context|
      source_tls_context.skip_finalize = true
      source_tls_context.free
    end

    destination_tls_sockets.each do |destination_tls_socket|
      destination_tls_socket.skip_finalize = true
      destination_tls_socket.free
    end

    destination_tls_contexts.each do |destination_tls_context|
      destination_tls_context.skip_finalize = true
      destination_tls_context.free
    end
  end

  def set_transfer_tls(transfer : Transfer, reset : Bool)
    transfer.source_tls_sockets = source_tls_sockets
    transfer.source_tls_contexts = source_tls_contexts
    transfer.destination_tls_sockets = destination_tls_sockets
    transfer.destination_tls_contexts = destination_tls_contexts

    if reset
      @sourceTlsSockets = nil
      @sourceTlsContexts = nil
      @destinationTlsSockets = nil
      @destinationTlsContexts = nil
    end
  end

  def reset(reset_tls : Bool)
    closed_memory = IO::Memory.new 0_i32
    closed_memory.close

    @inbound = closed_memory
    @holding = closed_memory
    @outbound = closed_memory

    if reset_tls
      @sourceTlsSockets = nil
      @sourceTlsContexts = nil
      @destinationTlsSockets = nil
      @destinationTlsContexts = nil
    end
  end

  def reset_peer(side : Transfer::Side, reset_tls : Bool)
    closed_memory = IO::Memory.new 0_i32
    closed_memory.close

    case side
    in .source?
      @inbound = closed_memory

      if reset_tls
        @sourceTlsSockets = nil
        @sourceTlsContexts = nil
      end
    in .destination?
      @outbound = closed_memory

      if reset_tls
        @destinationTlsSockets = nil
        @destinationTlsContexts = nil
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
