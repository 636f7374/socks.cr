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

  private def upgrade_websocket!(server : Server) : HTTP::Request
    from_io_request = HTTP::Request.from_io io: inbound
    response, key, request = HTTP::WebSocket.check_request_validity! socket: inbound, request: from_io_request
    check_proxy_authorization! server: server, request: request
    HTTP::WebSocket.accept! socket: inbound, response: response, key: key, request: request

    protocol = HTTP::WebSocket::Protocol.new io: inbound, masked: false, sync_close: true
    @inbound = Enhanced::WebSocket.new io: protocol, options: options

    request
  end

  private def check_proxy_authorization!(server : Server, request : HTTP::Request)
    case wrapper_authentication = server.wrapper_authentication
    in Frames::WebSocketAuthenticationFlag
      case wrapper_authentication
      in .basic?
        check_basic_proxy_authorization! server: server, authentication: wrapper_authentication, request: request
      end
    in Nil
    end
  end

  private def check_basic_proxy_authorization!(server : Server, authentication : Frames::WebSocketAuthenticationFlag, request : HTTP::Request) : Bool
    begin
      raise Exception.new String.build { |io| io << "Session.check_basic_proxy_authorization!: Your server expects authenticationFlag to be " << authentication << ", But the client HTTP::Headers is empty!" } unless request_headers = request.headers
      headers_proxy_authorization = request_headers["Proxy-Authorization"]?

      raise Exception.new String.build { |io| io << "Session.check_basic_proxy_authorization!: Your server expects authenticationFlag to be " << authentication << ", But the client HTTP::Headers lacks [Proxy-Authorization]!" } unless headers_proxy_authorization
      raise Exception.new String.build { |io| io << "Session.check_basic_proxy_authorization!: Your server expects authenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] is empty!" } if headers_proxy_authorization.empty?
    rescue ex
      response = HTTP::Client::Response.new status_code: 407_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: inbound rescue nil

      raise ex
    end

    begin
      authentication_type, delimiter, base64_user_name_password = headers_proxy_authorization.rpartition " "
      raise Exception.new String.build { |io| io << "Session.check_basic_proxy_authorization!: Your server expects authenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] authenticationType or base64UserNamePassword is empty!" } if authentication_type.empty? || base64_user_name_password.empty?
      raise Exception.new String.build { |io| io << "Session.check_basic_proxy_authorization!: Your server expects authenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] type is not UserNamePassword! (" << authentication_type << ")" } if "Basic" != authentication_type

      decoded_base64_user_name_password = Base64.decode_string base64_user_name_password rescue nil
      raise Exception.new String.build { |io| io << "Session.check_basic_proxy_authorization!: Your server expects authenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] Base64 decoding failed!" } unless decoded_base64_user_name_password

      user_name, delimiter, password = decoded_base64_user_name_password.rpartition ":"
      raise Exception.new String.build { |io| io << "Session.check_basic_proxy_authorization!: Your server expects authenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] username or password is empty!" } if user_name.empty? || password.empty?

      permission_type = server.on_wrapper_auth.try &.call(user_name, password) || Frames::PermissionFlag::Passed
      raise Exception.new String.build { |io| io << "Session.check_basic_proxy_authorization!: Your server expects authenticationFlag to be " << authentication << ", But the client HTTP::Headers[Proxy-Authorization] onAuth callback returns Denied!" } if permission_type.denied?
    rescue ex
      response = HTTP::Client::Response.new status_code: 401_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: inbound rescue nil

      raise ex
    end

    true
  end

  def process_upgrade!(server : Server) : HTTP::Request?
    _wrapper = options.server.wrapper

    case _wrapper
    in Options::Server::Wrapper::WebSocket
      upgrade_websocket! server: server
    in SOCKS::Options::Server::Wrapper
    in Nil
    end
  end
end
