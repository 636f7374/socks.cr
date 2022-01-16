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

  def source_tls_sockets=(value : Set(OpenSSL::SSL::Socket::Server))
    @sourceTlsSockets = value
  end

  def source_tls_sockets
    @sourceTlsSockets ||= Set(OpenSSL::SSL::Socket::Server).new
  end

  def add_source_tls_context=(value : OpenSSL::SSL::Context::Server)
    source_tls_contexts = @sourceTlsContexts ||= Set(OpenSSL::SSL::Context::Server).new
    source_tls_contexts << value
    @sourceTlsContexts = source_tls_contexts
  end

  def source_tls_contexts=(value : Set(OpenSSL::SSL::Context::Server))
    @sourceTlsContexts = value
  end

  def source_tls_contexts
    @sourceTlsContexts ||= Set(OpenSSL::SSL::Context::Server).new
  end

  def add_destination_tls_socket(value : OpenSSL::SSL::Socket::Client)
    destination_tls_sockets = @destinationTlsSockets ||= Set(OpenSSL::SSL::Socket::Client).new
    destination_tls_sockets << value
    @destinationTlsSockets = destination_tls_sockets
  end

  def destination_tls_sockets=(value : Set(OpenSSL::SSL::Socket::Client))
    @destinationTlsSockets = value
  end

  def destination_tls_sockets
    @destinationTlsSockets ||= Set(OpenSSL::SSL::Socket::Client).new
  end

  def add_destination_tls_context(value : OpenSSL::SSL::Context::Client)
    destination_tls_contexts = @destinationTlsContexts ||= Set(OpenSSL::SSL::Context::Client).new
    destination_tls_contexts << value
    @destinationTlsContexts = destination_tls_contexts
  end

  def destination_tls_contexts=(value : Set(OpenSSL::SSL::Context::Client))
    @destinationTlsContexts = value
  end

  def destination_tls_contexts
    @destinationTlsContexts ||= Set(OpenSSL::SSL::Context::Client).new
  end

  def connection_identifier=(value : UUID)
    @connectionIdentifier = value
  end

  def connection_identifier
    @connectionIdentifier
  end

  def connection_pause_pending=(value : Bool?)
    @connectionPausePending = value
  end

  def connection_pause_pending? : Bool?
    @connectionPausePending
  end

  def state=(value : Enhanced::State::WebSocket?)
    @state = value
  end

  def state : Enhanced::State::WebSocket?
    @state
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
    holding.try { |_holding| _holding.close rescue nil }

    if syncCloseOutbound
      outbound.try { |_outbound| _outbound.close rescue nil }
    end

    true
  end

  def cleanup : Bool
    close
    free_tls!
    reset_socket reset_tls: true

    true
  end

  def cleanup(sd_flag : Transfer::SDFlag, free_tls : Bool, reset : Bool = true)
    case sd_flag
    in .source?
      @inbound.try &.close rescue nil
    in .destination?
      @outbound.try &.close rescue nil
    end

    case sd_flag
    in .source?
      free_source_tls
    in .destination?
      free_destination_tls
    end

    reset_socket sd_flag: sd_flag, reset_tls: free_tls if reset
  end

  private def free_source_tls
    source_tls_sockets.try &.each &.free
    source_tls_contexts.try &.each &.free

    true
  end

  private def free_destination_tls
    destination_tls_sockets.try &.each &.free
    destination_tls_contexts.try &.each &.free

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

  def reset_socket(reset_tls : Bool)
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

  def reset_socket(sd_flag : Transfer::SDFlag, reset_tls : Bool)
    closed_memory = IO::Memory.new 0_i32
    closed_memory.close

    case sd_flag
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

  def process_upgrade!(server : Server, pause_pool : PausePool? = nil) : HTTP::Request?
    _wrapper = options.server.wrapper

    case _wrapper
    in Options::Server::Wrapper::WebSocket
      upgrade_websocket! server: server, pause_pool: pause_pool
    in Options::Server::Wrapper
    in Nil
    end
  end

  private def upgrade_websocket!(server : Server, pause_pool : PausePool? = nil) : HTTP::Request
    request = HTTP::Request.from_io io: inbound
    upgrade_websocket! request: request, server: server, pause_pool: pause_pool
  end

  private def upgrade_websocket!(request : HTTP::Request | HTTP::Status | Nil, server : Server, pause_pool : PausePool? = nil) : HTTP::Request
    response, key, request = HTTP::WebSocket.response_check_request_validity! socket: inbound, request: request
    check_authorization! server: server, request: request, response: response
    extensions = process_websocket_request request: request, response: response, pause_pool: pause_pool

    HTTP::WebSocket.accept! socket: inbound, response: response, key: key, request: request
    process_websocket_accept extensions: extensions, pause_pool: pause_pool

    request
  end

  private def process_websocket_accept(extensions : Set(Enhanced::ExtensionFlag), pause_pool : PausePool? = nil)
    protocol = HTTP::WebSocket::Protocol.new io: inbound, masked: false, sync_close: true
    @inbound = _inbound = Enhanced::WebSocket.new io: protocol, options: options

    _inbound.allow_connection_reuse = extensions.includes?(Enhanced::ExtensionFlag::CONNECTION_REUSE) && options.switcher.allowConnectionReuse
    _inbound.allow_connection_pause = extensions.includes?(Enhanced::ExtensionFlag::CONNECTION_PAUSE) && options.switcher.allowConnectionPause
    self.connection_identifier.try { |_connection_identifier| _inbound.connection_identifier = _connection_identifier }

    process_connection_pause_pending inbound: _inbound, pause_pool: pause_pool
    restore_state inbound: _inbound

    case _wrapper = options.server.wrapper
    in Options::Server::Wrapper::WebSocket
      _inbound.maximum_sent_sequence = _wrapper.maximumSentSequence
      _inbound.maximum_receive_sequence = _wrapper.maximumReceiveSequence
    in Options::Server::Wrapper
    in Nil
    end

    @inbound = _inbound
  end

  private def process_connection_pause_pending(inbound : Enhanced::WebSocket, pause_pool : PausePool? = nil)
    return unless pause_pool
    return unless _connection_identifier = self.connection_identifier
    return unless inbound.allow_connection_pause?
    return unless self.connection_pause_pending?
    return unless entry = inbound.process_server_side_connection_pause_pending! connection_identifier: _connection_identifier, pause_pool: pause_pool

    restore_outbound entry: entry
    self.state = entry.state
    self.connection_pause_pending = nil
  end

  private def restore_outbound(entry : PausePool::Entry)
    entry_transfer = entry.transfer
    entry_transfer.destination_tls_sockets.try { |_destination_tls_sockets| self.destination_tls_sockets = _destination_tls_sockets }
    entry_transfer.destination_tls_contexts.try { |_destination_tls_contexts| self.destination_tls_contexts = _destination_tls_contexts }
    @outbound = entry_transfer.destination
  end

  private def restore_state(inbound : Enhanced::WebSocket)
    self.state.try { |_state| inbound.state = _state }
    self.state = nil
  end

  private def process_websocket_request(request : HTTP::Request, response : HTTP::Server::Response, pause_pool : PausePool? = nil) : Set(Enhanced::ExtensionFlag)
    extensions = unwrap_websocket_request_extensions request: request

    value = process_websocket_request_connection_identifier request: request, response: response, extensions: extensions, pause_pool: pause_pool
    process_websocket_request_connection_reuse response: response if extensions.includes? Enhanced::ExtensionFlag::CONNECTION_REUSE

    case value
    in Tuple(Enhanced::ExtensionFlag, UUID)
      if !options.switcher.allowConnectionReuse || pause_pool.nil?
        response.headers.add key: "Connection-Pause", value: ConnectionPauseDecisionFlag::UNSUPPORTED.to_s
      else
        response.headers.add key: "Connection-Pause", value: ConnectionPauseDecisionFlag::SUPPORTED.to_s
        self.connection_identifier = value.last
      end
    in UUID
      if !options.switcher.allowConnectionReuse || pause_pool.nil?
        response.headers.add key: "Connection-Pause", value: ConnectionPauseDecisionFlag::UNSUPPORTED.to_s

        return extensions
      end

      case entry = pause_pool.get? connection_identifier: value
      in PausePool::Entry
        response.headers.add key: "Connection-Pause", value: ConnectionPauseDecisionFlag::VALID.to_s

        self.connection_pause_pending = false
        self.connection_identifier = value
        self.state = entry.state

        restore_outbound entry: entry
      in Nil
        decision_flag = pause_pool.connection_identifier_includes?(connection_identifier: value) ? ConnectionPauseDecisionFlag::PENDING : ConnectionPauseDecisionFlag::INVALID
        response.headers.add key: "Connection-Pause", value: decision_flag.to_s
        return extensions unless decision_flag.pending?

        self.connection_pause_pending = true
        self.connection_identifier = value
      end
    in ConnectionIdentifierDecisionFlag
    in Nil
    end

    extensions
  end

  private def unwrap_websocket_request_extensions(request : HTTP::Request) : Set(Enhanced::ExtensionFlag)
    extensions = Set(Enhanced::ExtensionFlag).new
    return extensions unless text_sec_websocket_extensions = request.headers["Sec-WebSocket-Extensions"]?
    sec_websocket_extensions = text_sec_websocket_extensions.split ", "

    sec_websocket_extensions.each do |sec_websocket_extension|
      extension_flag = Enhanced::ExtensionFlag.parse sec_websocket_extension rescue nil
      extensions << extension_flag if extension_flag
    end

    extensions
  end

  private def process_websocket_request_connection_identifier(request : HTTP::Request, response : HTTP::Server::Response, extensions : Set(Enhanced::ExtensionFlag), pause_pool : PausePool? = nil) : Tuple(Enhanced::ExtensionFlag, UUID) | ConnectionIdentifierDecisionFlag | UUID | Nil
    text_connection_identifier = request.headers["Connection-Identifier"]?

    if text_connection_identifier.nil? && extensions.includes?(Enhanced::ExtensionFlag::ASSIGN_IDENTIFIER)
      return if !options.switcher.enableConnectionIdentifier || pause_pool.nil?

      self.connection_identifier = _connection_identifier = pause_pool.assign_connection_identifier
      response.headers.add key: "Connection-Identifier", value: _connection_identifier.to_s

      return Tuple.new Enhanced::ExtensionFlag::ASSIGN_IDENTIFIER, _connection_identifier
    end

    if !options.switcher.enableConnectionIdentifier && extensions.includes?(Enhanced::ExtensionFlag::ASSIGN_IDENTIFIER)
      response.headers.add key: "Connection-Identifier", value: ConnectionIdentifierDecisionFlag::UNSUPPORTED.to_s

      return ConnectionIdentifierDecisionFlag::UNSUPPORTED
    end

    if text_connection_identifier
      return if text_connection_identifier.empty?
      _connection_identifier = UUID.new value: text_connection_identifier rescue nil
    end

    unless _connection_identifier
      response.headers.add key: "Connection-Identifier", value: ConnectionIdentifierDecisionFlag::INVALID_FORMAT.to_s

      return ConnectionIdentifierDecisionFlag::INVALID_FORMAT
    end

    response.headers.add key: "Connection-Identifier", value: ConnectionIdentifierDecisionFlag::VALID_FORMAT.to_s
    _connection_identifier
  end

  private def process_websocket_request_connection_reuse(response : HTTP::Server::Response)
    response.headers.add key: "Connection-Reuse", value: options.switcher.allowConnectionReuse ? ConnectionReuseDecisionFlag::SUPPORTED.to_s : ConnectionReuseDecisionFlag::UNSUPPORTED.to_s
  end

  private def process_websocket_request_connection_pause(response : HTTP::Server::Response, extensions : Set(Enhanced::ExtensionFlag))
    response.headers.add key: "Connection-Pause", value: options.switcher.allowConnectionPause ? ConnectionPauseDecisionFlag::SUPPORTED.to_s : ConnectionPauseDecisionFlag::UNSUPPORTED.to_s
  end

  def check_authorization!(server : Server, request : HTTP::Request, response : HTTP::Server::Response)
    case wrapper_authorization = server.wrapper_authorization
    in Frames::WebSocketAuthorizationFlag
      case wrapper_authorization
      in .basic?
        check_basic_authorization! server: server, wrapper_authorization: wrapper_authorization, request: request, response: response
      end
    in Nil
    end
  end

  private def check_basic_authorization!(server : Server, wrapper_authorization : Frames::WebSocketAuthorizationFlag, request : HTTP::Request, response : HTTP::Server::Response)
    begin
      raise Exception.new String.build { |io| io << "Session.check_basic_authorization!: Server expects wrapperAuthorizationFlag to be " << wrapper_authorization << ", But the client HTTP::Headers is empty!" } unless request_headers = request.headers
    rescue ex
      response = HTTP::Client::Response.new status_code: 407_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: inbound rescue nil

      raise ex
    end

    if headers_authorization = request_headers["Authorization"]?
      check_basic_authorization! server: server, wrapper_authorization: wrapper_authorization, request: request, response: response, value: headers_authorization

      return
    end

    if headers_sec_websocket_protocol = request_headers["Sec-WebSocket-Protocol"]?
      check_sec_websocket_protocol_authorization! server: server, wrapper_authorization: wrapper_authorization, request: request, response: response, value: headers_sec_websocket_protocol

      return
    end

    response = HTTP::Client::Response.new status_code: 407_i32, body: nil, version: request.version, body_io: nil
    response.to_io io: inbound rescue nil

    raise Exception.new String.build { |io| io << "Session.check_basic_authorization!: Server expects wrapperAuthorizationFlag to be " << wrapper_authorization << ", But the client HTTP::Headers[Authorization] or HTTP::Headers[Sec-WebSocket-Protocol] does not exists!" }
  end

  {% for authorization_type in ["basic", "sec_websocket_protocol"] %}
  private def check_{{authorization_type.id}}_authorization!(server : Server, wrapper_authorization : Frames::WebSocketAuthorizationFlag, request : HTTP::Request, response : HTTP::Server::Response, value : String) : Bool
    {% if "basic" == authorization_type %}
      authorization_headers_key = "Authorization"
    {% else %}
      authorization_headers_key = "Sec-WebSocket-Protocol"
    {% end %}

    begin
      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects wrapperAuthorizationFlag to be " << wrapper_authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] is empty!" } if value.empty?
    rescue ex
      response = HTTP::Client::Response.new status_code: 407_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: inbound rescue nil

      raise ex
    end

    begin
      {% if "basic" == authorization_type %}
        authorization_type, delimiter, base64_user_name_password = value.rpartition ' '
      {% else %}
        value_split = value.split ", "
        raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects wrapperAuthorizationFlag to be " << wrapper_authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] Less than 2 items (authorizationType, UserNamePassword)!" } if 2_i32 > value_split.size

        authorization_type = value_split.first
        base64_user_name_password = value_split[1_i32]
      {% end %}

      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects wrapperAuthorizationFlag to be " << wrapper_authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] authorizationType or Base64UserNamePassword is empty!" } if authorization_type.empty? || base64_user_name_password.empty?
      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects wrapperAuthorizationFlag to be " << wrapper_authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] type is not Basic! (" << authorization_type << ")" } unless "Basic" == authorization_type

      {% if "basic" == authorization_type %}
        decoded_base64_user_name_password = Base64.decode_string base64_user_name_password rescue nil rescue nil
      {% else %}
        decoded_base64_user_name_password = Frames.decode_sec_websocket_protocol_authorization! authorization: base64_user_name_password rescue nil
      {% end %}

      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects wrapperAuthorizationFlag to be " << wrapper_authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] Base64 decoding failed!" } unless decoded_base64_user_name_password
      user_name, delimiter, password = decoded_base64_user_name_password.rpartition ':'
      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects wrapperAuthorizationFlag to be " << wrapper_authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] username or password is empty!" } if user_name.empty? || password.empty?

      permission_type = server.on_wrapper_auth.try &.call(user_name, password) || Frames::PermissionFlag::Passed
      raise Exception.new String.build { |io| io << "Session.check_" << {{authorization_type}} << "_authorization!: Server expects wrapperAuthorizationFlag to be " << wrapper_authorization << ", But the client HTTP::Headers[" << authorization_headers_key << "] onAuth callback returns Denied!" } if permission_type.denied?
    rescue ex
      response = HTTP::Client::Response.new status_code: 401_i32, body: nil, version: request.version, body_io: nil
      response.to_io io: inbound rescue nil

      raise ex
    end

    {% if "sec_websocket_protocol" == authorization_type %}
      response.headers["Sec-WebSocket-Protocol"] = authorization_type
    {% end %}

    true
  end
  {% end %}
end
