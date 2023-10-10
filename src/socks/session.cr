class SOCKS::Session
  property source : IO
  getter options : Options
  property destination : IO?

  def initialize(@options : Options, @source : IO)
    @destination = nil
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

  def process_upgrade!(server : Server, pause_pool : PausePool? = nil) : HTTP::Request?
    case _wrapper = options.server.wrapper
    in Options::Server::Wrapper::WebSocket
      request = HTTP::Request.from_io io: @source
      response, key, request = HTTP::WebSocket.response_check_request_validity! socket: @source, request: request

      check_authorization! server: server, request: request, response: response
      extensions = process_websocket_request wrapper: _wrapper, request: request, response: response, pause_pool: pause_pool
      HTTP::WebSocket.accept! socket: @source, response: response, key: key, request: request
      process_websocket_accept wrapper: _wrapper, extensions: extensions, pause_pool: pause_pool

      request
    in Options::Server::Wrapper
    in Nil
    end
  end

  private def process_websocket_request(wrapper : Options::Server::Wrapper::WebSocket, request : HTTP::Request, response : HTTP::Server::Response, pause_pool : PausePool? = nil) : Set(Enhanced::ExtensionFlag)
    extensions = unwrap_websocket_request_extensions request: request
    value = process_websocket_request_connection_identifier wrapper: wrapper, request: request, response: response, extensions: extensions, pause_pool: pause_pool

    if extensions.includes? Enhanced::ExtensionFlag::CONNECTION_REUSE
      response.headers.add key: "Connection-Reuse", value: wrapper.allowConnectionReuse ? ConnectionReuseDecisionFlag::SUPPORTED.to_s : ConnectionReuseDecisionFlag::UNSUPPORTED.to_s
    end

    case value
    in Tuple(Enhanced::ExtensionFlag, UUID)
      if !wrapper.allowConnectionPause || pause_pool.nil?
        response.headers.add key: "Connection-Pause", value: ConnectionPauseDecisionFlag::UNSUPPORTED.to_s
      else
        response.headers.add key: "Connection-Pause", value: ConnectionPauseDecisionFlag::SUPPORTED.to_s
        @connectionIdentifier = value.last
      end
    in UUID
      if !wrapper.allowConnectionPause || pause_pool.nil?
        response.headers.add key: "Connection-Pause", value: ConnectionPauseDecisionFlag::UNSUPPORTED.to_s

        return extensions
      end

      case entry = pause_pool.get? connection_identifier: value
      in PausePool::Entry
        response.headers.add key: "Connection-Pause", value: ConnectionPauseDecisionFlag::VALID.to_s

        @connectionPausePending = false
        @connectionIdentifier = value
        @state = entry.state
        @destination = entry.destination
      in Nil
        decision_flag = pause_pool.connection_identifier_includes?(connection_identifier: value) ? ConnectionPauseDecisionFlag::PENDING : ConnectionPauseDecisionFlag::INVALID
        response.headers.add key: "Connection-Pause", value: decision_flag.to_s
        return extensions unless decision_flag.pending?

        @connectionPausePending = true
        @connectionIdentifier = value
      end
    in ConnectionIdentifierDecisionFlag
    in Nil
    end

    extensions
  end

  private def process_websocket_accept(wrapper : Options::Server::Wrapper::WebSocket, extensions : Set(Enhanced::ExtensionFlag), pause_pool : PausePool? = nil)
    protocol = HTTP::WebSocket::Protocol.new io: @source, masked: false, sync_close: true
    @source = _enhanced_websocket = Enhanced::WebSocket.new io: protocol, options: options

    _enhanced_websocket.allow_connection_reuse = extensions.includes?(Enhanced::ExtensionFlag::CONNECTION_REUSE) && wrapper.allowConnectionReuse
    _enhanced_websocket.allow_connection_pause = extensions.includes?(Enhanced::ExtensionFlag::CONNECTION_PAUSE) && wrapper.allowConnectionPause
    @connectionIdentifier.try { |_connection_identifier| _enhanced_websocket.connection_identifier = _connection_identifier }
    _enhanced_websocket.maximum_sent_sequence = wrapper.maximumSentSequence
    _enhanced_websocket.maximum_receive_sequence = wrapper.maximumReceiveSequence

    pause_pool.try { |_pause_pool| process_connection_pause_pending source: _enhanced_websocket, pause_pool: _pause_pool }

    if _state = @state
      _enhanced_websocket.state = _state
      @state = nil
    end

    @source = _enhanced_websocket
  end

  private def process_connection_pause_pending(source : Enhanced::WebSocket, pause_pool : PausePool)
    return unless _connection_identifier = self.connection_identifier
    return unless source.allow_connection_pause?
    return unless self.connection_pause_pending?
    return unless entry = source.process_server_side_connection_pause_pending! connection_identifier: _connection_identifier, pause_pool: pause_pool

    @destination = entry.destination
    @state = entry.state
    @connectionPausePending = nil
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

  private def process_websocket_request_connection_identifier(wrapper : Options::Server::Wrapper::WebSocket, request : HTTP::Request, response : HTTP::Server::Response, extensions : Set(Enhanced::ExtensionFlag), pause_pool : PausePool? = nil) : Tuple(Enhanced::ExtensionFlag, UUID) | ConnectionIdentifierDecisionFlag | UUID | Nil
    text_connection_identifier = request.headers["Connection-Identifier"]?

    if text_connection_identifier.nil? && extensions.includes?(Enhanced::ExtensionFlag::ASSIGN_IDENTIFIER)
      return if !wrapper.enableConnectionIdentifier || pause_pool.nil?

      @connectionIdentifier = _connection_identifier = pause_pool.assign_connection_identifier
      response.headers.add key: "Connection-Identifier", value: _connection_identifier.to_s

      return Tuple.new Enhanced::ExtensionFlag::ASSIGN_IDENTIFIER, _connection_identifier
    end

    if !wrapper.enableConnectionIdentifier && extensions.includes?(Enhanced::ExtensionFlag::ASSIGN_IDENTIFIER)
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
      response.to_io io: @source rescue nil

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
    response.to_io io: @source rescue nil

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
      response.to_io io: @source rescue nil

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
      response.to_io io: @source rescue nil

      raise ex
    end

    {% if "sec_websocket_protocol" == authorization_type %}
      response.headers["Sec-WebSocket-Protocol"] = authorization_type
    {% end %}

    true
  end
  {% end %}
end
