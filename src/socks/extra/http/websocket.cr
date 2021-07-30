class HTTP::WebSocket
  def self.accept!(socket : IO) : HTTP::Request
    from_io_request = HTTP::Request.from_io io: socket
    response, key, request = response_check_request_validity! socket: socket, request: from_io_request
    accept! socket: socket, response: response, key: key, request: request
  end

  def self.response_check_request_validity!(socket : IO, request : HTTP::Request | HTTP::Status | Nil) : Tuple(HTTP::Server::Response, String, HTTP::Request)
    raise Exception.new String.build { |io| io << "HTTP::WebSocket.accept: The request type (" << request.class << ") is not HTTP::Request." } unless request.is_a? HTTP::Request
    response = HTTP::Server::Response.new io: socket

    unless websocket_upgrade? request: request
      response.respond_with_status :bad_request
      response.upgrade { }

      raise Exception.new "HTTP::WebSocket.accept: The request does not contain the Upgrade header, or the header Key or Value is incorrect."
    end

    version = request.headers["Sec-WebSocket-Version"]?

    unless version == WebSocket::Protocol::VERSION
      response.status = :upgrade_required
      response.headers["Sec-WebSocket-Version"] = WebSocket::Protocol::VERSION
      response.upgrade { }

      raise Exception.new "HTTP::WebSocket.accept: HTTP::Headers[Version] is empty!"
    end

    unless key = request.headers["Sec-WebSocket-Key"]?
      response.respond_with_status :bad_request
      response.upgrade { }

      raise Exception.new "HTTP::WebSocket.accept: HTTP::Headers[Sec-WebSocket-Key] is empty!"
    end

    Tuple.new response, key, request
  end

  def self.accept!(socket : IO, response : HTTP::Server::Response, key : String, request : HTTP::Request) : HTTP::Request
    accept_code = WebSocket::Protocol.key_challenge key

    response.status = :switching_protocols
    response.headers["Upgrade"] = "websocket"
    response.headers["Connection"] = "Upgrade"
    response.headers["Sec-WebSocket-Accept"] = accept_code
    response.upgrade { }

    request
  end

  def self.handshake(socket : IO, host : String, port : Int32, resource : String = "/", headers : HTTP::Headers = HTTP::Headers.new, data_raw : String? = nil) : Tuple(HTTP::Client::Response, Protocol)
    random_key = Base64.strict_encode StaticArray(UInt8, 16_i32).new { rand(256_i32).to_u8 }

    headers["Host"] = headers["Host"]? || String.build { |io| io << host << ':' << port }
    headers["Connection"] = "Upgrade"
    headers["Upgrade"] = "websocket"
    headers["Sec-WebSocket-Version"] = Protocol::VERSION
    headers["Sec-WebSocket-Key"] = random_key

    resource = "/" if resource.empty?
    handshake = HTTP::Request.new method: "GET", resource: resource, headers: headers, body: data_raw
    handshake.to_io io: socket
    socket.flush

    handshake_response = HTTP::Client::Response.from_io io: socket
    raise Socket::Error.new "HTTP::WebSocket.handshake: Handshake got denied. Status code was #{handshake_response.status.code}." unless handshake_response.status.switching_protocols?

    challenge_response = Protocol.key_challenge random_key
    raise Socket::Error.new "HTTP::WebSocket.handshake: Handshake got denied. Server did not verify WebSocket challenge." unless handshake_response.headers["Sec-WebSocket-Accept"]? == challenge_response

    Tuple.new handshake_response, Protocol.new socket, masked: true
  end

  def self.websocket_upgrade?(request : HTTP::Request) : Bool
    return false unless upgrade = request.headers["Upgrade"]?
    return false unless (upgrade.compare "websocket", case_insensitive: true).zero?

    request.headers.includes_word? "Connection", "Upgrade"
  end
end
