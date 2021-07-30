class SOCKS::Client < IO
  getter outbound : IO
  getter dnsResolver : DNS::Resolver
  getter options : Options
  property holding : IO?
  property exchangeFrames : Set(Frames)

  def initialize(@outbound : IO, @dnsResolver : DNS::Resolver, @options : Options)
    @holding = nil
    @exchangeFrames = Set(Frames).new
  end

  def self.new(host : String, port : Int32, dns_resolver : DNS::Resolver, options : Options, timeout : TimeOut = TimeOut.new)
    socket = TCPSocket.new host: host, port: port, dns_resolver: dns_resolver, connect_timeout: timeout.connect, caller: nil

    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    new outbound: socket, dnsResolver: dns_resolver, options: options
  end

  def self.new(ip_address : Socket::IPAddress, dns_resolver : DNS::Resolver, options : Options, timeout : TimeOut = TimeOut.new)
    socket = TCPSocket.new ip_address: ip_address, connect_timeout: timeout.connect

    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    new outbound: socket, dnsResolver: dns_resolver, options: options
  end

  def version=(value : Frames::VersionFlag)
    @version = value
  end

  def version
    @version ||= Frames::VersionFlag::V5
  end

  def authenticate_frame=(value : Frames::Authenticate)
    @authenticateFrame = value
  end

  def authenticate_frame
    @authenticateFrame
  end

  def authentication_methods=(value : Frames::AuthenticationFlag)
    self.authentication_methods = [value]
  end

  def authentication_methods=(value : Array(Frames::AuthenticationFlag))
    @authenticationMethods = value.to_set
  end

  def authentication_methods=(value : Set(Frames::AuthenticationFlag))
    @authenticationMethods = value
  end

  def authentication_methods
    @authenticationMethods ||= Set{Frames::AuthenticationFlag::NoAuthentication}
  end

  def wrapper_authorization=(value : Frames::WebSocketAuthorizationFlag)
    @wrapperAuthorization = value
  end

  def wrapper_authorization
    @wrapperAuthorization
  end

  def wrapper_authorize_frame=(value : Frames::Authorize)
    @wrapperAuthorizeFrame = value
  end

  def wrapper_authorize_frame
    @wrapperAuthorizeFrame
  end

  def read_timeout=(value : Int | Time::Span | Nil)
    _io = outbound
    _io.read_timeout = value if value if _io.responds_to? :read_timeout=
  end

  def read_timeout
    _io = outbound
    _io.read_timeout if _io.responds_to? :read_timeout
  end

  def write_timeout=(value : Int | Time::Span | Nil)
    _io = outbound
    _io.write_timeout = value if value if _io.responds_to? :write_timeout=
  end

  def write_timeout
    _io = outbound
    _io.write_timeout if _io.responds_to? :write_timeout
  end

  def tcp_binding_timeout=(value : TimeOut)
    @tcpBindingTimeout = value
  end

  def tcp_binding_timeout
    @tcpBindingTimeout ||= TimeOut.new
  end

  def associate_udp_timeout=(value : TimeOut)
    @associateUDPTimeOut = value
  end

  def associate_udp_timeout
    @associateUDPTimeOut ||= TimeOut.udp_default
  end

  def outbound : IO
    @outbound
  end

  def holding : IO?
    @holding
  end

  def local_address : Socket::Address?
    _io = outbound
    _io.responds_to?(:local_address) ? _io.local_address : nil
  end

  def remote_address : Socket::Address?
    _io = outbound
    _io.responds_to?(:remote_address) ? _io.remote_address : nil
  end

  def read(slice : Bytes) : Int32
    return 0_i32 if slice.empty?
    outbound.read slice
  end

  def write(slice : Bytes) : Nil
    return if slice.empty?
    outbound.write slice
  end

  def flush
    outbound.flush
  end

  def close
    outbound.close rescue nil
    holding.try &.close rescue nil
  end

  def closed?
    outbound.closed?
  end

  def process_upgrade!
    _wrapper = options.client.wrapper

    case _wrapper
    in SOCKS::Options::Client::Wrapper::WebSocket
      upgrade_websocket! host: _wrapper.address.host, port: _wrapper.address.port, resource: _wrapper.resource, headers: _wrapper.headers.dup, data_raw: _wrapper.dataRaw
    in SOCKS::Options::Client::Wrapper
    in Nil
    end
  end

  private def upgrade_websocket!(host : String, port : Int32, resource : String = "/", headers : HTTP::Headers = HTTP::Headers.new, data_raw : String? = nil)
    case _wrapper_authorization = wrapper_authorization
    in Frames::WebSocketAuthorizationFlag
      case _wrapper_authorization
      in .basic?
        raise Exception.new String.build { |io| io << "Client.upgrade_websocket!: Client.wrapperAuthorizeFrame is Nil!" } unless _wrapper_authorize_frame = wrapper_authorize_frame
        raise Exception.new String.build { |io| io << "Client.upgrade_websocket!: Client.wrapperAuthorizeFrame.userName is Nil!" } unless _wrapper_authorize_frame_user_name = _wrapper_authorize_frame.userName
        raise Exception.new String.build { |io| io << "Client.upgrade_websocket!: Client.wrapperAuthorizeFrame.password is Nil!" } unless _wrapper_authorize_frame_password = _wrapper_authorize_frame.password

        headers["Authorization"] = String.build { |io| io << "Basic" << ' ' << Base64.strict_encode(String.build { |_io| _io << _wrapper_authorize_frame_user_name << ':' << _wrapper_authorize_frame_password }) }
      end
    in Nil
    end

    extensions = Set(Enhanced::ExtensionFlag).new
    extensions << Enhanced::ExtensionFlag::CONNECTION_REUSE if options.switcher.allowConnectionReuse
    extensions << Enhanced::ExtensionFlag::ASSIGN_IDENTIFIER if options.switcher.enableConnectionIdentifier
    headers["Sec-WebSocket-Extensions"] = String.build { |io| io << extensions.map(&.to_s).join ", " } unless extensions.empty?

    response, protocol = HTTP::WebSocket.handshake socket: outbound, host: host, port: port, resource: resource, headers: headers, data_raw: data_raw
    outbound = Enhanced::WebSocket.new io: protocol, options: options

    response_headers_connection_reuse = response.headers["Connection-Reuse"]?
    outbound.confirmed_connection_reuse = false if options.switcher.allowConnectionReuse && response_headers_connection_reuse.nil?

    response_headers_connection_reuse.try do |text_connection_reuse|
      case text_connection_reuse
      when "UNSUPPORTED"
        outbound.confirmed_connection_reuse = false
      end
    end

    @outbound = outbound
  end

  def notify_peer_termination! : SOCKS::Enhanced::DecisionFlag
    _outbound = outbound

    if _outbound.is_a? Enhanced::WebSocket
      decision_flag = _outbound.notify_receive_peer_termination! command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE, closed_flag: SOCKS::Enhanced::ClosedFlag::SOURCE
      raise Exception.new String.build { |io| io << "DecisionType received from IO (" << decision_flag << ")." } if decision_flag.refused?

      return decision_flag
    end

    _holding = holding

    if _holding.is_a? Enhanced::WebSocket
      outbound.close rescue nil
      decision_flag = _holding.notify_receive_peer_termination! command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE, closed_flag: SOCKS::Enhanced::ClosedFlag::SOURCE
      raise Exception.new String.build { |io| io << "DecisionType received from IO (" << decision_flag << ")." } if decision_flag.refused?

      @outbound = _holding
      @holding = nil

      return decision_flag
    end

    SOCKS::Enhanced::DecisionFlag::REFUSED
  end

  def handshake! : Bool
    # Send Negotiate Ask.

    uniq_authentication_methods = authentication_methods.to_a.uniq
    raise Exception.new "Client.handshake!: authenticationMethods cannot be empty!" if uniq_authentication_methods.size.zero?

    frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Ask
    frame_negotiate.methodCount = uniq_authentication_methods.size.to_u8
    frame_negotiate.methods = uniq_authentication_methods.to_set

    if 1_i32 == uniq_authentication_methods.size
      case uniq_authentication_methods.first
      when .user_name_password?
        raise Exception.new "Client.handshake!: Your authenticationMethods is UserNamePassword, but you did not provide Authenticate Frame." unless _authenticate_frame = authenticate_frame

        frame_negotiate.authenticateFrame = _authenticate_frame
      when .no_authentication?
      else
        raise Exception.new "Client.handshake!: Currently, authentication methods other than NoAuthentication and UserNamePassword are not supported."
      end
    end

    frame_negotiate.to_io io: outbound
    exchangeFrames << frame_negotiate

    # Receive Negotiate Reply.

    from_negotiate = Frames::Negotiate.from_io io: outbound, ar_type: ARType::Reply, version_flag: version
    exchangeFrames << from_negotiate
    raise Exception.new "Client.handshake!: Negotiate.acceptedMethod cannot be Nil!" unless accepted_method = from_negotiate.acceptedMethod

    unless authentication_methods.includes? accepted_method
      message = String.build do |io|
        io << "Client.handshake!: The acceptedMethod (" << accepted_method.to_s << ") provided by the remote does not match the authenticationMethods ("
        io << authentication_methods.to_s << ") you expect."
      end

      raise Exception.new message
    end

    # Check acceptedMethod.

    case accepted_method
    when .user_name_password?
      # If there is more than one authenticationMethod, sub-steps are required.

      if (1_i32 < uniq_authentication_methods.size) || from_negotiate.authenticateFrame.nil?
        raise Exception.new "Client.handshake!: Your authenticationMethods is UserNamePassword, but you did not provide Authenticate Frame." unless _authenticate_frame = authenticate_frame

        exchangeFrames << _authenticate_frame
        _authenticate_frame.to_io io: outbound
        from_negotiate.authenticateFrame = from_authenticate = Frames::Authenticate.from_io io: outbound, ar_type: ARType::Reply, version_flag: version
        exchangeFrames << from_authenticate
      end
    when .no_authentication?
    else
      raise Exception.new "Client.handshake!: (acceptedMethod) Currently, authentication methods other than NoAuthentication and UserNamePassword are not supported."
    end

    # Finally, check the Authenticate permissionType.

    case accepted_method
    when .no_authentication?
    else
      raise Exception.new "Client.handshake!: Authenticate.authenticateFrame cannot be Nil!" unless authenticate_frame = from_negotiate.authenticateFrame
      raise Exception.new "Client.handshake!: Authenticate.permissionType cannot be Nil!" unless permission_type = authenticate_frame.permissionType
      raise Exception.new "Client.handshake!: The server rejected this connection, it may be an authentication failure." if permission_type.denied?
    end

    true
  end

  def establish!(command_type : Frames::CommandFlag, host : String, port : Int32, remote_dns_resolution : Bool = true)
    destination_address = Address.new host: host, port: port
    establish! command_type: command_type, destination_address: destination_address, remote_dns_resolution: remote_dns_resolution
  end

  def establish!(command_type : Frames::CommandFlag, destination_address : Socket::IPAddress | Address, remote_dns_resolution : Bool = true)
    # Check Options::Switcher.

    raise Exception.new "Client.establish!: command_type is TCPBinding, but Switcher.allowTCPBinding is false." if command_type.tcp_binding? && !options.switcher.allowTCPBinding
    raise Exception.new "Client.establish!: command_type is AssociateUDP, but Switcher.allowAssociateUDP is false." if command_type.associate_udp? && !options.switcher.allowAssociateUDP

    case destination_address
    in Socket::IPAddress
    in Address
      SOCKS.to_ip_address(destination_address.host, destination_address.port).try { |ip_address| destination_address = ip_address }
    end

    frame_establish = Frames::Establish.new version: version, arType: ARType::Ask
    frame_establish.commandType = command_type

    unless remote_dns_resolution
      case destination_address
      in Socket::IPAddress
      in Address
        delegator, fetch_type, ip_addresses = dnsResolver.getaddrinfo host: destination_address.host, port: destination_address.port
        destination_address = ip_addresses.first
      end
    end

    case destination_address
    in Socket::IPAddress
      frame_establish.destinationIpAddress = destination_address

      case destination_address.family
      when .inet6?
        frame_establish.addressType = Frames::AddressFlag::Ipv6
      when .inet?
        frame_establish.addressType = Frames::AddressFlag::Ipv4
      end
    in Address
      frame_establish.destinationAddress = destination_address
      frame_establish.addressType = Frames::AddressFlag::Domain
    end

    # Send Establish Ask.

    frame_establish.to_io io: outbound
    exchangeFrames << frame_establish

    # Create Bind Socket.

    from_establish = Frames::Establish.from_io io: outbound, ar_type: ARType::Reply, version_flag: version
    exchangeFrames << from_establish

    raise Exception.new "Client.connect!: Establish.destinationAddress or destinationIpAddress cannot be Nil!" unless from_establish_destination_address = from_establish.get_destination_address
    raise Exception.new "Client.connect!: Establish.statusType cannot be Nil!" unless status_type = from_establish.statusType
    raise Exception.new String.build { |io| io << "Received from IO to failure status (" << status_type.to_s << ")." } unless status_type.indicates_success?

    case command_type
    in .tcp_connection?
    in .tcp_binding?
      bind_outbound_socket = SOCKS.create_outbound_socket command_type: command_type, destination_address: from_establish_destination_address,
        dns_resolver: dnsResolver, tcp_timeout: tcp_binding_timeout, udp_timeout: associate_udp_timeout

      _outbound = outbound
      @outbound = bind_outbound_socket
      @holding = _outbound
    in .associate_udp?
      bind_outbound_socket = SOCKS.create_outbound_socket command_type: command_type, destination_address: from_establish_destination_address,
        dns_resolver: dnsResolver, tcp_timeout: tcp_binding_timeout, udp_timeout: tcp_binding_timeout

      unless bind_outbound_socket.is_a? UDPSocket
        bind_outbound_socket.close rescue nil
        raise Exception.new "Client.establish!: SOCKS.create_outbound_socket type is not UDPSocket!"
      end

      associate_udp = Layer::Client::AssociateUDP.new io: bind_outbound_socket, addressType: frame_establish.addressType

      case destination_address
      in Socket::IPAddress
        associate_udp.destinationIpAddress = destination_address
      in Address
        associate_udp.destinationAddress = destination_address
      end

      _outbound = outbound
      @outbound = associate_udp
      @holding = _outbound
    end
  end
end

require "./layer/client/*"
require "./enhanced/*"
