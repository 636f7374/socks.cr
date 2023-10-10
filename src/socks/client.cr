class SOCKS::Client < IO
  property outbound : IO
  getter options : Options
  property udpForwarder : Layer::AssociateUDP?
  property tcpForwarder : Layer::TCPBinding?

  def initialize(@outbound : IO, @options : Options)
    @udpForwarder = nil
    @tcpForwarder = nil
  end

  def self.new(host : String, port : Int32, dns_resolver : DNS::Resolver, options : Options, timeout : TimeOut = TimeOut.new)
    socket = TCPSocket.new host: host, port: port, dns_resolver: dns_resolver, connect_timeout: timeout.connect, caller: nil

    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    new outbound: socket, options: options
  end

  def self.new(ip_address : Socket::IPAddress, options : Options, timeout : TimeOut = TimeOut.new)
    socket = TCPSocket.new ip_address: ip_address, connect_timeout: timeout.connect

    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    new outbound: socket, options: options
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

  def wrapper=(value : Options::Client::Wrapper)
    @wrapper = value
  end

  def wrapper
    @wrapper
  end

  def wrapper_authorize=(value : Frames::Authorize)
    @wrapperAuthorize = value
  end

  def wrapper_authorize
    @wrapperAuthorize
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

  def tcp_forwarder : Layer::TCPBinding?
    @tcpForwarder
  end

  def udp_forwarder : Layer::AssociateUDP?
    @udpForwarder
  end

  def last_alive_time : Int64?
    udp_last_alive_time = @udpForwarder.try &.last_alive_time
    tcp_last_alive_time = @tcpForwarder.try &.last_alive_time

    udp_last_alive_time || tcp_last_alive_time
  end

  def __transfer_before_call : Bool
    buffer = uninitialized UInt8[1_i32]
    forwarder = @udpForwarder || @tcpForwarder rescue nil

    case forwarder
    in Layer::AssociateUDP, Layer::TCPBinding
      forwarder.read slice: buffer.to_slice
    in IO
    in Nil
    end

    true
  end

  def __transfer_extra_sent_bytes : UInt64
    forwarder = @udpForwarder || @tcpForwarder rescue nil

    case forwarder
    in Layer::AssociateUDP, Layer::TCPBinding
      return forwarder.sentBytes.get
    in IO
    in Nil
    end

    0_u64
  end

  def __transfer_extra_received_bytes : UInt64
    forwarder = @udpForwarder || @tcpForwarder rescue nil

    case forwarder
    in Layer::AssociateUDP, Layer::TCPBinding
      return forwarder.receivedBytes.get
    in IO
    in Nil
    end

    0_u64
  end

  def read(slice : Bytes) : Int32
    return 0_i32 if slice.empty?
    @outbound.read slice: slice
  end

  def write(slice : Bytes) : Nil
    return if slice.empty?
    @outbound.write slice: slice
  end

  def flush
    @outbound.flush
  end

  def close
    @outbound.close rescue nil
    close_forwarder reset: true

    true
  end

  def close_forwarder(reset : Bool = true)
    @udpForwarder.try &.close rescue nil
    @tcpForwarder.try &.close rescue nil

    if reset
      @udpForwarder = nil
      @tcpForwarder = nil
    end
  end

  def closed?
    @outbound.closed?
  end

  def notify_peer_incoming
    _outbound = @outbound
    return unless _outbound.is_a? Enhanced::WebSocket

    _outbound.notify_peer_incoming
    true
  end

  def process_upgrade!(state : SOCKS::Enhanced::State? = nil)
    case _wrapper = @wrapper
    in SOCKS::Options::Client::Wrapper::WebSocket
      upgrade_websocket! wrapper: _wrapper, state: state
    in SOCKS::Options::Client::Wrapper
    in Nil
    end
  end

  private def upgrade_websocket!(wrapper : SOCKS::Options::Client::Wrapper::WebSocket, state : SOCKS::Enhanced::State?)
    headers = wrapper.headers.dup

    if _wrapper_authorize = wrapper_authorize
      case _wrapper_authorize.authorizationType
      in .basic?
        raise Exception.new String.build { |io| io << "Client.upgrade_websocket!: Client.wrapperAuthorizeFrame.userName is Nil!" } unless _wrapper_authorize_user_name = _wrapper_authorize.userName
        raise Exception.new String.build { |io| io << "Client.upgrade_websocket!: Client.wrapperAuthorizeFrame.password is Nil!" } unless _wrapper_authorize_password = _wrapper_authorize.password

        headers["Authorization"] = String.build { |io| io << "Basic" << ' ' << Base64.strict_encode(String.build { |_io| _io << _wrapper_authorize_user_name << ':' << _wrapper_authorize_password }) }
      end
    end

    process_websocket_request wrapper: wrapper, headers: headers
    response, protocol = HTTP::WebSocket.handshake socket: @outbound, host: wrapper.address.host, port: wrapper.address.port, resource: wrapper.resource, headers: headers, data_raw: wrapper.dataRaw
    @outbound = _outbound = Enhanced::WebSocket.new io: protocol, options: options, state: (state || SOCKS::Enhanced::State::WebSocket.new)
    process_websocket_response wrapper: wrapper, response: response, outbound: _outbound
  end

  private def process_websocket_request(wrapper : SOCKS::Options::Client::Wrapper::WebSocket, headers : HTTP::Headers) : Bool
    _connection_identifier = connection_identifier
    headers.add key: "Connection-Identifier", value: _connection_identifier.to_s if _connection_identifier && wrapper.enableConnectionIdentifier

    extensions = Set(Enhanced::ExtensionFlag).new
    extensions << Enhanced::ExtensionFlag::ASSIGN_IDENTIFIER if wrapper.enableConnectionIdentifier && !connection_identifier
    extensions << Enhanced::ExtensionFlag::CONNECTION_PAUSE if wrapper.allowConnectionPause
    extensions << Enhanced::ExtensionFlag::CONNECTION_REUSE if wrapper.allowConnectionReuse
    headers["Sec-WebSocket-Extensions"] = String.build { |io| io << extensions.map(&.to_s).join ", " } unless extensions.empty?

    true
  end

  private def process_websocket_response(wrapper : SOCKS::Options::Client::Wrapper::WebSocket, response : HTTP::Client::Response, outbound : Enhanced::WebSocket) : Bool
    outbound.maximum_sent_sequence = wrapper.maximumSentSequence
    outbound.maximum_receive_sequence = wrapper.maximumReceiveSequence

    connection_decision_identifier = process_websocket_response_connection_identifier wrapper: wrapper, response: response, outbound: outbound
    process_websocket_response_connection_reuse wrapper: wrapper, response: response, outbound: outbound, connection_decision_identifier: connection_decision_identifier
    process_websocket_response_connection_pause wrapper: wrapper, response: response, outbound: outbound, connection_decision_identifier: connection_decision_identifier
    process_connection_pause_pending! outbound: outbound

    true
  end

  private def process_connection_pause_pending!(outbound : Enhanced::WebSocket)
    return unless self.connection_pause_pending?
    outbound.process_client_side_connection_pause_pending!

    self.connection_pause_pending = nil
  end

  private def process_websocket_response_connection_identifier(wrapper : SOCKS::Options::Client::Wrapper::WebSocket, response : HTTP::Client::Response, outbound : Enhanced::WebSocket) : ConnectionIdentifierDecisionFlag | UUID | Nil
    return unless wrapper.enableConnectionIdentifier
    return unless response_headers_connection_identifier = response.headers["Connection-Identifier"]?

    decision_flag = ConnectionIdentifierDecisionFlag.parse response_headers_connection_identifier rescue nil
    _connection_identifier = UUID.new value: response_headers_connection_identifier rescue nil unless decision_flag
    value = decision_flag || _connection_identifier

    case value
    in ConnectionIdentifierDecisionFlag
      if value.valid_format?
        self.connection_identifier.try { |_connection_identifier| outbound.connection_identifier = _connection_identifier }
      else
        raise Exception.new String.build { |io| io << "SOCKS::Client.process_websocket_response_connection_identifier: " << "Abnormal status (" << value << ") received from IO." }
      end
    in UUID
      self.connection_identifier = value
      outbound.connection_identifier = value
    in Nil
    end

    value
  end

  private def process_websocket_response_connection_reuse(wrapper : SOCKS::Options::Client::Wrapper::WebSocket, response : HTTP::Client::Response, outbound : Enhanced::WebSocket, connection_decision_identifier : ConnectionIdentifierDecisionFlag | UUID | Nil) : Bool
    return false unless connection_decision_identifier
    return false unless wrapper.enableConnectionIdentifier
    return false unless wrapper.allowConnectionReuse

    unless response_headers_connection_reuse = response.headers["Connection-Reuse"]?
      outbound.allow_connection_reuse = false

      return false
    end

    decision_flag = ConnectionReuseDecisionFlag.parse response_headers_connection_reuse rescue nil

    unless decision_flag
      outbound.allow_connection_reuse = false

      return false
    end

    case decision_flag
    in .supported?
      outbound.allow_connection_reuse = true
    in .unsupported?
      outbound.allow_connection_reuse = false
    end

    true
  end

  private def process_websocket_response_connection_pause(wrapper : SOCKS::Options::Client::Wrapper::WebSocket, response : HTTP::Client::Response, outbound : Enhanced::WebSocket, connection_decision_identifier : ConnectionIdentifierDecisionFlag | UUID | Nil) : Bool
    return false unless connection_decision_identifier
    return false unless wrapper.enableConnectionIdentifier
    return false unless wrapper.allowConnectionPause

    unless response_headers_connection_pause = response.headers["Connection-Pause"]?
      outbound.allow_connection_pause = false

      return false
    end

    pause_decision_flag = ConnectionPauseDecisionFlag.parse response_headers_connection_pause rescue nil

    unless pause_decision_flag
      outbound.allow_connection_pause = false

      return false
    end

    case connection_decision_identifier
    in ConnectionIdentifierDecisionFlag
      unless connection_decision_identifier.valid_format?
        outbound.allow_connection_pause = false
        raise Exception.new String.build { |io| io << "SOCKS::Client.process_websocket_response_connection_pause: " << "Abnormal status (" << pause_decision_flag << ") received from IO." }
      end

      case pause_decision_flag
      when ConnectionPauseDecisionFlag::VALID
        outbound.allow_connection_pause = true
      when ConnectionPauseDecisionFlag::PENDING
        outbound.allow_connection_pause = true
        self.connection_pause_pending = true
      else
        outbound.allow_connection_pause = false
        raise Exception.new String.build { |io| io << "SOCKS::Client.process_websocket_response_connection_pause: " << "Abnormal status (" << pause_decision_flag << ") received from IO." }
      end
    in UUID
      unless pause_decision_flag.supported?
        outbound.allow_connection_pause = false
        raise Exception.new String.build { |io| io << "SOCKS::Client.process_websocket_response_connection_pause: " << "Abnormal status (" << pause_decision_flag << ") received from IO." }
      end

      outbound.allow_connection_pause = true
    end

    true
  end

  def notify_peer_negotiate(source : IO, command_flag : SOCKS::Enhanced::CommandFlag? = nil) : SOCKS::Enhanced::CommandFlag?
    close_forwarder reset: true
    return unless command_flag

    _outbound = @outbound
    return unless _outbound.is_a? Enhanced::WebSocket

    _outbound.notify_peer_negotiate command_flag: command_flag
    _outbound.process_negotiate source: source

    raise Exception.new String.build { |io| io << "SOCKS::Client.notify_peer_negotiate: outbound.final_command_flag? is Nil!" } unless final_command_flag = _outbound.final_command_flag?
    _outbound.reset_settings command_flag: final_command_flag

    final_command_flag
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
        raise Exception.new "Client.handshake!: authenticationMethods is UserNamePassword, but no Authenticate Frame is provided." unless _authenticate_frame = authenticate_frame

        frame_negotiate.authenticateFrame = _authenticate_frame
      when .no_authentication?
      else
        raise Exception.new "Client.handshake!: Currently, authentication methods other than NoAuthentication and UserNamePassword are not supported."
      end
    end

    frame_negotiate.to_io io: @outbound

    # Receive Negotiate Reply.

    from_negotiate = Frames::Negotiate.from_io io: @outbound, ar_type: ARType::Reply, version_flag: version
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

        _authenticate_frame.to_io io: @outbound
        from_negotiate.authenticateFrame = from_authenticate = Frames::Authenticate.from_io io: @outbound, ar_type: ARType::Reply, version_flag: version
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

  def establish!(dns_resolver : DNS::Resolver, command_flag : Frames::CommandFlag, host : String, port : Int32, remote_dns_resolution : Bool = true)
    destination_address = Address.new host: host, port: port
    establish! dns_resolver: dns_resolver, command_flag: command_flag, destination_address: destination_address, remote_dns_resolution: remote_dns_resolution
  end

  def establish!(dns_resolver : DNS::Resolver, command_flag : Frames::CommandFlag, destination_address : Socket::IPAddress | Address, remote_dns_resolution : Bool = true) : Frames::Establish?
    # Check Options::Switcher.

    raise Exception.new "Client.establish!: command_flag is TCPBinding, but Switcher.allowTCPBinding is false." if command_flag.tcp_binding? && !options.switcher.allowTCPBinding
    raise Exception.new "Client.establish!: command_flag is AssociateUDP, but Switcher.allowAssociateUDP is false." if command_flag.associate_udp? && !options.switcher.allowAssociateUDP
    raise Exception.new "Client.establish!: command_flag is EnhancedAssociateUDP, but Switcher.allowEnhancedAssociateUDP is false." if command_flag.enhanced_associate_udp? && !options.switcher.allowEnhancedAssociateUDP

    case destination_address
    in Socket::IPAddress
    in Address
      SOCKS.to_ip_address(destination_address.host, destination_address.port).try { |ip_address| destination_address = ip_address }
    end

    frame_establish = Frames::Establish.new version: version, arType: ARType::Ask
    frame_establish.commandType = command_flag

    case destination_address
    in Socket::IPAddress
      frame_establish.destinationAddress = nil
      frame_establish.destinationIpAddress = destination_address

      case destination_address.family
      when .inet6?
        frame_establish.addressType = Frames::AddressFlag::Ipv6
      when .inet?
        frame_establish.addressType = Frames::AddressFlag::Ipv4
      end
    in Address
      if remote_dns_resolution || (command_flag.tcp_binding? || command_flag.associate_udp? || command_flag.enhanced_associate_udp?)
        frame_establish.destinationAddress = destination_address
        frame_establish.addressType = Frames::AddressFlag::Domain
      else
        delegator, fetch_type, ip_addresses = dns_resolver.getaddrinfo host: destination_address.host, port: destination_address.port
        raise Exception.new String.build { |io| io << "Client.establish!: Unfortunately, DNS::Resolver.getaddrinfo! The host: (" << destination_address.host << ") & fetchType: (" << fetch_type << ")" << " IPAddress result is empty!" } if ip_addresses.empty?

        first_ip_address = ip_addresses.first
        frame_establish.destinationAddress = nil
        frame_establish.destinationIpAddress = first_ip_address
        frame_establish.addressType = first_ip_address.family.inet? ? Frames::AddressFlag::Ipv4 : Frames::AddressFlag::Ipv6
      end
    end

    # Send Establish Ask & Receive Establish Reply.

    frame_establish.to_io io: @outbound
    from_establish = Frames::Establish.from_io io: @outbound, ar_type: ARType::Reply, version_flag: version, command_flag: command_flag

    raise Exception.new "Client.connect!: Establish.statusType cannot be Nil!" unless status_type = from_establish.statusType
    raise Exception.new String.build { |io| io << "Received from IO to failure status (" << status_type.to_s << ")." } unless status_type.indicates_success?

    from_establish
  end

  def resynchronize(command_flag : Frames::CommandFlag) : Frames::Establish?
    case command_flag
    in .tcp_connection?
    in .tcp_binding?
      # Be sure to connect the Frames::Establish.destinationIpAddress (Bind) first, Then call Client.resynchronize.

      incoming_establish = Frames::Establish.from_io io: @outbound, ar_type: ARType::Reply, version_flag: version, command_flag: command_flag
    in .associate_udp?
    in .enhanced_associate_udp?
    end

    @outbound.try do |_outbound|
      if _outbound.is_a? Enhanced::WebSocket
        _outbound.resynchronize
        _outbound.transporting = true
      end
    end

    incoming_establish
  end
end

require "uuid"
require "./layer/*"
require "./enhanced/*"
