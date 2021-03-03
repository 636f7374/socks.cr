class SOCKS::Server
  getter io : Socket::Server
  getter dnsResolver : DNS::Resolver
  getter options : Options

  def initialize(@io : Socket::Server, @dnsResolver : DNS::Resolver, @options : Options = Options.new)
  end

  def self.new(host : String, port : Int32, dns_resolver : DNS::Resolver, options : Options = Options.new)
    tcp_server = TCPServer.new host: host, port: port
    new io: tcp_server, dnsResolver: dns_resolver, options: options
  end

  def local_address : Socket::Address?
    _io = io
    _io.responds_to?(:local_address) ? _io.local_address : nil
  end

  def remote_address : Socket::Address?
    _io = io
    _io.responds_to?(:remote_address) ? _io.remote_address : nil
  end

  def authentication=(value : Frames::AuthenticationFlag)
    @authentication = value
  end

  def authentication
    @authentication ||= Frames::AuthenticationFlag::NoAuthentication
  end

  def version=(value : Frames::VersionFlag)
    @version = value
  end

  def version
    @version ||= Frames::VersionFlag::V5
  end

  def on_auth=(value : Proc(String?, String?, Frames::PermissionFlag))
    @onAuth = value
  end

  def on_auth
    @onAuth
  end

  def client_timeout=(value : TimeOut)
    @clientTimeOut = value
  end

  def client_timeout
    @clientTimeOut ||= TimeOut.new
  end

  def establish_tcp_bind_timeout=(value : TimeOut)
    @establishTcpBindTimeout = value
  end

  def establish_tcp_bind_timeout
    @establishTcpBindTimeout ||= TimeOut.new
  end

  def establish_udp_bind_timeout=(value : TimeOut)
    @establishUdpBindTimeOut = value
  end

  def establish_udp_bind_timeout
    @establishUdpBindTimeOut ||= TimeOut.udp_default
  end

  def establish_tcp_outbound_timeout=(value : TimeOut)
    @establishTcpOutboundTimeOut = value
  end

  def establish_tcp_outbound_timeout
    @establishTcpOutboundTimeOut ||= TimeOut.new
  end

  def establish_udp_outbound_timeout=(value : TimeOut)
    @establishUdpOutboundTimeOut = value
  end

  def establish_udp_outbound_timeout
    @establishUdpOutboundTimeOut ||= TimeOut.udp_default
  end

  def handshake!(session : Session) : Bool
    from_negotiate = Frames::Negotiate.from_io io: session, ar_type: ARType::Ask, version_flag: version
    session.exchangeFrames << from_negotiate
    raise Exception.new "Server.handshake!: Frames::Negotiate.methodCount cannot be Nil!" unless _negotiate_method_count = from_negotiate.methodCount
    raise Exception.new "Server.handshake!: Frames::Negotiate.methods cannot be Nil!" unless _negotiate_methods = from_negotiate.methods
    raise Exception.new "Server.handshake!: Frames::Negotiate.methods cannot be empty!" unless _negotiate_methods_first = _negotiate_methods.first?

    _negotiate_authenticate_frame = from_negotiate.authenticateFrame

    unless _negotiate_methods.includes? authentication
      frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
      frame_negotiate.acceptedMethod = Frames::AuthenticationFlag::NoAcceptableMethods
      frame_negotiate.to_io session
      session.exchangeFrames << frame_negotiate

      message = String.build do |io|
        io << "Server.handshake!: The authentication method requested by the client (" << _negotiate_methods.to_s
        io << ") " << "is inconsistent with the authentication method set by the server (" << authentication.to_s << ")."
      end

      raise Exception.new message
    end

    if _negotiate_authenticate_frame && (1_i32 == _negotiate_methods.size) && _negotiate_methods_first.user_name_password?
      frame_authenticate = Frames::Authenticate.new version: version, arType: ARType::Reply
      frame_authenticate.authenticationChoiceType = Frames::AuthenticationChoiceFlag::UserNamePassword
      frame_authenticate.permissionType = on_auth.try &.call(_negotiate_authenticate_frame.userName, _negotiate_authenticate_frame.password) || Frames::PermissionFlag::Passed

      frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
      frame_negotiate.authenticateFrame = frame_authenticate
      frame_negotiate.acceptedMethod = authentication
      frame_negotiate.to_io session
      session.exchangeFrames << frame_negotiate

      return true
    end

    if authentication.user_name_password?
      reply_frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
      reply_frame_negotiate.acceptedMethod = authentication
      reply_frame_negotiate.to_io session
      session.exchangeFrames << reply_frame_negotiate

      from_authentication = Frames::Authenticate.from_io io: session, ar_type: ARType::Ask, version_flag: version
      session.exchangeFrames << from_authentication
      raise Exception.new "Server.handshake!: Frames::Authenticate.authenticationChoiceType cannot be Nil!" unless authentication_choice_type = from_authentication.authenticationChoiceType
      raise Exception.new "Server.handshake!: The authenticationChoiceType provided by the client Authentication is inconsistent with the authenticationChoiceType provided by the client Negotiate." unless authentication_choice_type.user_name_password?

      frame_authenticate = Frames::Authenticate.new version: version, arType: ARType::Reply
      frame_authenticate.authenticationChoiceType = Frames::AuthenticationChoiceFlag::UserNamePassword
      frame_authenticate.permissionType = on_auth.try &.call(from_authentication.userName, from_authentication.password) || Frames::PermissionFlag::Passed
      frame_authenticate.to_io session
      session.exchangeFrames << frame_authenticate

      return true
    end

    if authentication.no_authentication?
      reply_frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
      reply_frame_negotiate.acceptedMethod = authentication
      reply_frame_negotiate.to_io session
      session.exchangeFrames << reply_frame_negotiate

      return true
    end

    reply_frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
    reply_frame_negotiate.acceptedMethod = Frames::AuthenticationFlag::NoAcceptableMethods
    reply_frame_negotiate.to_io session
    session.exchangeFrames << reply_frame_negotiate

    raise Exception.new "Server.handshake: Unsupported authentication method or client authentication method is inconsistent with the authentication method preset by the server"
  end

  def establish!(session : Session) : Bool
    from_establish = Frames::Establish.from_io io: session, ar_type: ARType::Ask, version_flag: version
    session.exchangeFrames << from_establish
    raise Exception.new "Server.establish!: Establish.commandType cannot be Nil!" unless command_type = from_establish.commandType
    raise Exception.new "Server.establish!: Establish.destinationAddress or destinationIpAddress cannot be Nil!" unless destination_address = from_establish.get_destination_address

    begin
      check_destination_protection! destination_address: destination_address
    rescue ex
      send_establish_frame session: session, status_flag: Frames::StatusFlag::ConnectionDenied, destination_ip_address: nil
      raise ex
    end

    # Check if Options::Server accept TCPBinding or AssociateUDP

    case command_type
    in .tcp_connection?
    in .tcp_binding?
      unless options.server.allowTCPBinding
        send_establish_frame session: session, status_flag: Frames::StatusFlag::UnsupportedCommand, destination_ip_address: nil
        raise Exception.new "Because you have disabled Options::Server.allowTCPBinding, this client connection is rejected (UnsupportedCommand)."
      end
    in .associate_udp?
      unless options.server.allowAssociateUDP
        send_establish_frame session: session, status_flag: Frames::StatusFlag::UnsupportedCommand, destination_ip_address: nil
        raise Exception.new "Because you have disabled Options::Server.allowAssociateUDP, this client connection is rejected (UnsupportedCommand)."
      end
    end

    # Create Outbound Socket

    if options.server.syncCreateOutboundSocket
      begin
        outbound_socket = SOCKS.create_outbound_socket command_type: command_type, destination_address: destination_address,
          dns_resolver: dnsResolver, tcp_timeout: establish_tcp_bind_timeout, udp_timeout: establish_udp_bind_timeout

        session.outbound = outbound_socket
        outbound_socket_remote_address = outbound_socket.remote_address rescue nil
      rescue ex
        send_establish_frame session: session, status_flag: Frames::StatusFlag::ConnectFailed, destination_ip_address: nil
        raise Exception.new String.build { |io| io << "Server.establish!: " << ex.message << "." }
      end
    end

    # Create Bind Socket

    tuple_bind_socket = create_bind_socket session: session, command_type: command_type, tcp_timeout: establish_tcp_outbound_timeout,
      udp_timeout: establish_udp_outbound_timeout

    case command_type
    in .tcp_connection?
    in .tcp_binding?
      unless tuple_bind_socket
        send_establish_frame session: session, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
        raise Exception.new "Server.establish!: Bind local address failed!"
      end

      bind_socket_local_address, bind_socket = tuple_bind_socket
      session.holding = bind_socket

      raise Exception.new "Server.establish!: Server.create_bind_socket (TCPBinding) type is not Quirks::TCPBinding." unless bind_socket.is_a? Quirks::TCPBinding
    in .associate_udp?
      unless tuple_bind_socket
        send_establish_frame session: session, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
        raise Exception.new "Server.establish!: Bind local address failed!"
      end

      bind_socket_local_address, bind_socket = tuple_bind_socket
      session.holding = bind_socket

      raise Exception.new "Server.establish!: Server.create_bind_socket (AssociateUDP) type is not Quirks::AssociateUDP." unless bind_socket.is_a? Quirks::AssociateUDP
    end

    # Send Establish Status

    case command_type
    when .tcp_connection?
      status_flag = Frames::StatusFlag::IndicatesSuccess
      outbound_socket_remote_address = Socket::IPAddress.new("0.0.0.0", 0_i32) unless options.server.syncCreateOutboundSocket

      unless outbound_socket_remote_address
        status_flag = Frames::StatusFlag::NetworkUnreachable
      end

      send_establish_frame session: session, status_flag: status_flag, destination_ip_address: outbound_socket_remote_address
    when Frames::CommandFlag::TCPBinding, Frames::CommandFlag::AssociateUDP
      status_flag = Frames::StatusFlag::IndicatesSuccess

      unless bind_socket_local_address
        status_flag = Frames::StatusFlag::NetworkUnreachable

        send_establish_frame session: session, status_flag: status_flag, destination_ip_address: nil
        raise Exception.new "Server.establish!: Failed to get Bind local address!"
      end

      unless bind_socket
        status_flag = Frames::StatusFlag::NetworkUnreachable

        send_establish_frame session: session, status_flag: status_flag, destination_ip_address: nil
        raise Exception.new "Server.establish!: Failed to get Bind local address!"
      end

      send_establish_frame session: session, status_flag: status_flag, destination_ip_address: bind_socket_local_address

      # Because TCPBinding equal TCPServer.accept, so let's try to accept.

      if command_type.associate_udp?
        _outbound = outbound_socket
        raise Exception.new "Server.establish!: Server.create_bind_socket (AssociateUDP) type is not Quirks::AssociateUDP." unless _outbound.is_a? UDPSocket
        session.outbound = UDPOutbound.new io: _outbound, timeout: establish_udp_bind_timeout
      end

      if command_type.tcp_binding?
        raise Exception.new "Server.establish!: Server.create_bind_socket (TCPBinding) type is not Quirks::TCPBinding." unless bind_socket.is_a? Quirks::TCPBinding

        bind_socket.accept?
        bind_socket.read_timeout = establish_tcp_outbound_timeout.read
        bind_socket.write_timeout = establish_tcp_outbound_timeout.write
      end

      session_inbound = session.inbound
      session.inbound = bind_socket
      session.holding = session_inbound
    end

    true
  end

  private def check_destination_protection!(destination_address : Address | Socket::IPAddress) : Bool
    return true unless destination_protection = options.server.destinationProtection

    case destination_address
    in Address
      raise Exception.new "Server.check_destination_protection!: Establish.destinationAddress is in your preset destinationProtection!" if destination_protection.addresses.includes? destination_address
    in Socket::IPAddress
      server_local_address = io.local_address

      case server_local_address
      in Socket::UNIXAddress
      in Socket::IPAddress
        raise Exception.new "Server.check_destination_protection!: Establish.destinationAddress conflicts with your server address!" if InterfaceAddress.includes? ip_address: destination_address, interface_port: server_local_address.port
      in Socket::Address
      end

      raise Exception.new "Server.check_destination_protection!: Establish.destinationAddress is in your preset destinationProtection!" if destination_protection.ipAddresses.includes? destination_address
    end

    true
  end

  private def create_bind_socket(session : Session, command_type : Frames::CommandFlag, tcp_timeout : TimeOut = TimeOut.new, udp_timeout : TimeOut = TimeOut.udp_default) : Tuple(Socket::IPAddress?, Quirks::TCPBinding | Quirks::AssociateUDP)?
    case command_type
    in .tcp_connection?
    in .tcp_binding?
      create_tcp_bind_socket session: session, timeout: tcp_timeout
    in .associate_udp?
      create_udp_bind_socket session: session, timeout: udp_timeout
    end
  end

  private def create_tcp_bind_socket(session : Session, timeout : TimeOut = TimeOut.udp_default) : Tuple(Socket::IPAddress?, Quirks::TCPBinding)
    session_local_address = session.local_address rescue nil if session.responds_to? :local_address

    unless session_local_address
      send_establish_frame session: session, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
      raise Exception.new String.build { |io| io << "Server.create_tcp_bind_socket!: Failed to get client local_address." }
    end

    case session_local_address
    in Socket::UNIXAddress
      send_establish_frame session: session, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
      raise Exception.new String.build { |io| io << "Server.create_tcp_bind_socket!: Get the client local_address is UNIXAddress." }
    in Socket::IPAddress
    in Socket::Address
      send_establish_frame session: session, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
      raise Exception.new String.build { |io| io << "Server.create_tcp_bind_socket!: Get the client local_address is Address." }
    end

    socket = TCPServer.new session_local_address.address, 0_i32
    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    begin
      socket.reuse_address = true
      socket.reuse_port = true
    rescue ex
      socket.close rescue nil

      raise ex
    end

    socket = Quirks::TCPBinding.new server: socket, timeout: timeout
    Tuple.new (socket.server_local_address rescue nil), socket
  end

  private def create_udp_bind_socket(session : Session, timeout : TimeOut = TimeOut.udp_default) : Tuple(Socket::IPAddress?, Quirks::AssociateUDP)
    session_local_address = session.local_address rescue nil if session.responds_to? :local_address

    unless session_local_address
      send_establish_frame session: session, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
      raise Exception.new String.build { |io| io << "Server.create_udp_bind_socket!: Failed to get client local_address." }
    end

    case session_local_address
    in Socket::UNIXAddress
      send_establish_frame session: session, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
      raise Exception.new String.build { |io| io << "Server.create_udp_bind_socket!: Get the client local_address is UNIXAddress." }
    in Socket::IPAddress
    in Socket::Address
      send_establish_frame session: session, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
      raise Exception.new String.build { |io| io << "Server.create_udp_bind_socket!: Get the client local_address is Address." }
    end

    socket = UDPSocket.new family: session_local_address.family
    socket.read_timeout = timeout.read
    socket.write_timeout = timeout.write

    begin
      socket.bind session_local_address.address, 0_i32
      socket.reuse_address = true
      socket.reuse_port = true
    rescue ex
      socket.close rescue nil

      raise ex
    end

    socket = Quirks::AssociateUDP.new io: socket, timeout: timeout
    Tuple.new (socket.local_address rescue nil), socket
  end

  private def send_establish_frame(session : Session, status_flag : Frames::StatusFlag, destination_ip_address : Socket::IPAddress) : Bool
    frame_establish = Frames::Establish.new version: version, arType: ARType::Reply
    frame_establish.statusType = status_flag

    case destination_ip_address.family
    when .inet6?
      frame_establish.addressType = Frames::AddressFlag::Ipv6
      frame_establish.destinationIpAddress = destination_ip_address
    when .inet?
      frame_establish.addressType = Frames::AddressFlag::Ipv4
      frame_establish.destinationIpAddress = destination_ip_address
    end

    frame_establish.to_io session
    session.exchangeFrames << frame_establish

    true
  end

  private def send_establish_frame(session : Session, status_flag : Frames::StatusFlag, destination_ip_address : Nil) : Bool
    frame_establish = Frames::Establish.new version: version, arType: ARType::Reply
    frame_establish.statusType = status_flag

    frame_establish.addressType = Frames::AddressFlag::Ipv4
    frame_establish.destinationIpAddress = Socket::IPAddress.new("0.0.0.0", 0_i32)
    frame_establish.to_io session
    session.exchangeFrames << frame_establish

    true
  end

  def accept? : Session?
    return unless socket = io.accept?

    client_timeout.try do |_timeout|
      socket.read_timeout = _timeout.read if socket.responds_to? :read_timeout=
      socket.write_timeout = _timeout.write if socket.responds_to? :write_timeout=
    end

    Session.new inbound: socket, options: options
  end
end

require "./server/*"
require "./enhanced/*"
require "./quirks/*"
