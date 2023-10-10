class SOCKS::Server
  getter io : Socket::Server
  getter dnsResolver : DNS::Resolver?
  getter options : Options
  getter udpGateway : UdpGateway?

  def initialize(@io : Socket::Server, @dnsResolver : DNS::Resolver?, @options : Options = Options.new, @udpGateway : UdpGateway? = nil)
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

  def wrapper_authorization=(value : Frames::WebSocketAuthorizationFlag)
    @wrapperAuthorization = value
  end

  def wrapper_authorization
    @wrapperAuthorization
  end

  def on_wrapper_auth=(value : Proc(String?, String?, Frames::PermissionFlag))
    @onWrapperAuth = value
  end

  def on_wrapper_auth
    @onWrapperAuth
  end

  def client_timeout=(value : TimeOut)
    @clientTimeOut = value
  end

  def client_timeout
    @clientTimeOut ||= TimeOut.new
  end

  def outbound_timeout=(value : TimeOut)
    @outboundTimeOut = value
  end

  def outbound_timeout
    @outboundTimeOut ||= TimeOut.new
  end

  def handshake!(session : Session) : Bool
    from_negotiate = Frames::Negotiate.from_io io: session.source, ar_type: ARType::Ask, version_flag: version
    raise Exception.new "Server.handshake!: Frames::Negotiate.methodCount cannot be Nil!" unless _negotiate_method_count = from_negotiate.methodCount
    raise Exception.new "Server.handshake!: Frames::Negotiate.methods cannot be Nil!" unless _negotiate_methods = from_negotiate.methods
    raise Exception.new "Server.handshake!: Frames::Negotiate.methods cannot be empty!" unless _negotiate_methods_first = _negotiate_methods.first?

    _negotiate_authenticate_frame = from_negotiate.authenticateFrame

    unless _negotiate_methods.includes? authentication
      frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
      frame_negotiate.acceptedMethod = Frames::AuthenticationFlag::NoAcceptableMethods
      frame_negotiate.to_io io: session.source

      raise Exception.new String.build { |io| io << "Server.handshake!: The authentication method requested by the client (" << _negotiate_methods.to_s << ") " << "is inconsistent with the authentication method set by the server (" << authentication.to_s << ")." }
    end

    if _negotiate_authenticate_frame && (1_i32 == _negotiate_methods.size) && _negotiate_methods_first.user_name_password?
      frame_authenticate = Frames::Authenticate.new version: version, arType: ARType::Reply
      frame_authenticate.authenticationChoiceType = Frames::AuthenticationChoiceFlag::UserNamePassword
      frame_authenticate.permissionType = on_auth.try &.call(_negotiate_authenticate_frame.userName, _negotiate_authenticate_frame.password) || Frames::PermissionFlag::Passed

      frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
      frame_negotiate.authenticateFrame = frame_authenticate
      frame_negotiate.acceptedMethod = authentication
      frame_negotiate.to_io io: session.source

      return true
    end

    if authentication.user_name_password?
      reply_frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
      reply_frame_negotiate.acceptedMethod = authentication
      reply_frame_negotiate.to_io io: session.source

      from_authentication = Frames::Authenticate.from_io io: session.source, ar_type: ARType::Ask, version_flag: version
      raise Exception.new "Server.handshake!: Frames::Authenticate.authenticationChoiceType cannot be Nil!" unless authentication_choice_type = from_authentication.authenticationChoiceType
      raise Exception.new "Server.handshake!: The authenticationChoiceType provided by the client Authentication is inconsistent with the authenticationChoiceType provided by the client Negotiate." unless authentication_choice_type.user_name_password?

      frame_authenticate = Frames::Authenticate.new version: version, arType: ARType::Reply
      frame_authenticate.authenticationChoiceType = Frames::AuthenticationChoiceFlag::UserNamePassword
      frame_authenticate.permissionType = on_auth.try &.call(from_authentication.userName, from_authentication.password) || Frames::PermissionFlag::Passed
      frame_authenticate.to_io io: session.source

      return true
    end

    if authentication.no_authentication?
      reply_frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
      reply_frame_negotiate.acceptedMethod = authentication
      reply_frame_negotiate.to_io io: session.source

      return true
    end

    reply_frame_negotiate = Frames::Negotiate.new version: version, arType: ARType::Reply
    reply_frame_negotiate.acceptedMethod = Frames::AuthenticationFlag::NoAcceptableMethods
    reply_frame_negotiate.to_io io: session.source

    raise Exception.new "Server.handshake: Unsupported authentication method or client authentication method is inconsistent with the authentication method preset by the server"
  end

  def establish!(session : Session, start_immediately : Bool = true, sync_create_outbound_socket : Bool = true) : Tuple(Frames::Establish, Frames::CommandFlag, Address | Socket::IPAddress)
    from_establish = Frames::Establish.from_io io: session.source, ar_type: ARType::Ask, version_flag: version
    raise Exception.new "Server.establish!: Establish.commandType cannot be Nil!" unless command_flag = from_establish.commandType
    raise Exception.new "Server.establish!: Establish.destinationAddress or destinationIpAddress cannot be Nil!" unless destination_address = from_establish.get_destination_address

    return Tuple.new from_establish, command_flag, destination_address unless start_immediately
    establish! session: session, from_establish: from_establish, sync_create_outbound_socket: sync_create_outbound_socket

    Tuple.new from_establish, command_flag, destination_address
  end

  def establish!(session : Session, from_establish : Frames::Establish, sync_create_outbound_socket : Bool = true) : Bool
    session_source = session.source

    begin
      raise Exception.new "Server.establish!: Establish.commandType cannot be Nil!" unless command_flag = from_establish.commandType
      raise Exception.new "Server.establish!: Establish.destinationAddress or destinationIpAddress cannot be Nil!" unless destination_address = from_establish.get_destination_address
      raise Exception.new "Server.establish!: Server.dnsResolver is Nil!" unless dns_resolver = dnsResolver
    rescue ex
      send_establish_frame session: session, command_flag: nil, status_flag: Frames::StatusFlag::ConnectionDenied, destination_ip_address: nil
      raise ex
    end

    # Check if Options::Server accept TCPBinding or AssociateUDP.

    case command_flag
    in .tcp_connection?
    in .tcp_binding?
      unless options.switcher.allowTCPBinding
        send_establish_frame session: session, command_flag: command_flag, status_flag: Frames::StatusFlag::UnsupportedCommand, destination_ip_address: nil
        raise Exception.new "Because you have disabled Options::Switcher.allowTCPBinding, this client connection is rejected (UnsupportedCommand)."
      end
    in .associate_udp?
      unless options.switcher.allowAssociateUDP
        send_establish_frame session: session, command_flag: command_flag, status_flag: Frames::StatusFlag::UnsupportedCommand, destination_ip_address: nil
        raise Exception.new "Because you have disabled Options::Switcher.allowAssociateUDP, this client connection is rejected (UnsupportedCommand)."
      end
    in .enhanced_associate_udp?
      unless options.switcher.allowEnhancedAssociateUDP
        send_establish_frame session: session, command_flag: command_flag, status_flag: Frames::StatusFlag::UnsupportedCommand, destination_ip_address: nil
        raise Exception.new "Because you have disabled Options::Switcher.allowEnhancedAssociateUDP, this client connection is rejected (UnsupportedCommand)."
      end
    end

    # Create Outbound & Bind Socket.

    if command_flag.tcp_connection?
      if sync_create_outbound_socket
        begin
          outbound_socket = SOCKS.create_outbound_socket command_flag: command_flag, destination_address: destination_address, dns_resolver: dns_resolver, tcp_timeout: outbound_timeout

          session.destination = outbound_socket
          outbound_socket_remote_address = outbound_socket.remote_address rescue nil
        rescue ex
          send_establish_frame session: session, command_flag: command_flag, status_flag: Frames::StatusFlag::ConnectFailed, destination_ip_address: nil
          raise Exception.new String.build { |io| io << "Server.establish!: " << ex.message << '.' }
        end
      end

      # Send Establish Status

      status_flag = Frames::StatusFlag::IndicatesSuccess
      outbound_socket_remote_address = Socket::IPAddress.new(address: "0.0.0.0", port: 0_i32) unless sync_create_outbound_socket
      status_flag = Frames::StatusFlag::NetworkUnreachable unless outbound_socket_remote_address

      send_establish_frame session: session, command_flag: command_flag, status_flag: status_flag, destination_ip_address: outbound_socket_remote_address
    else
      if command_flag.associate_udp? || command_flag.enhanced_associate_udp?
        if check_udp_gateway_destination_address_conflict? destination_address: destination_address
          send_establish_frame session: session, command_flag: command_flag, status_flag: Frames::StatusFlag::ConnectionDenied, destination_ip_address: nil
          raise Exception.new "Server.establish!: destination_address conflicts with local UdpGateway address!"
        end
      end

      begin
        bind_socket_local_address, bind_socket = SOCKS.create_bind_socket dns_resolver: dns_resolver, session: session, command_flag: command_flag, destination_address: destination_address, tcp_timeout: outbound_timeout
        session.destination = bind_socket
      rescue ex
        send_establish_frame session: session, command_flag: command_flag, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
        raise Exception.new "Server.establish!: Bind local address failed!"
      end

      # Send Establish Status

      case command_flag
      in .tcp_connection?
      in .tcp_binding?
        raise Exception.new "Server.establish!: Server.create_bind_socket (TCPBinding) type is not TCPServer." unless bind_socket.is_a? TCPServer
        raise Exception.new "Server.establish!: commandType is TCPBinding, but Session.source.remote_address is Nil!" unless session_source.responds_to? :remote_address
        session_source_remote_address = session_source.remote_address
        raise Exception.new "Server.establish!: commandType is TCPBinding, but Session.source.remote_address is not Socket::IPAddress!" unless session_source_remote_address.is_a? Socket::IPAddress
        raise Exception.new "Server.establish!: commandType is TCPBinding, but options.server.tcpBinding is Nil!" unless options_tcp_binding = options.server.tcpBinding
        status_flag = Frames::StatusFlag::IndicatesSuccess

        if session_source_remote_address.link_local? || session_source_remote_address.loopback? || session_source_remote_address.private?
          tcp_binding_server_external_ip_address = bind_socket_local_address
        else
          tcp_binding_server_external_ip_address = case bind_socket_local_address.family
                                                   when .inet?
                                                     raise Exception.new "Server.establish!: commandType is TCPBinding, but options.server.tcpBinding.externalIpv4Address is Nil!" unless tcp_binding_external_ipv4_address = options_tcp_binding.externalIpv4Address
                                                     Socket::IPAddress.new address: tcp_binding_external_ipv4_address.address, port: bind_socket_local_address.port
                                                   else
                                                     raise Exception.new "Server.establish!: commandType is TCPBinding, but options.server.tcpBinding.externalIpv6Address is Nil!" unless tcp_binding_external_ipv6_address = options_tcp_binding.externalIpv6Address
                                                     Socket::IPAddress.new address: tcp_binding_external_ipv6_address.address, port: bind_socket_local_address.port
                                                   end
        end

        spawn do
          sleep 0.1_f32.seconds
          send_establish_frame session: session, command_flag: command_flag, status_flag: status_flag, destination_ip_address: tcp_binding_server_external_ip_address
        end

        begin
          accepted_bind_socket = bind_socket.accept
          accepted_bind_socket.read_timeout = outbound_timeout.read
          accepted_bind_socket.write_timeout = outbound_timeout.write

          bind_socket.close rescue nil
          session.destination = accepted_bind_socket
        rescue ex
          send_establish_frame session: session, command_flag: command_flag, status_flag: Frames::StatusFlag::TTLTimeOut, destination_ip_address: nil

          raise ex
        end

        begin
          accepted_bind_socket_remote_address = accepted_bind_socket.remote_address
          send_establish_frame session: session, command_flag: command_flag, status_flag: status_flag, destination_ip_address: accepted_bind_socket_remote_address
        rescue ex
          send_establish_frame session: session, command_flag: command_flag, status_flag: Frames::StatusFlag::NetworkUnreachable, destination_ip_address: nil
          raise Exception.new "Server.establish!: Failed to get Bind.accept local address!"
        end
      in .associate_udp?
        raise Exception.new "Server.establish!: commandType is AssociateUDP, but Session.source.remote_address is Nil!" unless session_source.responds_to? :remote_address
        session_source_remote_address = session_source.remote_address
        raise Exception.new "Server.establish!: commandType is AssociateUDP, but Session.source.remote_address is not Socket::IPAddress!" unless session_source_remote_address.is_a? Socket::IPAddress
        raise Exception.new "Server.establish!: commandType is AssociateUDP, but options.server.udpRelay is Nil!" unless options_udp_relay = options.server.udpRelay
        raise Exception.new "Server.establish!: Server.create_bind_socket type is not Layer::AssociateUDP." unless bind_socket.is_a? Layer::AssociateUDP
        status_flag = Frames::StatusFlag::IndicatesSuccess
        bind_socket.raw_mode = true

        if session_source_remote_address.link_local? || session_source_remote_address.loopback? || session_source_remote_address.private?
          udp_relay_external_ip_address = bind_socket_local_address
        else
          udp_relay_external_ip_address = case bind_socket_local_address.family
                                          when .inet?
                                            raise Exception.new "Server.establish!: commandType is AssociateUDP, but options.server.udpRelay.externalIpv4Address is Nil!" unless udp_relay_external_ipv4_address = options_udp_relay.externalIpv4Address
                                            Socket::IPAddress.new address: udp_relay_external_ipv4_address.address, port: bind_socket_local_address.port
                                          else
                                            raise Exception.new "Server.establish!: commandType is AssociateUDP, but options.server.udpRelay.externalIpv6Address is Nil!" unless udp_relay_external_ipv6_address = options_udp_relay.externalIpv6Address
                                            Socket::IPAddress.new address: udp_relay_external_ipv6_address.address, port: bind_socket_local_address.port
                                          end
        end

        send_establish_frame session: session, command_flag: command_flag, status_flag: status_flag, destination_ip_address: udp_relay_external_ip_address
      in .enhanced_associate_udp?
        raise Exception.new "Server.establish!: commandType is EnhancedAssociateUDP, but Session.source.remote_address is Nil!" unless session_source.responds_to? :remote_address
        session_source_remote_address = session_source.remote_address
        raise Exception.new "Server.establish!: commandType is AssociateUDP, but Session.source.remote_address is not Socket::IPAddress!" unless session_source_remote_address.is_a? Socket::IPAddress
        raise Exception.new "Server.establish!: commandType is EnhancedAssociateUDP, but options.server.udpGateway is Nil!" unless options_udp_gateway = options.server.udpGateway
        raise Exception.new "Server.establish!: Server.create_bind_socket type is not Layer::AssociateUDP." unless bind_socket.is_a? Layer::AssociateUDP
        status_flag = Frames::StatusFlag::IndicatesSuccess

        udp_gateway_external_ip_address = case bind_socket_local_address.family
                                          when .inet?
                                            raise Exception.new "Server.establish!: commandType is EnhancedAssociateUDP, but options.server.udpGateway.externalIpv4Address is Nil!" unless udp_gateway_external_ipv4_address = options_udp_gateway.externalIpv4Address
                                            udp_gateway_external_ipv4_address
                                          else
                                            raise Exception.new "Server.establish!: commandType is EnhancedAssociateUDP, but options.server.udpGateway.externalIpv6Address is Nil!" unless udp_gateway_external_ipv6_address = options_udp_gateway.externalIpv6Address
                                            udp_gateway_external_ipv6_address
                                          end

        if session_source_remote_address.link_local? || session_source_remote_address.loopback? || session_source_remote_address.private?
          udp_gateway_external_ip_address = Socket::IPAddress.new address: bind_socket_local_address.address, port: udp_gateway_external_ip_address.port
        end

        send_establish_frame session: session, command_flag: command_flag, status_flag: status_flag, destination_ip_address: udp_gateway_external_ip_address, forward_ip_address: bind_socket_local_address
      end
    end

    true
  end

  private def check_udp_gateway_destination_address_conflict?(destination_address : Socket::IPAddress | Address) : Bool
    return false if destination_address.is_a? Address
    return false unless options_udp_gateway = options.server.udpGateway

    destination_address_local = destination_address.link_local? || destination_address.loopback? || destination_address.private? || destination_address.unspecified?
    return false unless destination_address_local

    case destination_address.family
    when .inet?
      return false unless udp_gateway_external_ipv4_address = options_udp_gateway.externalIpv4Address
      destination_address.port == udp_gateway_external_ipv4_address.port
    when .inet6?
      return false unless udp_gateway_external_ipv6_address = options_udp_gateway.externalIpv6Address
      destination_address.port == udp_gateway_external_ipv6_address.port
    else
      false
    end
  end

  private def send_establish_frame(session : Session, command_flag : Frames::CommandFlag?, status_flag : Frames::StatusFlag, destination_ip_address : Socket::IPAddress, forward_ip_address : Socket::IPAddress? = nil) : Bool
    frame_establish = Frames::Establish.new version: version, arType: ARType::Reply
    frame_establish.statusType = status_flag
    frame_establish.commandType = command_flag

    case destination_ip_address.family
    when .inet6?
      frame_establish.addressType = Frames::AddressFlag::Ipv6
      frame_establish.destinationIpAddress = destination_ip_address
    when .inet?
      frame_establish.addressType = Frames::AddressFlag::Ipv4
      frame_establish.destinationIpAddress = destination_ip_address
    end

    frame_establish.forwardIpAddress = forward_ip_address
    frame_establish.to_io io: session.source

    true
  end

  def send_establish_frame(session : Session, command_flag : Frames::CommandFlag?, status_flag : Frames::StatusFlag, destination_ip_address : Nil, forward_ip_address : Socket::IPAddress? = nil) : Bool
    frame_establish = Frames::Establish.new version: version, arType: ARType::Reply
    frame_establish.statusType = status_flag
    frame_establish.commandType = command_flag

    frame_establish.addressType = Frames::AddressFlag::Ipv4
    frame_establish.destinationIpAddress = Socket::IPAddress.new address: "0.0.0.0", port: 0_i32

    frame_establish.forwardIpAddress = forward_ip_address
    frame_establish.to_io io: session.source

    true
  end

  def accept? : Session?
    return unless socket = io.accept?
    socket.sync = true if socket.responds_to? :sync=

    client_timeout.try do |_timeout|
      socket.read_timeout = _timeout.read if socket.responds_to? :read_timeout=
      socket.write_timeout = _timeout.write if socket.responds_to? :write_timeout=
    end

    if socket.is_a? OpenSSL::SSL::Socket::Server
      begin
        socket.accept
      rescue ex
        return
      end
    end

    Session.new options: options, source: socket
  end
end

require "./enhanced/*"
require "./layer/*"
