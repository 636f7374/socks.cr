require "../src/socks.cr"

def create_remote_socks_client(dns_resolver : DNS::Resolver, command_flag : SOCKS::Frames::CommandFlag, destination_address : SOCKS::Address | Socket::IPAddress, outbound_timeout : SOCKS::TimeOut) : Tuple(SOCKS::Frames::Establish, SOCKS::Client)
  options = SOCKS::Options.new
  options.switcher.allowTCPBinding = true
  options.switcher.allowAssociateUDP = true
  options.switcher.allowEnhancedAssociateUDP = true
  options.session.aliveInterval = 30_i32.seconds
  options.session.udpAliveInterval = 15_i32.seconds

  authenticate_frame = SOCKS::Frames::Authenticate.new version: SOCKS::Frames::VersionFlag::V5, arType: SOCKS::ARType::Ask
  authenticate_frame.authenticationChoiceType = SOCKS::Frames::AuthenticationChoiceFlag::UserNamePassword
  authenticate_frame.userName = "admin"
  authenticate_frame.password = "abc123"

  socks_client = SOCKS::Client.new host: "0.0.0.0", port: 1234_i32, dns_resolver: dns_resolver, options: options, timeout: outbound_timeout
  socks_client.authenticate_frame = authenticate_frame
  socks_client.authentication_methods = [SOCKS::Frames::AuthenticationFlag::UserNamePassword]

  # Set wrapper authentication method.
  socks_client.wrapper = SOCKS::Options::Client::Wrapper::WebSocket.new address: SOCKS::Address.new(host: "0.0.0.0", port: 1234_i32), resource: "/", headers: HTTP::Headers.new, dataRaw: nil, enableConnectionIdentifier: true, allowConnectionReuse: true, allowConnectionPause: false, maximumSentSequence: Int8::MAX, maximumReceiveSequence: Int8::MAX
  socks_client.wrapper_authorize = SOCKS::Frames::Authorize.new authorizationType: SOCKS::Frames::WebSocketAuthorizationFlag::Basic, userName: "admin", password: "abc123"

  begin
    socks_client.process_upgrade!
    socks_client.handshake!
    remote_establish_frame = socks_client.establish! dns_resolver: dns_resolver, command_flag: command_flag, destination_address: destination_address, remote_dns_resolution: true
  rescue ex
    socks_client.close
    raise ex
  end

  Tuple.new remote_establish_frame, socks_client
end

# Use `DNS.getaddrinfo` instead of `C.getaddrinfo`, fast and stable DNS resolver.
# DNS.cr will send and receive DNS requests in concurrent.

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), timeout: DNS::TimeOut.new
dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new("8.8.4.4", 53_i32), timeout: DNS::TimeOut.new
dns_servers << DNS::Address::TLS.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32), timeout: DNS::TimeOut.new, tls: nil
dns_resolver = DNS::Resolver.new dnsServers: dns_servers

# `SOCKS::Options`, adjust the server policy.

options = SOCKS::Options.new
options.switcher.allowTCPBinding = true
options.switcher.allowAssociateUDP = true
options.switcher.allowEnhancedAssociateUDP = true
options.server.wrapper = SOCKS::Options::Server::Wrapper::WebSocket.new maximumSentSequence: Int8::MAX, maximumReceiveSequence: Int8::MAX, enableConnectionIdentifier: true, allowConnectionPause: true, allowConnectionReuse: true
options.server.pausePool = SOCKS::Options::Server::PausePool.new clearInterval: 60_i32.seconds, capacity: 128_i32, socketSwitchSeconds: 720_i32.seconds, socketSwitchBytes: 100000000_i32, socketSwitchExpression: Transfer::SocketSwitchExpressionFlag::OR
options.server.udpGateway = options_udp_gateway = SOCKS::Options::Server::UdpGateway.new listenPort: 8866_i32, externalIpv4Address: Socket::IPAddress.new(address: "127.0.0.1", port: 8866_i32), externalIpv6Address: Socket::IPAddress.new(address: "127.0.0.1", port: 8866_i32)
options.session.aliveInterval = 30_i32.seconds
options.session.udpAliveInterval = 120_i32.seconds

# Create.

udp_gateway = options_udp_gateway ? SOCKS::UdpGateway.new(listenAddress: Socket::IPAddress.new(address: "127.0.0.1", port: options_udp_gateway.listenPort)) : nil
tcp_server = TCPServer.new host: "0.0.0.0", port: 1238_i32
server = SOCKS::Server.new io: tcp_server, dnsResolver: dns_resolver, options: options, udpGateway: udp_gateway
pause_pool = SOCKS::PausePool.new clearInterval: options.server.pausePool.clearInterval, capacity: options.server.pausePool.capacity

# Set Client, Outbound Timeout.

client_timeout = SOCKS::TimeOut.new
client_timeout.read = 15_i32
client_timeout.write = 15_i32

outbound_timeout = SOCKS::TimeOut.new
outbound_timeout.read = 15_i32
outbound_timeout.write = 15_i32

server.client_timeout = client_timeout
server.outbound_timeout = outbound_timeout

# Set `SOCKS::Server.authentication`, such as (`UserNamePassword` and SOCKS::Server.on_auth).

server.authentication = SOCKS::Frames::AuthenticationFlag::UserNamePassword
server.on_auth = ->(user_name : String?, password : String?) do
  return SOCKS::Frames::PermissionFlag::Denied unless _user_name = user_name
  return SOCKS::Frames::PermissionFlag::Denied if "admin" != _user_name

  return SOCKS::Frames::PermissionFlag::Denied unless _password = password
  return SOCKS::Frames::PermissionFlag::Denied if "abc123" != _password

  SOCKS::Frames::PermissionFlag::Passed
end

server.wrapper_authorization = SOCKS::Frames::WebSocketAuthorizationFlag::Basic
server.on_wrapper_auth = ->(user_name : String?, password : String?) do
  return SOCKS::Frames::PermissionFlag::Denied unless _user_name = user_name
  return SOCKS::Frames::PermissionFlag::Denied if "admin" != _user_name

  return SOCKS::Frames::PermissionFlag::Denied unless _password = password
  return SOCKS::Frames::PermissionFlag::Denied if "abc123" != _password

  SOCKS::Frames::PermissionFlag::Passed
end

# PausePool Cleanup.

spawn do
  loop do
    pause_pool.inactive_entry_cleanup_mutex
    sleep 5_i32.seconds
  end
end

# UDPGateway Listen.

spawn do
  server.udpGateway.try &.listen
end

# Process.

loop do
  session = server.accept? rescue nil
  next unless session

  spawn do
    begin
      # Accept client.

      session.process_upgrade! server: server, pause_pool: pause_pool
      server.handshake! session: session
      raise Exception.new "Server.establish!: error!" unless local_establish_tuple = server.establish! session: session, sync_create_outbound_socket: false
      from_establish, command_flag, destination_address = local_establish_tuple

      # Create Remote SOCKS connection.

      remote_establish_frame, socks_client = create_remote_socks_client dns_resolver: dns_resolver, command_flag: command_flag,
        destination_address: destination_address, outbound_timeout: outbound_timeout

      # Process Command.

      case command_flag
      in .tcp_connection?
      in .tcp_binding?
        begin
          raise Exception.new "Session.destination is Nil!" unless source_binding = session.destination
          raise Exception.new "Session.destination is not TCPSocket!" unless source_binding.is_a? TCPSocket
          bind_destination_address = remote_establish_frame.get_destination_address
          raise Exception.new "socks_client.establish! (remote_establish_frame) destinationAddress is not Socket::IPAddress!" unless bind_destination_address.is_a? Socket::IPAddress

          destination_binding = TCPSocket.new ip_address: bind_destination_address, connect_timeout: outbound_timeout.connect
          destination_binding.read_timeout = outbound_timeout.read
          destination_binding.write_timeout = outbound_timeout.write
        rescue ex
          socks_client.close

          raise ex
        end

        socks_client.tcpForwarder = SOCKS::Layer::TCPBinding.new source: source_binding, destination: destination_binding
        session.destination = nil
      in .associate_udp?
        begin
          raise Exception.new "Session.destination is Nil!" unless session_destination = session.destination
          raise Exception.new "Session.destination is not SOCKS::Layer::AssociateUDP!" unless session_destination.is_a? SOCKS::Layer::AssociateUDP
          remote_bind_destination_address = remote_establish_frame.get_destination_address
          raise Exception.new "socks_client.establish! (remote_establish_frame) destinationAddress is not Socket::IPAddress!" unless remote_bind_destination_address.is_a? Socket::IPAddress
        rescue ex
          socks_client.close

          raise ex
        end

        session_destination.outbound_ip_address = remote_bind_destination_address
        session_destination.raw_mode = true
        session.destination = socks_client
        socks_client.udpForwarder = session_destination
      in .enhanced_associate_udp?
        begin
          raise Exception.new "Session.destination is Nil!" unless session_destination = session.destination
          raise Exception.new "Session.destination is not SOCKS::Layer::AssociateUDP!" unless session_destination.is_a? SOCKS::Layer::AssociateUDP
          remote_bind_destination_address = remote_establish_frame.get_destination_address
          raise Exception.new "socks_client.establish! (remote_establish_frame) destinationAddress is not Socket::IPAddress!" unless remote_bind_destination_address.is_a? Socket::IPAddress
          remote_forward_ip_address = remote_establish_frame.forwardIpAddress
          raise Exception.new "socks_client.establish! (remote_establish_frame) remoteForwardIpAddress is not Socket::IPAddress!" unless remote_forward_ip_address.is_a? Socket::IPAddress
        rescue ex
          socks_client.close

          raise ex
        end

        # Settings EnhancedAssociateUDP related.

        session_destination.destination_enhanced_associate_udp = true
        session_destination.outbound_ip_address = remote_bind_destination_address
        session_destination.outbound_forward_ip_address = remote_forward_ip_address

        # * Because it is Relay and not Endpoint.
        # session_destination.raw_mode = true

        session.destination = socks_client
        socks_client.udpForwarder = session_destination
      end

      # Resynchronize.

      begin
        socks_client.resynchronize command_flag: command_flag
      rescue ex
        socks_client.close

        raise ex
      end

      # Session.destination = socks_client.

      if command_flag.tcp_connection? || command_flag.tcp_binding?
        session.destination = socks_client
      end
    rescue ex
      session.connection_identifier.try { |_connection_identifier| pause_pool.remove_connection_identifier connection_identifier: _connection_identifier }
      session.source.close rescue nil
      session.destination.try &.close rescue nil
      STDOUT.puts [:EXCEPTION, ex]

      next
    end

    SOCKS::SessionProcessor.perform server: server, session: session, pause_pool: pause_pool
  end
end
