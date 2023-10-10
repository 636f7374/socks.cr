require "../src/socks.cr"

# Use `DNS.getaddrinfo` instead of `C.getaddrinfo`, fast and stable DNS resolver.
# DNS.cr will send and receive DNS requests in concurrent.

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), timeout: DNS::TimeOut.new
dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new("8.8.4.4", 53_i32), timeout: DNS::TimeOut.new
dns_servers << DNS::Address::TLS.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32), timeout: DNS::TimeOut.new, tls: nil
dns_resolver = DNS::Resolver.new dnsServers: dns_servers

# `SOCKS::Options`, adjust the server policy, such as whether to allow WebSocketKeepAlive.

options = SOCKS::Options.new
options.switcher.allowTCPBinding = true
options.switcher.allowAssociateUDP = true
options.switcher.allowEnhancedAssociateUDP = true
options.server.wrapper = SOCKS::Options::Server::Wrapper::WebSocket.new maximumSentSequence: Int8::MAX, maximumReceiveSequence: Int8::MAX, enableConnectionIdentifier: true, allowConnectionPause: true, allowConnectionReuse: true
options.server.pausePool = SOCKS::Options::Server::PausePool.new clearInterval: 60_i32.seconds, capacity: 128_i32, socketSwitchSeconds: 720_i32.seconds, socketSwitchBytes: 100000000_i32, socketSwitchExpression: Transfer::SocketSwitchExpressionFlag::OR
options.server.udpGateway = options_udp_gateway = SOCKS::Options::Server::UdpGateway.new listenPort: 8877_i32, externalIpv4Address: Socket::IPAddress.new(address: "127.0.0.1", port: 8877_i32), externalIpv6Address: Socket::IPAddress.new(address: "127.0.0.1", port: 8877_i32)
options.server.udpRelay = SOCKS::Options::Server::UdpRelay.new externalIpv4Address: Socket::IPAddress.new(address: "127.0.0.1", port: 0_i32), externalIpv6Address: Socket::IPAddress.new(address: "127.0.0.1", port: 0_i32)
options.server.tcpBinding = SOCKS::Options::Server::TcpBinding.new externalIpv4Address: Socket::IPAddress.new(address: "127.0.0.1", port: 0_i32), externalIpv6Address: Socket::IPAddress.new(address: "127.0.0.1", port: 0_i32)
options.session.aliveInterval = 15_i32.seconds
options.session.udpAliveInterval = 120_i32.seconds

# Finally, you call `SOCKS::SessionProcessor.perform` to automatically process.
# This example is used to demonstrate how to use it, you can modify it as appropriate.

udp_gateway = options_udp_gateway ? SOCKS::UdpGateway.new(listenAddress: Socket::IPAddress.new(address: "0.0.0.0", port: options_udp_gateway.listenPort)) : nil
tcp_server = TCPServer.new host: "0.0.0.0", port: 1234_i32
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

spawn do
  loop do
    pause_pool.inactive_entry_cleanup_mutex
    sleep 5_i32.seconds
  end
end

spawn do
  server.udpGateway.try &.listen
end

loop do
  session = server.accept? rescue nil
  next unless session

  spawn do
    begin
      session.process_upgrade! server: server, pause_pool: pause_pool
      server.handshake! session: session
      STDOUT.puts [:ESTABLISH, server.establish!(session: session, sync_create_outbound_socket: (session.destination ? false : true))]
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
