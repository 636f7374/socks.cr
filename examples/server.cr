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
options.switcher.enableConnectionIdentifier = true
options.switcher.allowConnectionPause = true
options.switcher.allowConnectionReuse = true
options.server.wrapper = SOCKS::Options::Server::Wrapper::WebSocket.new maximumSentSequence: Int8::MAX, maximumReceiveSequence: Int8::MAX
options.server.pausePool = SOCKS::Options::Server::PausePool.new clearInterval: 60_i32.seconds, capacity: 128_i32, socketSwitchSeconds: 720_i32.seconds, socketSwitchBytes: 100000000_i32, socketSwitchExpression: Transfer::SocketSwitchExpressionFlag::OR
options.session.aliveInterval = 30_i32.seconds

# Finally, you call `SOCKS::SessionProcessor.perform` to automatically process.
# This example is used to demonstrate how to use it, you can modify it as appropriate.

tcp_server = TCPServer.new host: "0.0.0.0", port: 1234_i32
server = SOCKS::Server.new io: tcp_server, dnsResolver: dns_resolver, options: options
pause_pool = SOCKS::PausePool.new clearInterval: options.server.pausePool.clearInterval, capacity: options.server.pausePool.capacity

server.associate_udp_timeout = SOCKS::TimeOut.udp_default
server.udp_outbound_timeout = SOCKS::TimeOut.udp_default

# Set TCPBinding Timeout.

tcp_binding_timeout = SOCKS::TimeOut.new
tcp_binding_timeout.read = 15_i32
tcp_binding_timeout.write = 15_i32
server.tcp_binding_timeout = tcp_binding_timeout

# Set TCPOutbound Timeout.

tcp_outbound_timeout = SOCKS::TimeOut.new
tcp_outbound_timeout.read = 15_i32
tcp_outbound_timeout.write = 15_i32
server.tcp_outbound_timeout = tcp_outbound_timeout

# Set Client Timeout.

client_timeout = SOCKS::TimeOut.new
client_timeout.read = 15_i32
client_timeout.write = 15_i32
server.client_timeout = client_timeout

# You can set `SOCKS::Server.authentication`, such as (`UserNamePassword` and SOCKS::Server.on_auth).

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

loop do
  session = server.accept? rescue nil
  next unless _session = session

  spawn do
    begin
      _session.process_upgrade! server: server, pause_pool: pause_pool
      server.handshake! session: _session
      server.establish! session: _session, sync_create_outbound_socket: (_session.outbound ? false : true)
    rescue ex
      _session.connection_identifier.try { |_connection_identifier| pause_pool.remove_connection_identifier connection_identifier: _connection_identifier }
      _session.syncCloseOutbound = true
      _session.cleanup

      next
    end

    processor = SOCKS::SessionProcessor.new session: session
    processor.perform server: server, pause_pool: pause_pool
  end
end
