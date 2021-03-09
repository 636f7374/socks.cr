require "../src/socks.cr"

# Use `DNS.getaddrinfo` instead of `C.getaddrinfo`, fast and stable DNS resolver.
# DNS.cr will send and receive DNS requests in concurrent.

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), protocolType: DNS::ProtocolType::UDP
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32), protocolType: DNS::ProtocolType::TLS
dns_resolver = DNS::Resolver.new dnsServers: dns_servers

# `SOCKS::Server::Options`, adjust the server policy, such as whether to allow WebSocketKeepAlive.
# Finally, you call `SOCKS::SessionProcessor.perform` to automatically process.
# This example is used to demonstrate how to use it, you can modify it as appropriate.

options = SOCKS::Options.new
options.server.allowWebSocketKeepAlive = true
options.server.wrapper = SOCKS::Options::Server::Wrapper::WebSocket.new

tcp_server = TCPServer.new host: "0.0.0.0", port: 1234_i32
server = SOCKS::Server.new io: tcp_server, dnsResolver: dns_resolver, options: options

server.tcp_outbound_timeout = SOCKS::TimeOut.new
server.udp_outbound_timeout = SOCKS::TimeOut.udp_default
server.tcp_binding_timeout = SOCKS::TimeOut.new
server.associate_udp_timeout = SOCKS::TimeOut.udp_default
server.client_timeout = SOCKS::TimeOut.new

# You can set `SOCKS::Server.authentication`, such as (`UserNamePassword` and SOCKS::Server.on_auth).

server.authentication = SOCKS::Frames::AuthenticationFlag::UserNamePassword
server.on_auth = ->(user_name : String?, password : String?) do
  return SOCKS::Frames::PermissionFlag::Denied unless _user_name = user_name
  return SOCKS::Frames::PermissionFlag::Denied if "admin" != _user_name

  return SOCKS::Frames::PermissionFlag::Denied unless _password = password
  return SOCKS::Frames::PermissionFlag::Denied if "abc123" != _password

  SOCKS::Frames::PermissionFlag::Passed
end

loop do
  session = server.accept? rescue nil
  next unless _session = session

  spawn do
    begin
      _session.process_upgrade!
      server.handshake! _session
      server.establish! _session
    rescue ex
      _session.close rescue nil

      next
    end

    processor = SOCKS::SessionProcessor.new session: session
    processor.perform server: server
  end
end
