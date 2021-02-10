require "../src/socks.cr"

# Use `Durian.getaddrinfo` instead of `C.getaddrinfo`, fast and stable DNS resolver.
# Durian will send and receive DNS requests in parallel.
# Especially if you enable `IpCache`, it will speed up DNS queries.

dns_servers = [] of Durian::Resolver::Server
dns_servers << Durian::Resolver::Server.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), protocol: Durian::Protocol::UDP
dns_servers << Durian::Resolver::Server.new ipAddress: Socket::IPAddress.new("8.8.4.4", 53_i32), protocol: Durian::Protocol::UDP

dns_resolver = Durian::Resolver.new dns_servers
dns_resolver.ip_cache = Durian::Cache::IPAddress.new

# `Transport::Reliable` to ensure connection stability, usually `Transport::Reliable::Half`.
# `SOCKS::Server::Options`, adjust the server policy, such as whether to allow WebSocketKeepAlive.
# Finally, you call `SOCKS::Server::Processor.perform` to automatically process.
# This example is used to demonstrate how to use it, you can modify it as appropriate.

transport_reliable = Transport::Reliable::Half
server_options = SOCKS::Server::Options.new
server_options.allowWebSocketKeepAlive = true

server = SOCKS::Server.new host: "0.0.0.0", port: 1234_i32, dns_resolver: dns_resolver, options: server_options
server.establish_tcp_outbound_timeout = SOCKS::TimeOut.new
server.establish_udp_outbound_timeout = SOCKS::TimeOut.udp_default
server.establish_tcp_bind_timeout = SOCKS::TimeOut.new
server.establish_udp_bind_timeout = SOCKS::TimeOut.udp_default
server.client_timeout = SOCKS::TimeOut.new

# You can set `SOCKS::Server.authentication`, such as (`UserNamePassword` + on_auth).

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
      _session.upgrade_websocket
      server.handshake! _session
      server.establish! _session
    rescue ex
      _session.close rescue nil

      next
    end

    unless outbound = _session.outbound
      _session.close rescue nil

      next
    end

    processor = SOCKS::Server::Processor.new session: session
    processor.perform server: server, reliable: transport_reliable
  end
end
