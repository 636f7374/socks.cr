require "../src/socks.cr"

# Use `Durian.getaddrinfo` instead of `C.getaddrinfo`, fast and stable DNS resolver.
# Durian will send and receive DNS requests in parallel.
# Especially if you enable `IpCache`, it will speed up DNS queries.

dns_servers = [] of Durian::Resolver::Server
dns_servers << Durian::Resolver::Server.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), protocol: Durian::Protocol::UDP
dns_servers << Durian::Resolver::Server.new ipAddress: Socket::IPAddress.new("8.8.4.4", 53_i32), protocol: Durian::Protocol::UDP

dns_resolver = Durian::Resolver.new dns_servers
dns_resolver.ip_cache = Durian::Cache::IPAddress.new

# `SOCKS::Client.new` will create a socket connected to the destination address.
# Then you can add Authentication Methods, such as `UserNamePassword`.
# If you want to use websocket as a destination wrapper, you need to call upgrade_websocket.
# Then handshake, establish, you have completed all the steps.
# After finishing the job, you can call `SOCKS::Client.notify_keep_alive!` to reuse the pipeline.
# So much until it's done.

client = SOCKS::Client.new host: "0.0.0.0", port: 1234_i32, dns_resolver: dns_resolver

client.authentication_methods = [SOCKS::Frames::AuthenticationFlag::UserNamePassword]
authenticate_frame = SOCKS::Frames::Authenticate.new version: SOCKS::Frames::VersionFlag::V5, arType: SOCKS::ARType::Ask
authenticate_frame.authenticationChoiceType = SOCKS::Frames::AuthenticationChoiceFlag::UserNamePassword
authenticate_frame.userName = "admin"
authenticate_frame.password = "abc123"
client.authenticate_frame = authenticate_frame

begin
  # Upgrade outbound to WebSocket, and handshake.
  client.upgrade_websocket host: "0.0.0.0", port: 1234_i32, path: "/"
  client.handshake!

  # Establish a TCPConnection to example.com through outbound.
  client.establish! command_type: SOCKS::Frames::CommandFlag::TCPConnection, host: "example.com", port: 80_i32, remote_dns_resolution: true

  # Send HTTP::Request (TCPConnection)
  http_request = HTTP::Request.new "GET", "http://www.example.com"
  http_request.headers.add "Host", "www.example.com"
  http_request.to_io io: client

  # Receive HTTP::Client::Response (TCPConnection)
  http_response = HTTP::Client::Response.from_io io: client
  STDOUT.puts [:tcpConnection, Time.local, http_response]

  # Use WebSocket Enhanced KeepAlive to tell the peer to terminate the destination connection.
  STDOUT.puts [:keepAlive, Time.local, client.notify_keep_alive!]

  # Establish a TCPBinding to example.com through outbound.
  client.establish! command_type: SOCKS::Frames::CommandFlag::TCPBinding, host: "example.com", port: 80_i32, remote_dns_resolution: true

  # Send HTTP::Request (TCPBinding)
  http_request = HTTP::Request.new "GET", "http://www.example.com"
  http_request.headers.add "Host", "www.example.com"
  http_request.to_io io: client

  # Receive HTTP::Client::Response (TCPBinding)
  http_response = HTTP::Client::Response.from_io io: client
  STDOUT.puts [:tcpBinding, Time.local, http_response]

  # Use WebSocket Enhanced KeepAlive to tell the peer to terminate the destination connection.
  STDOUT.puts [:keepAlive, Time.local, client.notify_keep_alive!]

  # Establish a AssociateUDP to example.com through outbound.
  client.establish! command_type: SOCKS::Frames::CommandFlag::AssociateUDP, host: "8.8.8.8", port: 53_i32, remote_dns_resolution: true

  # Send Durian::Packet Query (AssociateUDP).
  dns_request = Durian::Packet.new Durian::Protocol::UDP, Durian::Packet::QRFlag::Query
  dns_request.add_query "www.example.com", Durian::RecordFlag::A
  client.write dns_request.to_slice

  # Create a buffer for receiving subsequent UDP packets.
  buffer = uninitialized UInt8[4096_i32]

  # Receive 4096 Bytes, because Fragment and DNS query may be larger than 512 Bytes. (AssociateUDP).
  read_length = client.read buffer.to_slice
  memory = IO::Memory.new buffer.to_slice[0_i32, read_length]

  # Parsing Durian::Packet Response (AssociateUDP).
  STDOUT.puts [:associateUDPFirst, Time.local, (Durian::Packet.from_io! protocol: Durian::Protocol::UDP, io: memory)]

  # Send Durian::Packet Query (AssociateUDP).
  dns_request = Durian::Packet.new Durian::Protocol::UDP, Durian::Packet::QRFlag::Query
  dns_request.add_query "www.google.com", Durian::RecordFlag::A
  client.write dns_request.to_slice

  # Receive 4096 Bytes, because Fragment and DNS query may be larger than 512 Bytes. (AssociateUDP).
  read_length = client.read buffer.to_slice
  memory = IO::Memory.new buffer.to_slice[0_i32, read_length]

  # Parsing Durian::Packet Response (AssociateUDP).
  STDOUT.puts [:associateUDPLast, Time.local, (Durian::Packet.from_io! protocol: Durian::Protocol::UDP, io: memory)]
rescue ex
  STDOUT.puts [ex]
end

# Never forget to close IO, otherwise it will cause socket leakage.

client.close
