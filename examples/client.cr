require "../src/socks.cr"

# Use `DNS.getaddrinfo` instead of `C.getaddrinfo`, fast and stable DNS resolver.
# DNS.cr will send and receive DNS requests in concurrent.

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), protocolType: DNS::ProtocolType::UDP
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32), protocolType: DNS::ProtocolType::TLS
dns_resolver = DNS::Resolver.new dnsServers: dns_servers

# Create SOCKS::Options.

options = SOCKS::Options.new
options.client.wrapper = SOCKS::Options::Client::Wrapper::WebSocket.new address: SOCKS::Address.new(host: "0.0.0.0", port: 1234_i32), resource: "/", headers: HTTP::Headers.new, dataRaw: nil
options.switcher.allowWebSocketKeepAlive = true
options.switcher.allowTCPBinding = true
options.switcher.allowAssociateUDP = true

# `SOCKS::Client.new` will create a socket connected to the destination address.
# Then you can add Authentication Methods, such as `UserNamePassword`.
# If you want to use websocket as a destination wrapper, you need to call upgrade_websocket.
# Then handshake, establish, you have completed all the steps.
# After finishing the job, you can call `SOCKS::Client.notify_keep_alive!` to reuse the pipeline.
# So much until it's done.

client = SOCKS::Client.new host: "0.0.0.0", port: 1234_i32, dns_resolver: dns_resolver, options: options, timeout: SOCKS::TimeOut.new

# Set TCPBinding and AssociateUDP timeout.

client.tcp_binding_timeout = SOCKS::TimeOut.new
client.associate_udp_timeout = SOCKS::TimeOut.udp_default

# Set authentication method.

client.authentication_methods = [SOCKS::Frames::AuthenticationFlag::UserNamePassword]
authenticate_frame = SOCKS::Frames::Authenticate.new version: SOCKS::Frames::VersionFlag::V5, arType: SOCKS::ARType::Ask
authenticate_frame.authenticationChoiceType = SOCKS::Frames::AuthenticationChoiceFlag::UserNamePassword
authenticate_frame.userName = "admin"
authenticate_frame.password = "abc123"
client.authenticate_frame = authenticate_frame

# Set wrapper authentication method.

client.wrapper_authorization = SOCKS::Frames::WebSocketAuthorizationFlag::Basic
authorize_frame = SOCKS::Frames::Authorize.new authorizationType: SOCKS::Frames::WebSocketAuthorizationFlag::Basic, userName: "admin", password: "abc123"
client.wrapper_authorize_frame = authorize_frame

begin
  # Upgrade outbound to WebSocket, and handshake.
  client.process_upgrade!
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
  dns_ask = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: "www.example.com", record_type: DNS::Packet::RecordFlag::A
  dns_ask.transmissionId = Random.new.rand UInt16
  client.write dns_ask.to_slice

  # Create a buffer for receiving subsequent UDP packets.
  buffer = uninitialized UInt8[4096_i32]

  # Receive 4096 Bytes, because Fragment and DNS query may be larger than 512 Bytes. (AssociateUDP).
  read_length = client.read buffer.to_slice
  memory = IO::Memory.new buffer.to_slice[0_i32, read_length]

  # Parsing Durian::Packet Response (AssociateUDP).
  STDOUT.puts [:associateUDPFirst, Time.local, (DNS::Packet.from_io protocol_type: DNS::ProtocolType::UDP, io: memory)]

  # Send Durian::Packet Query (AssociateUDP).
  dns_ask = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: "www.google.com", record_type: DNS::Packet::RecordFlag::A
  dns_ask.transmissionId = Random.new.rand UInt16
  client.write dns_ask.to_slice

  # Receive 4096 Bytes, because Fragment and DNS query may be larger than 512 Bytes. (AssociateUDP).
  read_length = client.read buffer.to_slice
  memory = IO::Memory.new buffer.to_slice[0_i32, read_length]

  # Parsing Durian::Packet Response (AssociateUDP).
  STDOUT.puts [:associateUDPLast, Time.local, (DNS::Packet.from_io protocol_type: DNS::ProtocolType::UDP, io: memory)]
rescue ex
  STDOUT.puts [ex]
end

# Never forget to close IO, otherwise it will cause socket leakage.

client.close
