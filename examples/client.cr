require "../src/socks.cr"

# Use `DNS.getaddrinfo` instead of `C.getaddrinfo`, fast and stable DNS resolver.
# DNS.cr will send and receive DNS requests in concurrent.

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), timeout: DNS::TimeOut.new
dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new("8.8.4.4", 53_i32), timeout: DNS::TimeOut.new
dns_servers << DNS::Address::TLS.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32), timeout: DNS::TimeOut.new, tls: nil
dns_resolver = DNS::Resolver.new dnsServers: dns_servers

# Create SOCKS::Options.

options = SOCKS::Options.new
options.switcher.allowTCPBinding = true
options.switcher.allowAssociateUDP = true
options.switcher.allowEnhancedAssociateUDP = true

authenticate_frame = SOCKS::Frames::Authenticate.new version: SOCKS::Frames::VersionFlag::V5, arType: SOCKS::ARType::Ask
authenticate_frame.authenticationChoiceType = SOCKS::Frames::AuthenticationChoiceFlag::UserNamePassword
authenticate_frame.userName = "admin"
authenticate_frame.password = "abc123"

# `SOCKS::Client.new` will create a socket connected to the destination address.

client = SOCKS::Client.new host: "0.0.0.0", port: 1234_i32, dns_resolver: dns_resolver, options: options, timeout: SOCKS::TimeOut.new

# Set authentication method.

client.authentication_methods = [SOCKS::Frames::AuthenticationFlag::UserNamePassword]
client.authenticate_frame = authenticate_frame

# Set wrapper authentication method.

client.wrapper = SOCKS::Options::Client::Wrapper::WebSocket.new address: SOCKS::Address.new(host: "0.0.0.0", port: 1234_i32), resource: "/", headers: HTTP::Headers.new, dataRaw: nil, enableConnectionIdentifier: true, allowConnectionReuse: true, allowConnectionPause: true, maximumSentSequence: Int8::MAX, maximumReceiveSequence: Int8::MAX
client.wrapper_authorize = SOCKS::Frames::Authorize.new authorizationType: SOCKS::Frames::WebSocketAuthorizationFlag::Basic, userName: "admin", password: "abc123"

begin
  # Upgrade outbound to WebSocket, and handshake.

  client.process_upgrade!
  client.handshake!

  #
  #
  #
  #
  # TCPConnection
  #
  #
  #
  #
  #

  # Establish a TCPConnection to example.com through outbound.

  client.establish! dns_resolver: dns_resolver, command_flag: SOCKS::Frames::CommandFlag::TCPConnection, host: "example.com", port: 80_i32, remote_dns_resolution: true
  client.resynchronize command_flag: SOCKS::Frames::CommandFlag::TCPConnection

  # Send HTTP::Request (TCPConnection)

  http_request = HTTP::Request.new "GET", "http://www.example.com"
  http_request.headers.add "Host", "www.example.com"
  http_request.to_io io: client

  # Receive HTTP::Client::Response (TCPConnection)

  http_response = HTTP::Client::Response.from_io io: client # <=== <Transfer::TerminateConnection:Enhanced::State::WebSocket.synchronize: Received Ping CommandFlag::CONNECTION_REUSE from io.
  STDOUT.puts [:TCPConnection, Time.local, http_response]

  # Use WebSocket Enhanced KeepAlive to tell the peer to terminate the destination connection.

  STDOUT.puts [:ConnectionReuse, Time.local, client.notify_peer_negotiate(source: STDOUT, command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE)]

  #
  #
  #
  #
  # TCPBinding
  #
  #
  #
  #
  #

  # Establish a TCPBinding to example.com through outbound.

  tcp_binding_from_establish = client.establish! dns_resolver: dns_resolver, command_flag: SOCKS::Frames::CommandFlag::TCPBinding, host: "example.com", port: 80_i32, remote_dns_resolution: true
  raise Exception.new "client.establish! TCPBinding establish_frame is Nil!" unless _tcp_binding_from_establish = tcp_binding_from_establish
  raise Exception.new "client.establish! TCPBinding establish_frame is not SOCKS::Frames::Establish!" unless _tcp_binding_from_establish.is_a? SOCKS::Frames::Establish

  from_establish_destination_address = _tcp_binding_from_establish.get_destination_address
  tcp_binding_socket = SOCKS.create_outbound_socket command_flag: SOCKS::Frames::CommandFlag::TCPConnection, destination_address: from_establish_destination_address, dns_resolver: dns_resolver, tcp_timeout: SOCKS::TimeOut.new
  incoming_establish = client.resynchronize command_flag: SOCKS::Frames::CommandFlag::TCPBinding

  100.times do
    # Send HTTP::Request (TCPBinding)

    http_request = HTTP::Request.new "GET", "http://www.example.com"
    http_request.headers.add "Host", "www.example.com"
    http_request.to_io io: client

    # Receive HTTP::Request (TCPBinding)

    http_response = HTTP::Request.from_io io: tcp_binding_socket
    STDOUT.puts [:TCPBinding, Time.local, http_response]
  end

  # Send HTTP::Request (TCPBinding)

  http_request = HTTP::Request.new "GET", "http://www.example.com"
  http_request.headers.add "Host", "www.example.com"
  http_request.to_io io: tcp_binding_socket

  # Receive HTTP::Request (TCPBinding)

  http_response = HTTP::Request.from_io io: client
  STDOUT.puts [:TCPBinding, Time.local, http_response]

  # Use WebSocket Enhanced KeepAlive to tell the peer to terminate the destination connection.

  STDOUT.puts [:ConnectionReuse, Time.local, client.notify_peer_negotiate(source: STDOUT, command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE)]

  #
  #
  #
  #
  # AssociateUDP
  #
  #
  #
  #
  #

  # Establish a AssociateUDP to example.com through outbound.

  associate_udp_from_establish = client.establish! dns_resolver: dns_resolver, command_flag: SOCKS::Frames::CommandFlag::AssociateUDP, host: "8.8.8.8", port: 53_i32, remote_dns_resolution: true
  raise Exception.new "client.establish! AssociateUDP establish_frame is Nil!" unless _associate_udp_from_establish = associate_udp_from_establish
  raise Exception.new "client.establish! AssociateUDP establish_frame is not SOCKS::Frames::Establish!" unless _associate_udp_from_establish.is_a? SOCKS::Frames::Establish
  raise Exception.new "client.establish! AssociateUDP destinationIpAddress is Nil!" unless _associate_udp_from_establish_destination_ip_address = _associate_udp_from_establish.destinationIpAddress
  client.resynchronize command_flag: SOCKS::Frames::CommandFlag::EnhancedAssociateUDP

  # Create a buffer for receiving subsequent UDP packets.

  buffer = uninitialized UInt8[4096_i32]

  # Create UDP Socket.

  associate_udp = UDPSocket.new

  {"twitter.com", "example.com", "google.com"}.each_with_index do |domain, index|
    # Create DNS Packet Query (AssociateUDP).

    dns_ask = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: domain, record_type: DNS::Packet::RecordFlag::A
    dns_ask.transmissionId = Random.new.rand type: UInt16

    # Send DNS Packet Query (AssociateUDP) & Receive 4096 Bytes, because Fragment and DNS query may be larger than 512 Bytes. (AssociateUDP).

    STDOUT.puts [:DDD, _associate_udp_from_establish_destination_ip_address]
    associate_udp.send message: dns_ask.to_slice, to: _associate_udp_from_establish_destination_ip_address
    received_length, ip_address = associate_udp.receive message: buffer.to_slice

    # Decode DNS Packet Response (AssociateUDP).

    STDOUT.puts [:AssociateUDP, index, Time.local, DNS::Packet.from_slice(protocol_type: DNS::ProtocolType::UDP, slice: buffer.to_slice[0_i32, received_length])]
  end

  #
  #
  #
  #
  #
  #
  #
  #
  #
  #

  # Use WebSocket Enhanced KeepAlive to tell the peer to terminate the destination connection.

  STDOUT.puts [:ConnectionReuse, Time.local, client.notify_peer_negotiate(source: STDOUT, command_flag: SOCKS::Enhanced::CommandFlag::CONNECTION_REUSE)]
rescue ex
  STDOUT.puts [:EXCEPTION, ex, ex.backtrace?]
end

# Never forget to close IO, otherwise it will cause socket leakage.

client.close
