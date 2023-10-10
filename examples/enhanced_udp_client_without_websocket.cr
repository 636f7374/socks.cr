require "../src/socks.cr"

def do_something(udp_from_establish_destination_ip_address : Socket::IPAddress, udp_from_establish_forward_ip_address : Socket::IPAddress)
  # Create a buffer for receiving subsequent UDP packets.

  buffer = uninitialized UInt8[4096_i32]

  # Create UDP Socket.

  associate_udp = UDPSocket.new

  # Send DNS Packet Query (EnhancedAssociateUDP).

  dns_ask = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: "example.com", record_type: DNS::Packet::RecordFlag::A
  dns_ask.transmissionId = Random.new.rand type: UInt16

  # Create Frames::Fragment.

  fragment = SOCKS::Frames::Fragment.new version: SOCKS::Frames::VersionFlag::V5, arType: SOCKS::ARType::Ask
  fragment.fragmentId = 0_u8
  fragment.addressType = SOCKS::Frames::AddressFlag::Ipv4
  fragment.destinationIpAddress = Socket::IPAddress.new(address: "8.8.8.8", port: 53_i32)
  fragment.forwardIpAddress = udp_from_establish_forward_ip_address

  # Print Detail.

  STDOUT.puts [:Detail, fragment, dns_ask.to_slice, udp_from_establish_destination_ip_address, udp_from_establish_forward_ip_address]

  3_i32.times do |index|
    dns_ask.transmissionId = Random.new.rand type: UInt16
    fragment.payload = dns_ask.to_slice

    # Send DNS Packet Query (AssociateUDP) & Receive 4096 Bytes, because Fragment and DNS query may be larger than 512 Bytes. (EnhancedAssociateUDP).

    associate_udp.send message: fragment.to_slice, to: udp_from_establish_destination_ip_address
    received_length, ip_address = associate_udp.receive message: buffer.to_slice

    # Decode DNS Packet Response (AssociateUDP).

    _fragment = SOCKS::Frames::Fragment.from_slice slice: buffer.to_slice[0_i32, received_length], ar_type: SOCKS::ARType::Reply, command_flag: SOCKS::Frames::CommandFlag::EnhancedAssociateUDP
    STDOUT.puts [:EnhancedAssociateUDP, index, Time.local, (DNS::Packet.from_slice protocol_type: DNS::ProtocolType::UDP, slice: _fragment.payload || Bytes.new(size: 0_i32))]
  end
end

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

# `SOCKS::Client.new` will create a socket connected to the destination address.

client = SOCKS::Client.new host: "0.0.0.0", port: 1236_i32, dns_resolver: dns_resolver, options: options, timeout: SOCKS::TimeOut.new

begin
  # Upgrade outbound to WebSocket, and handshake.

  client.process_upgrade!
  client.handshake!

  # Establish a EnhancedAssociateUDP to example.com through outbound.

  associate_udp_from_establish = client.establish! dns_resolver: dns_resolver, command_flag: SOCKS::Frames::CommandFlag::EnhancedAssociateUDP, host: "8.8.8.8", port: 53_i32, remote_dns_resolution: true
  raise Exception.new "client.establish! EnhancedAssociateUDP establish_frame is Nil!" unless _associate_udp_from_establish = associate_udp_from_establish
  raise Exception.new "client.establish! EnhancedAssociateUDP establish_frame is not SOCKS::Frames::Establish!" unless _associate_udp_from_establish.is_a? SOCKS::Frames::Establish
  raise Exception.new "client.establish! EnhancedAssociateUDP destinationIpAddress is Nil!" unless _associate_udp_from_establish_destination_ip_address = _associate_udp_from_establish.destinationIpAddress
  raise Exception.new "client.establish! EnhancedAssociateUDP forwardIpAddress is Nil!" unless _associate_udp_from_establish_forward_ip_address = _associate_udp_from_establish.forwardIpAddress
  client.resynchronize command_flag: SOCKS::Frames::CommandFlag::EnhancedAssociateUDP

  # Do Something.

  do_something udp_from_establish_destination_ip_address: _associate_udp_from_establish_destination_ip_address, udp_from_establish_forward_ip_address: _associate_udp_from_establish_forward_ip_address
rescue ex
  STDOUT.puts [:EXCEPTION, ex, ex.backtrace?]
end

# Never forget to close IO, otherwise it will cause socket leakage.

client.close
