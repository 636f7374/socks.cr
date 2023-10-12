class SOCKS::UdpGateway
  getter listenAddress : Socket::IPAddress

  def initialize(@listenAddress : Socket::IPAddress)
  end

  # public_ip_address?(Socket::IPAddress.new(address: "::ffff:10.2.0.4", port: 50768_i32)) => true
  # ::ffff:10.2.0.4 should be private.
  # Note: Oct, 12, 2023 | Crystal bug (Crystal 1.10.0).

  def self.public_ip_address?(ip_address : Socket::IPAddress)
    (ip_address.link_local? || ip_address.loopback? || ip_address.private? || ip_address.unspecified?) ? false : true
  end

  def self.strip_ffff_ip_address(ip_address : Socket::IPAddress) : Socket::IPAddress
    ip_address_text = ip_address.address
    return ip_address unless ip_address_text.starts_with? str: "::ffff:"

    strip_ip_address_text = ip_address_text.lstrip chars: "::ffff:"
    Socket::IPAddress.new address: strip_ip_address_text, port: ip_address.port
  end

  def listen
    modified_buffer = uninitialized UInt8[4096_i32]
    buffer = uninitialized UInt8[4096_i32]

    begin
      socket = UDPSocket.new family: listenAddress.family
      socket.bind host: listenAddress.address, port: listenAddress.port
      socket_local_address = socket.local_address
    rescue ex
      socket.try &.close

      return
    end

    loop do
      received_length, incoming_address = socket.receive message: buffer.to_slice
      next if received_length <= 1_i32

      # _8 Bytes: Ip46Flag (1 Bytes) + Ipv4Address (_4 Bytes) + Port (2 Bytes) + Minimum Bytes (1 Bytes) = _8 Bytes
      # 20 Bytes: Ip46Flag (1 Bytes) + Ipv6Address (16 Bytes) + Port (2 Bytes) + Minimum Bytes (1 Bytes) = 20 Bytes

      next unless ip46_flag = Frames::Ip46Flag.from_value? value: buffer.to_slice[0_u8]
      next if received_length <= (ip46_flag.ipv4? ? 8_u8 : 20_u8)

      # ...

      destination_address = Socket::IPAddress.parse slice: buffer.to_slice[1_u8..(ip46_flag.ipv4? ? 6_u8 : 18_u8)], family: (ip46_flag.ipv4? ? Socket::Family::INET : Socket::Family::INET6), with_port: true rescue nil
      next unless destination_address

      # Block if destination_address equal incoming_address, listenAddress and Block if destination_address and incoming_address are External IpAddress.
      # Block if destination_address is local IpAddress and destination_address port is equal to listenAddress port (Prevent reflection attacks (-> UdpGateway -> UdpGateway ->)).

      strip_incoming_address = UdpGateway.strip_ffff_ip_address ip_address: incoming_address
      strip_destination_address = UdpGateway.strip_ffff_ip_address ip_address: destination_address

      next if (strip_destination_address == strip_incoming_address) || (strip_destination_address == listenAddress)
      incoming_address_is_public_ip = UdpGateway.public_ip_address? ip_address: strip_incoming_address
      destination_address_is_public_ip = UdpGateway.public_ip_address? ip_address: strip_destination_address
      next if incoming_address_is_public_ip && destination_address_is_public_ip
      next if !destination_address_is_public_ip && (strip_destination_address.port == listenAddress.port)

      # Prevent reflection attacks (... -> UdpGateway -> Endpoint -> UdpGateway -> Endpoint -> ...).
      # ...

      if __ip46_flag = Frames::Ip46Flag.from_value? value: buffer.to_slice[7_u8]
        __destination_address = Socket::IPAddress.parse slice: buffer.to_slice[8_u8..(ip46_flag.ipv4? ? 13_u8 : 25_u8)], family: (ip46_flag.ipv4? ? Socket::Family::INET : Socket::Family::INET6), with_port: true rescue nil

        if __destination_address
          __destination_address = UdpGateway.strip_ffff_ip_address ip_address: __destination_address
          next if !UdpGateway.public_ip_address?(ip_address: __destination_address) && __destination_address.port == listenAddress.port
        end
      end

      # Stripping "::ffff:" prefix from request.connection.remoteAddress nodejs: https://stackoverflow.com/questions/31100703/stripping-ffff-prefix-from-request-connection-remoteaddress-nodejs
      # What happens is your OS is listening with a hybrid IPv4-IPv6 socket, which converts any IPv4 address to IPv6, by embedding it within the IPv4-mapped IPv6 address format. This format just prefixes the IPv4 address with :ffff:, so you can recover the original IPv4 address by just stripping the :ffff:. (Some deprecated mappings prefix with :: instead of :ffff:, so we use the regex /^.*:/ to match both forms.)

      if socket.family.inet6? && destination_address.family.inet?
        hybrid_destination_address = Socket::IPAddress.new address: String.build { |io| io << "::ffff:" << destination_address.address }, port: destination_address.port
      end

      # Normal process.

      spawn do
        begin
          modified_buffer.to_slice[0_u8] = (incoming_address.family.inet? ? Frames::ModifiedIp46Flag::Ipv4 : Frames::ModifiedIp46Flag::Ipv6).value
          incoming_address.to_slice slice: modified_buffer.to_slice[1_u8..(incoming_address.family.inet? ? 6_u8 : 18_u8)]
          modified_buffer.to_slice[(incoming_address.family.inet? ? 7_u8 : 19_u8)...].copy_from source: buffer.to_slice[(destination_address.family.inet? ? 7_u8 : 19_u8)..(received_length - 1_u8)]
          socket.send message: modified_buffer.to_slice[0_u8, (received_length - (destination_address.family.inet? ? 7_u8 : 19_u8) + (incoming_address.family.inet? ? 7_u8 : 19_u8))], to: (hybrid_destination_address || destination_address)
        rescue ex
        end
      end
    end

    socket.close rescue nil
  end
end
