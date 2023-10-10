struct SOCKS::Frames
  struct Fragment < Frames
    property version : VersionFlag
    property arType : ARType
    property fragmentId : UInt8?
    property addressType : AddressFlag?
    property destinationIpAddress : Socket::IPAddress?
    property destinationAddress : Address?
    property forwardIpAddress : Socket::IPAddress?
    property payload : Bytes?

    def initialize(@version : VersionFlag, @arType : ARType)
      @fragmentId = nil
      @addressType = nil
      @destinationIpAddress = nil
      @destinationAddress = nil
      @forwardIpAddress = nil
      @payload = nil
    end

    def self.from_string(string : String, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5) : Fragment
      from_slice slice: string.to_slice, ar_type: ar_type, version_flag: version_flag
    end

    def self.from_slice(slice : Bytes, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5, command_flag : CommandFlag = CommandFlag::AssociateUDP) : Fragment
      case ar_type
      in .ask?
        read_ask slice: slice, version_flag: version_flag, command_flag: command_flag
      in .reply?
        read_reply slice: slice, version_flag: version_flag, command_flag: command_flag
      end
    end

    def to_slice : Bytes
      case @arType
      in .ask?
        to_ask_slice
      in .reply?
        to_reply_slice
      end
    end

    {% for name in ["ask", "reply"] %}
    private def self.read_{{name.id}}(slice : Bytes, version_flag : VersionFlag = VersionFlag::V5, command_flag : CommandFlag = CommandFlag::AssociateUDP) : Fragment
      frame = new version: version_flag, arType: ARType::{{name.capitalize.id}}
      pos = 0_u8

      if command_flag.enhanced_associate_udp?
        forward_ip46_flag = Frames::ModifiedIp46Flag.from_value value: slice[0_u8]
        frame.forwardIpAddress = forward_ip_address = Socket::IPAddress.parse slice: slice[1_u8...], family: (forward_ip46_flag.ipv4? ? Socket::Family::INET : Socket::Family::INET6), with_port: true
        pos += (forward_ip_address.family.inet? ? 7_u8 : 19_u8) # Count not index.
      end

      reserved = slice[(pos + 0_u8)]
      reserved = slice[(pos + 1_u8)]
      frame.fragmentId = slice[(pos + 2_u8)]
      frame.addressType = address_type = AddressFlag.from_value value: slice[(pos + 3_u8)]
      address_length = pos + 4_u8 # (reserved) 2 Bytes, (fragmentId) 1 Bytes, (addressType) 1 Bytes.

      case address_type
      in .ipv4?
        address_length += 4_u8
      in .ipv6?
        address_length += 16_u8
      in .domain?
        domain_length = slice[(4_u8 + pos)]
        address_length += 1_u8
        address_length += domain_length
      end

      # Address Port (1 Bytes).

      address_length += 1_u8

      # ...

      address_buffer = IO::Memory.new slice: slice[(pos + 4_u8)..address_length]
      destination_ip_address, destination_address = Frames.read_destination_address! io: address_buffer, address_type: address_type
      frame.destinationIpAddress = destination_ip_address
      frame.destinationAddress = destination_address
      frame.payload = slice[(address_length + 1_u8)...]

      frame
    end
    {% end %}

    {% for name in ["ask", "reply"] %}
    def to_{{name.id}}_slice : Bytes
      raise Exception.new String.build { |io| io << "Fragment.to_" << {{name}} << "_slice: Fragment.destinationAddress cannot be Nil!" } unless destination_address = get_destination_address
      raise Exception.new String.build { |io| io << "Fragment.to_" << {{name}} << "_slice: Fragment.fragmentId cannot be Nil!" } unless fragment_id = fragmentId
      raise Exception.new String.build { |io| io << "Fragment.to_" << {{name}} << "_slice: Fragment.addressType cannot be Nil!" } unless address_type = addressType
      raise Exception.new String.build { |io| io << "Fragment.to_" << {{name}} << "_slice: Fragment.payload cannot be Nil!" } unless _payload = payload

      memory = IO::Memory.new
      reserved = Bytes[0_i32]

      if forward_ip_address = forwardIpAddress
        memory.write_bytes (forward_ip_address.family.inet? ? Frames::Ip46Flag::Ipv4 : Frames::Ip46Flag::Ipv6).value, IO::ByteFormat::BigEndian
        memory.write slice: forward_ip_address.to_slice
        memory.write_bytes forward_ip_address.port.to_u16, IO::ByteFormat::BigEndian
      end

      memory.write slice: reserved
      memory.write slice: reserved
      memory.write slice: Bytes[fragment_id.to_i]
      memory.write slice: Bytes[address_type.to_i]

      case destination_address
      in Socket::IPAddress
        memory.write slice: destination_address.to_slice
        memory.write_bytes destination_address.port.to_u16, IO::ByteFormat::BigEndian
      in Address
        memory.write_bytes destination_address.host.size.to_u8, IO::ByteFormat::BigEndian
        memory.write slice: destination_address.host.to_slice
        memory.write_bytes destination_address.port.to_u16, IO::ByteFormat::BigEndian
      end

      memory.write slice: _payload
      memory.to_slice
    end
    {% end %}

    def get_destination_address : Socket::IPAddress | Address
      raise Exception.new "Establish.get_destination_address: Establish.addressType cannot be Nil!" unless address_type = addressType

      case address_type
      in .ipv6?
        raise Exception.new "Establish.get_destination_address: Establish.destinationIpAddress cannot be Nil!" unless destination_ip_address = destinationIpAddress
        destination_ip_address
      in .ipv4?
        raise Exception.new "Establish.get_destination_address: Establish.destinationIpAddress cannot be Nil!" unless destination_ip_address = destinationIpAddress
        destination_ip_address
      in .domain?
        raise Exception.new "Establish.get_destination_address: Establish.destinationAddress cannot be Nil!" unless destination_address = destinationAddress
        destination_address
      end
    end
  end
end
