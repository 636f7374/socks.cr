struct SOCKS::Frames
  struct Fragment < Frames
    property version : VersionFlag
    property arType : ARType
    property sourceIpAddress : Socket::IPAddress
    property fragmentId : UInt8?
    property addressType : AddressFlag?
    property destinationIpAddress : Socket::IPAddress?
    property destinationAddress : Address?
    property payload : Bytes?
    property successed : Bool?

    def initialize(@version : VersionFlag, @arType : ARType, @sourceIpAddress : Socket::IPAddress)
      @fragmentId = nil
      @addressType = nil
      @destinationIpAddress = nil
      @destinationAddress = nil
      @payload = nil
      @successed = nil
    end

    def self.from_string(source_ip_address : Socket::IPAddress, string : String, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5) : Fragment
      from_slice source_ip_address: source_ip_address, slice: string.to_slice, ar_type: ar_type, version_flag: version_flag
    end

    def self.from_slice(source_ip_address : Socket::IPAddress, slice : Bytes, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5) : Fragment
      case ar_type
      in .ask?
        read_ask source_ip_address: source_ip_address, slice: slice, version_flag: version_flag
      in .reply?
        read_reply source_ip_address: source_ip_address, slice: slice, version_flag: version_flag
      end
    end

    def to_slice
      to_slice ar_type: arType, version_flag: version
    end

    def to_slice(ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5) : Bytes
      raise Exception.new "Fragment.to_slice: version_flag and Fragment.version do not match!" if version_flag != version
      raise Exception.new "Fragment.to_slice: ar_type and Fragment.arType do not match!" if ar_type != arType

      case ar_type
      in .ask?
        to_ask_slice version_flag: version_flag
      in .reply?
        to_reply_slice version_flag: version_flag
      end
    end

    {% for name in ["ask", "reply"] %}
    private def self.read_{{name.id}}(source_ip_address : Socket::IPAddress, slice : Bytes, version_flag : VersionFlag = VersionFlag::V5) : Fragment
      memory = IO::Memory.new slice
      read_{{name.id}} source_ip_address: source_ip_address, io: memory, version_flag: version_flag
    end

    private def self.read_{{name.id}}(source_ip_address : Socket::IPAddress, io : IO::Memory, version_flag : VersionFlag = VersionFlag::V5) : Fragment
      frame = new version: version_flag, arType: ARType::{{name.capitalize.id}}, sourceIpAddress: source_ip_address

      reserved = Frames.read_reserved! io: io
      reserved = Frames.read_reserved! io: io
      frame.fragmentId = Frames.read_fragment_id! io: io
      frame.addressType = address_type = Frames.read_address! io: io

      destination_ip_address, destination_address = Frames.read_destination_address! io: io, address_type: address_type
      frame.destinationIpAddress = destination_ip_address
      frame.destinationAddress = destination_address
      frame.payload = io.to_slice[io.pos..(io.size - 1_i32)]

      frame.successed = true

      frame
    end
    {% end %}

    def to_ask_slice(version_flag : VersionFlag = VersionFlag::V5) : Bytes
      raise Exception.new String.build { |io| io << "Fragment.to_ask_slice: Fragment.destinationAddress cannot be Nil!" } unless destination_address = get_destination_address
      raise Exception.new String.build { |io| io << "Fragment.to_ask_slice: Fragment.fragmentId cannot be Nil!" } unless fragment_id = fragmentId
      raise Exception.new String.build { |io| io << "Fragment.to_ask_slice: Fragment.addressType cannot be Nil!" } unless address_type = addressType
      raise Exception.new String.build { |io| io << "Fragment.to_ask_slice: Fragment.payload cannot be Nil!" } unless _payload = payload

      memory = IO::Memory.new
      reserved = Bytes[0_i32]
      memory.write reserved
      memory.write reserved
      memory.write Bytes[fragment_id.to_i]
      memory.write Bytes[address_type.to_i]

      case destination_address
      in Socket::IPAddress
        case destination_address.family
        when .inet6?
          memory.write destination_address.to_slice
          memory.write_bytes destination_address.port.to_u16, IO::ByteFormat::BigEndian
        when .inet?
          memory.write destination_address.to_slice
          memory.write_bytes destination_address.port.to_u16, IO::ByteFormat::BigEndian
        end
      in Address
        memory.write destination_address.host.to_slice
        memory.write_bytes destination_address.port.to_u16, IO::ByteFormat::BigEndian
      end

      memory.write _payload
      memory.to_slice
    end

    def to_reply_slice(version_flag : VersionFlag = VersionFlag::V5) : Bytes
      raise Exception.new String.build { |io| io << "Fragment.to_reply_slice: Fragment.fragmentId cannot be Nil!" } unless fragment_id = fragmentId
      raise Exception.new String.build { |io| io << "Fragment.to_reply_slice: Fragment.addressType cannot be Nil!" } unless address_type = addressType
      raise Exception.new String.build { |io| io << "Fragment.to_reply_slice: Fragment.payload cannot be Nil!" } unless _payload = payload

      memory = IO::Memory.new
      reserved = Bytes[0_i32]
      memory.write reserved
      memory.write reserved
      memory.write Bytes[fragment_id.to_i]
      memory.write Bytes[address_type.to_i]

      case sourceIpAddress.family
      when .inet6?
        memory.write Socket::IPAddress.ipv6_to_bytes! sourceIpAddress
        memory.write_bytes sourceIpAddress.port.to_u16, IO::ByteFormat::BigEndian
      when .inet?
        memory.write Socket::IPAddress.ipv4_to_bytes! sourceIpAddress
        memory.write_bytes sourceIpAddress.port.to_u16, IO::ByteFormat::BigEndian
      end

      memory.write _payload
      memory.to_slice
    end

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
