struct SOCKS::Frames
  struct Establish < Frames
    property version : VersionFlag
    property arType : ARType
    property commandType : CommandFlag?
    property addressType : AddressFlag?
    property destinationIpAddress : Socket::IPAddress?
    property destinationAddress : Address?
    property forwardIpAddress : Socket::IPAddress?
    property statusType : StatusFlag?

    def initialize(@version : VersionFlag, @arType : ARType)
      @commandType = nil
      @addressType = nil
      @destinationIpAddress = nil
      @destinationAddress = nil
      @forwardIpAddress = nil
      @statusType = nil
    end

    # command_flag (read_reply / EnhancedAssociateUDP).

    def self.from_io(io : IO, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5, command_flag : CommandFlag? = nil) : Establish
      case ar_type
      in .ask?
        Establish.read_ask io: io, version_flag: version_flag
      in .reply?
        Establish.read_reply io: io, version_flag: version_flag, command_flag: command_flag
      end
    end

    def to_io(io : IO)
      to_io io: io, ar_type: arType, version_flag: version
    end

    # write_reply (EnhancedAssociateUDP), commandType, forwardIpAddress.

    def to_io(io : IO, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5) : IO
      raise Exception.new "Establish.to_io: version_flag and Establish.version do not match!" if version_flag != version
      raise Exception.new "Establish.to_io: ar_type and Establish.arType do not match!" if ar_type != arType

      case ar_type
      in .ask?
        write_ask io: io, version_flag: version_flag
      in .reply?
        write_reply io: io, version_flag: version_flag
      end

      io
    end

    def self.read_ask(io : IO, version_flag : VersionFlag = VersionFlag::V5) : Establish
      io_version_flag = Frames.strict_read_version! io: io, version_flag: version_flag
      frame = new version: io_version_flag, arType: ARType::Ask

      frame.commandType = Frames.read_command! io: io
      reserved = Frames.read_reserved! io: io
      frame.addressType = address_type = Frames.read_address! io: io

      destination_ip_address, destination_address = Frames.read_destination_address! io: io, address_type: address_type
      frame.destinationIpAddress = destination_ip_address
      frame.destinationAddress = destination_address

      frame
    end

    def write_ask(io : IO, version_flag : VersionFlag = VersionFlag::V5)
      raise Exception.new "Establish.write_ask: Establish.commandType cannot be Nil!" unless command_flag = commandType
      raise Exception.new "Establish.write_ask: Establish.addressType cannot be Nil!" unless address_type = addressType
      raise Exception.new "Establish.write_ask: Establish.destinationAddress or destinationIpAddress cannot be Nil!" unless destination_address = get_destination_address

      strict_check_version! version_flag
      memory = IO::Memory.new
      reserved = Bytes[0_i32]

      memory.write Bytes[version.to_i]
      memory.write Bytes[command_flag.to_i]
      memory.write reserved
      memory.write Bytes[address_type.to_i]

      case destination_address
      in Socket::IPAddress
        memory.write destination_address.to_slice
        memory.write_bytes destination_address.port.to_u16, IO::ByteFormat::BigEndian
      in Address
        memory.write Bytes[destination_address.host.size.to_u8]
        memory.write destination_address.host.to_slice
        memory.write_bytes destination_address.port.to_u16, IO::ByteFormat::BigEndian
      end

      io.write memory.to_slice
    end

    def self.read_reply(io : IO, version_flag : VersionFlag = VersionFlag::V5, command_flag : CommandFlag? = nil) : Establish
      io_version_flag = Frames.strict_read_version! io: io, version_flag: version_flag
      frame = new version: io_version_flag, arType: ARType::Reply

      frame.statusType = Frames.read_status! io: io
      reserved = Frames.read_reserved! io: io
      frame.addressType = address_type = Frames.read_address! io: io

      destination_ip_address, destination_address = Frames.read_destination_address! io: io, address_type: address_type
      frame.destinationIpAddress = destination_ip_address
      frame.destinationAddress = destination_address

      if command_flag.try &.enhanced_associate_udp?
        forward_ip46_flag = Frames.read_ip46! io: io
        frame.forwardIpAddress = forward_ipaddress = Frames.read_ip_address! io: io, address_flag: (forward_ip46_flag.ipv4? ? AddressFlag::Ipv4 : AddressFlag::Ipv6)
      end

      frame
    end

    def write_reply(io : IO, version_flag : VersionFlag = VersionFlag::V5)
      raise Exception.new "Establish.write_reply: Establish.commandType cannot be Nil!" unless command_flag = commandType
      raise Exception.new "Establish.write_reply: Establish.statusType cannot be Nil!" unless status_type = statusType
      raise Exception.new "Establish.write_reply: Establish.addressType cannot be Nil!" unless address_type = addressType
      raise Exception.new "Establish.write_reply: Establish.destinationAddress or destinationIpAddress cannot be Nil!" unless destination_address = get_destination_address

      strict_check_version! version_flag
      memory = IO::Memory.new
      reserved = Bytes[0_i32]

      memory.write Bytes[version.to_i]
      memory.write Bytes[status_type.to_i]
      memory.write reserved
      memory.write Bytes[address_type.to_i]

      case destination_address
      in Socket::IPAddress
        begin
          write_destination_ip_address io: memory, destination_address: destination_address
        rescue ex : ArgumentError
          destination_address = Address.new host: destination_address.address, port: destination_address.port
          write_destination_address io: memory, destination_address: destination_address
        end
      in Address
        write_destination_address io: memory, destination_address: destination_address
      end

      if commandType.try &.enhanced_associate_udp?
        raise Exception.new "Establish.write_reply: commandType is EnhancedAssociateUDP, but forwardIpAddress is Nil!" unless forward_ip_address = forwardIpAddress

        memory.write_bytes (forward_ip_address.family.inet? ? Frames::Ip46Flag::Ipv4 : Frames::Ip46Flag::Ipv6).value, IO::ByteFormat::BigEndian
        memory.write slice: forward_ip_address.to_slice
        memory.write_bytes forward_ip_address.port.to_u16, IO::ByteFormat::BigEndian
      end

      io.write slice: memory.to_slice
    end

    private def write_destination_ip_address(io : IO, destination_address : Socket::IPAddress)
      io.write destination_address.to_slice
      io.write_bytes destination_address.port.to_u16, IO::ByteFormat::BigEndian
    end

    private def write_destination_address(io : IO, destination_address : Address)
      io.write Bytes[destination_address.host.size.to_u8]
      io.write destination_address.host.to_slice
      io.write_bytes destination_address.port.to_u16, IO::ByteFormat::BigEndian
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

    private def strict_check_version!(version_flag : VersionFlag = VersionFlag::V5) : Bool
      Frames.strict_check_version! struct_version_flag: version, version_flag: version_flag
    end
  end
end
