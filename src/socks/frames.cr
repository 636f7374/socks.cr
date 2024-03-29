abstract struct SOCKS::Frames
  Base64AuthenticationMapping = Set{['+', '!'], ['/', '%'], ['=', '#'], ['.', '$'], ['_', '&']}

  enum AuthenticationFlag : UInt8
    NoAuthentication                         =   0_u8
    GSSAPI                                   =   1_u8
    UserNamePassword                         =   2_u8
    ChallengeHandshakeAuthenticationProtocol =   3_u8
    Unassigned                               =   4_u8
    ChallengeResponseAuthenticationMethod    =   5_u8
    SecureSocketsLayer                       =   6_u8
    NDSAuthentication                        =   7_u8
    MultiAuthenticationFramework             =   8_u8
    JSONParameterBlock                       =   9_u8
    NoAcceptableMethods                      = 255_u8

    # (0x03/__3) - (0x7F/127) IANA Assigned
    # (0x80/128) - (0xFE/254) Reserved For Private Methods

  end

  enum VersionFlag : UInt8
    V4 = 4_u8
    V5 = 5_u8
  end

  enum AddressFlag : UInt8
    Ipv4   = 1_u8
    Domain = 3_u8
    Ipv6   = 4_u8
  end

  enum CommandFlag : UInt8
    TCPConnection        = 1_u8
    TCPBinding           = 2_u8
    AssociateUDP         = 3_u8
    EnhancedAssociateUDP = 4_u8
  end

  enum StatusFlag : UInt8
    IndicatesSuccess       = 0_u8
    ConnectFailed          = 1_u8
    ConnectionNotAllowed   = 2_u8
    NetworkUnreachable     = 3_u8
    HostUnreachable        = 4_u8
    ConnectionDenied       = 5_u8
    TTLTimeOut             = 6_u8
    UnsupportedCommand     = 7_u8
    UnsupportedAddressType = 8_u8
    Undefined              = 9_u8
  end

  enum AuthenticationChoiceFlag : UInt8
    UserNamePassword = 1_u8
  end

  enum ReservedFlag : UInt8
    Nil = 0_u8
  end

  enum PermissionFlag : UInt8
    Passed = 0_u8
    Denied = 1_u8
  end

  enum WebSocketAuthorizationFlag : UInt8
    Basic = 1_u8
  end

  enum WrapperFlag : UInt8
    None      = 0_u8
    WebSocket = 1_u8
  end

  enum Ip46Flag : UInt8
    Ipv4 = 0_u8
    Ipv6 = 1_u8
  end

  enum ModifiedIp46Flag : UInt8
    Ipv4 = 254_u8
    Ipv6 = 255_u8
  end

  def self.encode_sec_websocket_protocol_authorization(user_name : String, password : String) : String
    authorization = String.build { |_io| _io << user_name << ':' << password }
    encode_sec_websocket_protocol_authorization value: authorization
  end

  def self.encode_sec_websocket_protocol_authorization(value : String) : String
    value = Base64.strict_encode value
    Base64AuthenticationMapping.each { |chars| value = value.gsub chars.first, chars.last }

    value
  end

  def self.decode_sec_websocket_protocol_authorization!(authorization : String) : String
    Base64AuthenticationMapping.each { |chars| authorization = authorization.gsub chars.last, chars.first }
    Base64.decode_string authorization
  end

  {% for name in ["optional_size", "fragment_id"] %}
  def self.read_{{name.id}}!(io : IO, exception : Exception? = nil) : UInt8
    buffer = uninitialized UInt8[1_i32]
    read_length = io.read buffer.to_slice

    if read_length.zero?
      message = String.build { |io| io << "Failed to read " << {{name.id.stringify}} << " size, read_length is zero!" }
      raise exception || Exception.new message: message
    end

    buffer.to_slice[0_u8].dup
  end
  {% end %}

  def self.strict_read_version!(io : IO, version_flag : VersionFlag) : VersionFlag
    io_version_flag = read_version! io: io

    if io_version_flag != version_flag
      message = String.build do |io|
        io << "The IO version (" << version_flag.to_s << ") "
        io << "does not match the expected version (" << io_version_flag.to_s << ")."
      end

      raise Exception.new message: message
    end

    io_version_flag
  end

  def self.strict_check_version!(struct_version_flag : VersionFlag, version_flag : VersionFlag) : Bool
    return true if struct_version_flag == version_flag

    message = String.build do |io|
      io << "The Struct version (" << struct_version_flag.to_s << ") "
      io << "does not match the expected version (" << version_flag.to_s << ")."
    end

    raise Exception.new message: message
  end

  def self.read_ip_address!(io : IO, address_flag : AddressFlag) : Socket::IPAddress
    case address_flag
    when .ipv6?
      ipv6_buffer = uninitialized UInt8[18_i32]
      io.read slice: ipv6_buffer.to_slice

      Socket::IPAddress.parse slice: ipv6_buffer.to_slice, family: Socket::Family::INET6, with_port: true
    when .ipv4?
      ipv4_buffer = uninitialized UInt8[6_i32]
      io.read slice: ipv4_buffer.to_slice

      Socket::IPAddress.parse slice: ipv4_buffer.to_slice, family: Socket::Family::INET, with_port: true
    else
      raise Exception.new "Invalid AddressFlag, Frames.read_ip_address! failed!"
    end
  end

  def self.read_domain!(io : IO) : Address
    buffer = uninitialized UInt8[1_i32]
    read_length = io.read slice: buffer.to_slice

    if read_length.zero?
      message = String.build { |io| io << "Frames.read_domain!: Failed to read domain, read_length is zero!" }
      raise Exception.new message: message
    end

    temporary_slice = Bytes.new size: buffer.to_slice[0_i32]
    value_length = io.read slice: temporary_slice

    if value_length.zero?
      message = String.build { |io| io << "Frames.read_domain!: Failed to read host, copy_length is zero!" }
      raise Exception.new message: message
    end

    host = String.new temporary_slice
    port = io.read_bytes type: UInt16, format: IO::ByteFormat::BigEndian

    Address.new host, port.to_i32
  end

  def self.read_destination_address!(io : IO, address_type : AddressFlag) : Tuple(Socket::IPAddress?, Address)
    case address_type
    in .ipv6?
      ip_address = Frames.read_ip_address! io: io, address_flag: address_type
      destination_address = Address.new ip_address.address, ip_address.port

      Tuple.new ip_address, destination_address
    in .ipv4?
      ip_address = Frames.read_ip_address! io: io, address_flag: address_type
      destination_address = Address.new ip_address.address, ip_address.port

      Tuple.new ip_address, destination_address
    in .domain?
      destination_address = Frames.read_domain! io: io

      Tuple.new nil, destination_address
    end
  end

  {% for name in ["username", "password"] %}
  def self.read_{{name.id}}!(io : IO) : String
    buffer = uninitialized UInt8[1_i32]
    read_length = io.read slice: buffer.to_slice

    if read_length.zero?
      message = String.build { |io| io << "Failed to read " << {{name.id.stringify}} << ", read_length is zero!" } 
      raise Exception.new message: message
    end

    temporary_slice = Bytes.new size: buffer.to_slice[0_i32]
    value_length = io.read slice: temporary_slice

    if value_length.zero?
      message = String.build { |io| io << "Failed to read " << {{name.id.stringify}} << ", value_length is zero!" } 
      raise Exception.new message: message
    end

    String.new temporary_slice
  end
  {% end %}

  {% for name in ["version", "command", "reserved", "address", "authentication", "authentication_choice", "permission", "status", "ip46", "modified_ip46"] %}
  def self.read_{{name.id}}!(io : IO) : {{name.camelcase.id}}Flag
    buffer = uninitialized UInt8[1_i32]
    read_length = io.read slice: buffer.to_slice

    if read_length.zero?
      message = String.build { |io| io << "Failed to read " << {{name.id.stringify}} << ", read_length is zero!" } 
      raise Exception.new message: message
    end

    unless value = {{name.camelcase.id}}Flag.from_value? value: buffer.to_slice[0_i32].to_i32
      message = String.build do |io| 
        io << "Failed to read " << {{name.id.stringify}} << ", " << "value does not exist in Frames::" 
        io << {{name.camelcase.id.stringify}} << "Flag Enum!"
      end

      raise Exception.new message: message
    end

    value
  end
  {% end %}
end

require "./frames/*"
