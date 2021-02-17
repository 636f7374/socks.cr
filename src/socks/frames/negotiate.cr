struct SOCKS::Frames
  struct Negotiate < Frames
    property version : VersionFlag
    property arType : ARType
    property methodCount : UInt8?
    property methods : Set(AuthenticationFlag)?
    property acceptedMethod : AuthenticationFlag?
    property authenticateFrame : Authenticate?
    property successed : Bool?

    def initialize(@version : VersionFlag, @arType : ARType)
      @methodCount = nil
      @methods = nil
      @acceptedMethod = nil
      @authenticateFrame = nil
      @successed = nil
    end

    def self.from_io(io : IO, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5) : Negotiate
      case ar_type
      in .ask?
        Negotiate.read_ask io: io, version_flag: version_flag
      in .reply?
        Negotiate.read_reply io: io, version_flag: version_flag
      end
    end

    def to_io(io : IO)
      to_io io: io, ar_type: arType, version_flag: version
    end

    def to_io(io : IO, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5) : IO
      raise Exception.new "Negotiate.to_io: version_flag and Negotiate.version do not match!" if version_flag != version
      raise Exception.new "Negotiate.to_io: ar_type and Negotiate.arType do not match!" if ar_type != arType

      case ar_type
      in .ask?
        write_ask io: io, version_flag: version_flag
      in .reply?
        write_reply io: io, version_flag: version_flag
      end

      io
    end

    def self.read_ask(io : IO, version_flag : VersionFlag = VersionFlag::V5) : Negotiate
      io_version_flag = Frames.strict_read_version! io: io, version_flag: version_flag
      frame = new version: io_version_flag, arType: ARType::Ask

      method_count_exception = Exception.new "Failed to read Negotiate.methodCount (1 Bytes) from IO."
      method_count = Frames.read_optional_size! io: io, exception: method_count_exception
      raise Exception.new "Read Negotiate.methodCount from IO is Integer zero." if method_count.zero?
      frame.methodCount = method_count

      # Note: When the number of authentication methods is 1 and UserNamePassword, the authenticateFrame is not always attached.
      # Buffer allocation instructions:
      # 255 Bytes: Maximum methodCount (UInt8::MAX)
      # 1 Bytes: authenticationChoiceType
      # If authenticationMethod == AuthenticationFlag::UserNamePassword
      # > 1 Bytes: UserName Next Length
      # > 255 Bytes: Maximum UserName (UInt8::MAX)
      # > 1 Bytes: Password Next Length
      # > 255 Bytes: Maximum Password (UInt8::MAX)
      # Else
      # > There are 10 authentication methods (includes IANA), should we allocate 4096 Bytes? Or fail?
      # End

      buffer = uninitialized UInt8[768_i32]
      read_length = io.read buffer.to_slice
      memory = IO::Memory.new read_length
      memory.write buffer.to_slice[0_i32, read_length]
      memory.rewind

      methods = Set(AuthenticationFlag).new
      method_count.times { methods << Frames.read_authentication! io: memory }
      frame.methods = methods

      if (memory.pos < memory.size) && (1_i32 == methods.size) && methods.includes? AuthenticationFlag::UserNamePassword
        frame.authenticateFrame = Authenticate.from_io io: memory, ar_type: ARType::Ask, version_flag: version_flag
      end

      frame.successed = true

      frame
    end

    def write_ask(io : IO, version_flag : VersionFlag = VersionFlag::V5)
      raise Exception.new "Negotiate.write_ask: Negotiate.methodCount cannot be Nil!" unless method_count = methodCount
      raise Exception.new "Negotiate.write_ask: Negotiate.methodCount cannot be Integer zero!" if method_count.zero?
      raise Exception.new "Negotiate.write_ask: Negotiate.methods cannot be Nil!" unless _methods = methods
      raise Exception.new "Negotiate.write_ask: Negotiate.methods cannot be empty!" if _methods.empty?
      raise Exception.new "Negotiate.write_ask: Negotiate methods and methodCount do not match!" if method_count != _methods.size

      strict_check_version! version_flag
      memory = IO::Memory.new
      memory.write Bytes[version.to_i]
      memory.write Bytes[method_count.to_i]
      _methods.each { |method| memory.write Bytes[method.to_i] }

      if (1_i32 == _methods.size) && _methods.includes? AuthenticationFlag::UserNamePassword
        authenticateFrame.try { |_authenticate_frame| _authenticate_frame.to_io io: memory if _authenticate_frame.arType.ask? }
      end

      io.write memory.to_slice
    end

    def self.read_reply(io : IO, version_flag : VersionFlag = VersionFlag::V5, with_authenticate : Bool? = false) : Negotiate
      io_version_flag = Frames.strict_read_version! io: io, version_flag: version_flag
      frame = new version: io_version_flag, arType: ARType::Reply

      accepted_method = Frames.read_authentication! io: io
      frame.acceptedMethod = accepted_method

      frame.authenticateFrame = Authenticate.from_io io: io, ar_type: ARType::Reply, version_flag: version_flag if with_authenticate
      frame.successed = true

      frame
    end

    def write_reply(io : IO, version_flag : VersionFlag = VersionFlag::V5)
      raise Exception.new "Negotiate.write_reply: Negotiate.acceptedMethod cannot be Nil!" unless accepted_method = acceptedMethod

      strict_check_version! version_flag
      memory = IO::Memory.new

      memory.write Bytes[version.to_i]
      memory.write Bytes[accepted_method.to_i]

      if _authenticate_frame = authenticateFrame
        _authenticate_frame.to_io io: memory if _authenticate_frame.arType.reply?
      end

      io.write memory.to_slice
    end

    private def strict_check_version!(version_flag : VersionFlag = VersionFlag::V5) : Bool
      Frames.strict_check_version! struct_version_flag: version, version_flag: version_flag
    end
  end
end
