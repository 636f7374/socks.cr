struct SOCKS::Frames
  struct Authenticate < Frames
    property version : VersionFlag
    property arType : ARType
    property authenticationChoiceType : AuthenticationChoiceFlag?
    property userName : String?
    property password : String?
    property permissionType : PermissionFlag?

    def initialize(@version : VersionFlag, @arType : ARType)
      @authenticationChoiceType = nil
      @userName = nil
      @password = nil
      @permissionType = nil
    end

    def self.from_io(io : IO, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5) : Authenticate
      case ar_type
      in .ask?
        Authenticate.read_ask io: io, version_flag: version_flag
      in .reply?
        Authenticate.read_reply io: io, version_flag: version_flag
      end
    end

    def to_io(io : IO)
      to_io io: io, ar_type: arType, version_flag: version
    end

    def to_io(io : IO, ar_type : ARType, version_flag : VersionFlag = VersionFlag::V5) : IO
      raise Exception.new "Authenticate.to_io: version_flag and Authenticate.version do not match!" if version_flag != version
      raise Exception.new "Authenticate.to_io: ar_type and Authenticate.arType do not match!" if ar_type != arType

      case ar_type
      in .ask?
        write_ask io: io, version_flag: version_flag
      in .reply?
        write_reply io: io, version_flag: version_flag
      end

      io
    end

    def self.read_ask(io : IO, version_flag : VersionFlag = VersionFlag::V5) : Authenticate
      frame = new version: version_flag, arType: ARType::Ask
      frame.authenticationChoiceType = authentication_choice_type = Frames.read_authentication_choice! io: io

      case authentication_choice_type
      when .user_name_password?
        frame.userName = Frames.read_username! io: io
        frame.password = Frames.read_password! io: io
      else
        raise Exception.new "Authenticate.read_ask: Invalid AuthenticationChoiceFlag, Authenticate.read_ask failed!"
      end

      frame
    end

    def write_ask(io : IO, version_flag : VersionFlag = VersionFlag::V5)
      raise Exception.new "Authenticate.write_ask: Authenticate.authenticationChoiceType cannot be Nil!" unless authentication_choice_type = authenticationChoiceType
      raise Exception.new "Authenticate.write_ask: Authenticate.userName cannot be Nil!" unless user_name = userName
      raise Exception.new "Authenticate.write_ask: Authenticate.password cannot be Nil!" unless _password = password

      memory = IO::Memory.new

      case authentication_choice_type
      when .user_name_password?
        memory.write Bytes[authentication_choice_type.to_i]
        memory.write Bytes[user_name.size]
        memory.write user_name.to_slice
        memory.write Bytes[_password.size]
        memory.write _password.to_slice
      else
        raise Exception.new "Authenticate.write_ask: Invalid AuthenticationChoiceFlag, Authenticate.write_ask failed!"
      end

      io.write memory.to_slice
    end

    def self.read_reply(io : IO, version_flag : VersionFlag = VersionFlag::V5) : Authenticate
      frame = new version: version_flag, arType: ARType::Reply
      frame.authenticationChoiceType = authentication_choice_type = Frames.read_authentication_choice! io: io

      case authentication_choice_type
      when .user_name_password?
        frame.permissionType = Frames.read_permission! io: io rescue Frames::PermissionFlag::Denied
      end

      frame
    end

    def write_reply(io : IO, version_flag : VersionFlag = VersionFlag::V5)
      raise Exception.new "Authenticate.write_reply: Authenticate.authenticationChoiceType cannot be Nil!" unless authentication_choice_type = authenticationChoiceType
      raise Exception.new "Authenticate.write_reply: Authenticate.permissionType cannot be Nil!" unless permission_type = permissionType

      memory = IO::Memory.new

      case authentication_choice_type
      when .user_name_password?
        memory.write Bytes[authentication_choice_type.to_i]
        memory.write Bytes[permission_type.to_i]
      else
        raise Exception.new "Authenticate.write_reply: Invalid AuthenticationChoiceFlag, Authenticate.write_reply failed!"
      end

      io.write memory.to_slice
    end
  end
end
