module SOCKS::Enhanced
  enum ExtensionFlag : UInt8
    ASSIGN_IDENTIFIER = 2_u8
    CONNECTION_REUSE  = 3_u8
    CONNECTION_PAUSE  = 4_u8
  end

  enum CommandFlag : UInt8
    CONNECTION_REUSE = 0_u8
    CONNECTION_PAUSE = 1_u8
  end

  enum StateFlag : UInt8
    SENT               = 0_u8
    RECEIVED_CONFIRMED = 1_u8
    RESYNCHRONIZE      = 2_u8
    COMMAND            = 3_u8
    INCOMING           = 4_u8
    HEARTBEAT          = 5_u8
  end
end
