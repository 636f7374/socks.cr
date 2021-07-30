module SOCKS::Enhanced
  enum ExtensionFlag : UInt8
    ASSIGN_IDENTIFIER = 2_u8
    CONNECTION_REUSE  = 3_u8
  end

  enum CommandFlag : UInt8
    CONNECTION_REUSE = 0_i8
  end

  enum ClosedFlag : UInt8
    SOURCE      = 0_u8
    DESTINATION = 1_u8
  end

  enum DecisionFlag : UInt8
    CONFIRMED =   0_u8
    REFUSED   = 255_u8
  end
end
