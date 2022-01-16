module SOCKS::Enhanced
  abstract class State
    enum QueueFlag : UInt8
      WAITING =   0_u8
      READY   =   1_u8
      REFUSED = 255_u8
    end

    enum SynchronizeFlag : UInt8
      READABLE      = 0_u8
      WRITEABLE     = 1_u8
      RESYNCHRONIZE = 2_u8
      NEGOTIATE     = 3_u8
    end

    enum RBFlag : UInt8
      READY = 1_u8
      BUSY  = 2_u8
      NONE  = 3_u8
    end

    class IncomingAlert < Exception
    end
  end
end

require "./state/*"
