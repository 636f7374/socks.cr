abstract class IO
  class CopyException < Exception
    property count : Int64?

    def initialize(@message : String? = nil, @cause : Exception? = nil, @count : Int64? = nil)
    end
  end

  def self.super_copy(src : IO, dst : IO, &block : ->) : Int64
    buffer = uninitialized UInt8[4096_i32]
    count = 0_i64

    begin
      while (len = src.read(buffer.to_slice).to_i32) > 0_i32
        dst.write buffer.to_slice[0_i32, len]
        count &+= len

        yield
      end
    rescue ex
      raise CopyException.new message: String.new, cause: ex, count: count
    end

    count
  end
end
