abstract class IO
  class CopyException < Exception
    property len : Int32?
    property count : Int64?
    property bytes : Bytes?

    def initialize(@message : String? = nil, @cause : Exception? = nil, @len : Int32? = nil, @count : Int64? = nil, @bytes : Bytes? = nil)
    end
  end

  def self.yield_copy(src : IO, dst : IO, &block : Int64, Int32 ->) : Int64
    buffer = uninitialized UInt8[4096_i32]
    count = 0_i64

    begin
      while (len = src.read(buffer.to_slice).to_i32) > 0_i32
        dst.write buffer.to_slice[0_i32, len]

        count &+= len
        yield count, len

        len = 0_i32
      end
    rescue ex
      bytes = len.try { |_len| buffer.to_slice[0_i32, _len].dup }

      raise CopyException.new message: String.new, cause: ex, len: len, count: count, bytes: bytes
    end

    count
  end
end
