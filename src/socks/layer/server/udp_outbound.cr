module SOCKS::Layer
  module Server
    class UDPOutbound < IO
      getter io : UDPSocket
      getter timeout : TimeOut

      def initialize(@io : UDPSocket, @timeout : TimeOut)
      end

      def read_timeout=(value : Int | Time::Span | Nil)
        _io = io
        _io.read_timeout = value if value if _io.responds_to? :read_timeout=
      end

      def read_timeout
        _io = io
        _io.read_timeout if _io.responds_to? :read_timeout
      end

      def write_timeout=(value : Int | Time::Span | Nil)
        _io = io
        _io.write_timeout = value if value if _io.responds_to? :write_timeout=
      end

      def write_timeout
        _io = io
        _io.write_timeout if _io.responds_to? :write_timeout
      end

      def local_address : Socket::Address?
        _io = io
        _io.responds_to?(:local_address) ? _io.local_address : nil
      end

      def remote_address : Socket::Address?
        _io = io
        _io.responds_to?(:remote_address) ? _io.remote_address : nil
      end

      # Warning: Please read 4096 Bytes at once, not byte by byte, Because sometimes the read length is greater than 512 Bytes.
      # I.e, The Fragment structure and payload may exceed 512 Bytes, if you read 512 Bytes, it will cause incomplete reading.

      def read(slice : Bytes) : Int32
        return 0_i32 if slice.empty?

        buffer = uninitialized UInt8[4096_i32]
        received_length, ip_address = io.receive buffer.to_slice

        memory = IO::Memory.new buffer.to_slice[0_i32, received_length]
        memory.read slice
      end

      def write(slice : Bytes) : Nil
        return nil if slice.empty?

        io.connect io.remote_address, connect_timeout: timeout.connect
        io.send slice
      end

      def close
        io.close
      end

      def closed?
        io.closed?
      end
    end
  end
end
