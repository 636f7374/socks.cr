module SOCKS::Layer
  module Server
    class AssociateUDP < IO
      getter io : UDPSocket
      getter timeout : TimeOut
      getter sourceIpAddress : Socket::IPAddress?
      getter fragment : Frames::Fragment?
      getter mutex : Mutex

      def initialize(@io : UDPSocket, @timeout : TimeOut = TimeOut.udp_default)
        @sourceIpAddress = nil
        @fragment = nil
        @mutex = Mutex.new :unchecked
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

        fragment = Frames::Fragment.from_slice source_ip_address: ip_address, slice: buffer.to_slice[0_i32, received_length], ar_type: ARType::Ask
        raise Exception.new "Fragment.payload is Nil!" unless payload = fragment.payload

        @mutex.synchronize do
          if source_ip_address = sourceIpAddress
            return 0_i32 if ip_address != source_ip_address
          end

          @sourceIpAddress = ip_address
          @fragment = fragment
        end

        payload_memory = IO::Memory.new payload
        payload_memory.read slice
      end

      def write(slice : Bytes) : Nil
        return nil if slice.empty?
        return nil unless source_ip_address = @mutex.synchronize { sourceIpAddress }
        return nil unless _fragment = @mutex.synchronize { fragment }

        frame_fragment = Frames::Fragment.new version: Frames::VersionFlag::V5, arType: ARType::Reply, sourceIpAddress: source_ip_address
        frame_fragment.fragmentId = _fragment.fragmentId
        frame_fragment.addressType = _fragment.addressType
        frame_fragment.destinationIpAddress = _fragment.destinationIpAddress
        frame_fragment.destinationAddress = _fragment.destinationAddress
        frame_fragment.payload = slice

        io.connect ip_address: source_ip_address, connect_timeout: timeout.connect
        io.send message: frame_fragment.to_slice
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
