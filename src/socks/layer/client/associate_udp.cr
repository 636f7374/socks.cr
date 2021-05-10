module SOCKS::Layer
  module Client
    class AssociateUDP < IO
      property io : UDPSocket
      property addressType : Frames::AddressFlag?
      property destinationIpAddress : Socket::IPAddress?
      property destinationAddress : Address?

      def initialize(@io : UDPSocket, @addressType : Frames::AddressFlag?)
        @destinationIpAddress = nil
        @destinationAddress = nil
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

        fragment = Frames::Fragment.from_slice source_ip_address: Socket::IPAddress.new("0.0.0.0", 0_i32), slice: buffer.to_slice[0_i32, received_length], ar_type: ARType::Reply
        raise Exception.new "Fragment.payload is Nil!" unless payload = fragment.payload

        payload_memory = IO::Memory.new payload
        payload_memory.read slice
      end

      def write(slice : Bytes) : Nil
        write slice: slice, fragment_id: 0_u8, address_type: addressType, destination_ip_address: destinationIpAddress, destination_address: destinationAddress
      end

      def write(slice : Bytes, fragment_id : UInt8, address_type : Frames::AddressFlag?, destination_ip_address : Socket::IPAddress?, destination_address : Address?) : Nil
        return nil if slice.empty?

        frame_fragment = Frames::Fragment.new version: Frames::VersionFlag::V5, arType: ARType::Ask, sourceIpAddress: Socket::IPAddress.new("0.0.0.0", 0_i32)
        frame_fragment.fragmentId = fragment_id
        frame_fragment.addressType = address_type
        frame_fragment.destinationIpAddress = destination_ip_address
        frame_fragment.destinationAddress = destination_address
        frame_fragment.payload = slice

        io.write frame_fragment.to_slice
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
