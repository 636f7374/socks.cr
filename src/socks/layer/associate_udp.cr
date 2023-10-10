module SOCKS::Layer
  class AssociateUDP < IO
    getter targetAddress : Socket::IPAddress | Address
    getter source : UDPSocket
    getter destination : UDPSocket
    getter inboundIpAddress : Socket::IPAddress?
    getter outboundIpAddress : Socket::IPAddress
    getter inboundForwardIpAddress : Socket::IPAddress?
    getter outboundForwardIpAddress : Socket::IPAddress?
    getter lastAliveTime : Atomic(Int64)
    getter sentBytes : Atomic(UInt64)
    getter receivedBytes : Atomic(UInt64)
    getter rawMode : Atomic(Int8)
    getter sourceEnhancedAssociateUdp : Atomic(Int8)
    getter destinationEnhancedAssociateUdp : Atomic(Int8)
    getter running : Atomic(Int8)
    getter closed : Atomic(Int8)
    getter rwLock : Crystal::RWLock

    def initialize(@targetAddress : Socket::IPAddress | Address, @outboundIpAddress : Socket::IPAddress, @source : UDPSocket)
      @destination = UDPSocket.new
      @inboundIpAddress = nil
      @inboundForwardIpAddress = nil
      @outboundForwardIpAddress = nil
      @lastAliveTime = Atomic(Int64).new -1_i64
      @sentBytes = Atomic(UInt64).new 0_u64
      @receivedBytes = Atomic(UInt64).new 0_u64
      @rawMode = Atomic(Int8).new value: -1_i8
      @sourceEnhancedAssociateUdp = Atomic(Int8).new value: -1_i8
      @destinationEnhancedAssociateUdp = Atomic(Int8).new value: -1_i8
      @running = Atomic(Int8).new value: -1_i8
      @closed = Atomic(Int8).new value: -1_i8
      @rwLock = Crystal::RWLock.new
    end

    def self.new(dns_resolver : DNS::Resolver, target_address : Socket::IPAddress | Address, source : UDPSocket)
      _resolve_target_address = case target_address
                                in SOCKS::Address
                                  packets = dns_resolver.getaddrinfo host: target_address.host, port: target_address.port
                                  fetch_method, fetch_type, ip_addresses = packets

                                  ip_addresses.first
                                in Socket::IPAddress
                                  target_address
                                end

      new targetAddress: target_address, outboundIpAddress: _resolve_target_address, source: source
    end

    def source_enhanced_associate_udp=(value : Bool)
      @rwLock.write_lock
      @sourceEnhancedAssociateUdp.set value: (value == true ? 0_i8 : -1_i8)
      @rwLock.write_unlock
    end

    def source_enhanced_associate_udp? : Bool
      @rwLock.read_lock
      _source_enhanced_associate_udp = @sourceEnhancedAssociateUdp.get.zero?
      @rwLock.read_unlock

      _source_enhanced_associate_udp
    end

    def destination_enhanced_associate_udp=(value : Bool)
      @rwLock.write_lock
      @destinationEnhancedAssociateUdp.set value: (value == true ? 0_i8 : -1_i8)
      @rwLock.write_unlock
    end

    def destination_enhanced_associate_udp? : Bool
      @rwLock.read_lock
      _destination_enhanced_associate_udp = @destinationEnhancedAssociateUdp.get.zero?
      @rwLock.read_unlock

      _destination_enhanced_associate_udp
    end

    def inbound_ip_address=(value : Socket::IPAddress)
      @rwLock.write_lock
      @inboundIpAddress = value
      @rwLock.write_unlock
    end

    def outbound_ip_address=(value : Socket::IPAddress)
      @rwLock.write_lock
      @outboundIpAddress = value
      @rwLock.write_unlock
    end

    def inbound_forward_ip_address=(value : Socket::IPAddress)
      @rwLock.write_lock
      @inboundForwardIpAddress = value
      @rwLock.write_unlock
    end

    def outbound_forward_ip_address=(value : Socket::IPAddress)
      @rwLock.write_lock
      @outboundForwardIpAddress = value
      @rwLock.write_unlock
    end

    def local_address : Socket::IPAddress
      @source.local_address
    end

    def raw_mode=(value : Bool)
      @rwLock.write_lock
      @rawMode.set value: (value == true ? 0_i8 : -1_i8)
      @rwLock.write_unlock
    end

    def raw_mode? : Bool
      @rwLock.read_lock
      _raw_mode = @rawMode.get.zero?
      @rwLock.read_unlock

      _raw_mode
    end

    def running=(value : Bool)
      @rwLock.write_lock
      @running.set value: (value == true ? 0_i8 : -1_i8)
      @rwLock.write_unlock
    end

    def running? : Bool
      @rwLock.read_lock
      _running = @running.get.zero?
      @rwLock.read_unlock

      _running
    end

    def closed? : Bool
      @rwLock.read_lock
      _closed = @closed.get.zero?
      @rwLock.read_unlock

      _closed
    end

    def last_alive_time : Int64
      @lastAliveTime.get
    end

    # inbound_forward_ip_address until source receive first buffer parse.
    def forward_source : Bool
      raise Exception.new "Layer::AssociateUDP.forward_destination: closed!" if self.closed?

      modified_buffer = uninitialized UInt8[4096_i32]
      buffer = uninitialized UInt8[4096_i32]
      received_length, ip_address = @source.receive message: buffer.to_slice
      @lastAliveTime.set value: Time.local.to_unix_ms

      # Update inboundIpAddress

      @rwLock.write_lock
      @inboundIpAddress = ip_address unless @inboundIpAddress
      @rwLock.write_unlock

      #####################
      # EnhancedUDP handle.
      #####################

      @rwLock.read_lock
      _outbound_forward_ip_address = @outboundForwardIpAddress.dup
      _outbound_ip_address = @outboundIpAddress.dup
      @rwLock.read_unlock

      if source_enhanced_associate_udp?
        forward_ip46_flag = Frames::ModifiedIp46Flag.from_value value: buffer.to_slice[0_u8]
        return false if received_length <= (forward_ip46_flag.ipv4? ? 8_u8 : 20_u8) # received_length <= minimum_length

        _inbound_forward_ip_address = Socket::IPAddress.parse slice: buffer.to_slice[1_u8..(forward_ip46_flag.ipv4? ? 6_u8 : 18_u8)], family: (forward_ip46_flag.ipv4? ? Socket::Family::INET : Socket::Family::INET6), with_port: true
        self.inbound_forward_ip_address = _inbound_forward_ip_address # Default Nil, Update value.

        #
        #

        if _outbound_forward_ip_address
          # EnhancedUDP => EnhancedUDP

          modified_buffer.to_slice[0_u8] = (_outbound_forward_ip_address.family.inet? ? Frames::Ip46Flag::Ipv4 : Frames::Ip46Flag::Ipv6).value
          _outbound_forward_ip_address.to_slice slice: modified_buffer.to_slice[1_u8..(_outbound_forward_ip_address.family.inet? ? 6_u8 : 18_u8)]
          modified_buffer.to_slice[(_outbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8)...].copy_from source: buffer.to_slice[(_inbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8)..(received_length - 1_u8)]
          @destination.send message: modified_buffer.to_slice[0_u8, (received_length - (_inbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8) + (_outbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8))], to: _outbound_ip_address
        else
          # EnhancedUDP => NormalUDP

          pos = (_inbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8)
          _fragment = Frames::Fragment.from_slice slice: buffer.to_slice[pos..(received_length - 1_u8)], ar_type: ARType::Ask, command_flag: Frames::CommandFlag::AssociateUDP
          _fragment.payload.try { |payload| @destination.send message: payload, to: _outbound_ip_address }
        end

        #
        #

        @rwLock.write_lock
        @sentBytes.add(value: received_length.to_u64) rescue @sentBytes.set(value: 0_u64)
        @rwLock.write_unlock

        return true
      end

      if destination_enhanced_associate_udp? && _outbound_forward_ip_address
        # NormalUDP => EnhancedUDP

        modified_buffer.to_slice[0_u8] = (_outbound_forward_ip_address.family.inet? ? Frames::Ip46Flag::Ipv4 : Frames::Ip46Flag::Ipv6).value
        _outbound_forward_ip_address.to_slice slice: modified_buffer.to_slice[1_u8..(_outbound_forward_ip_address.family.inet? ? 6_u8 : 18_u8)]
        modified_buffer.to_slice[(_outbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8)...].copy_from source: buffer.to_slice[0_u8, received_length]
        @destination.send message: modified_buffer.to_slice[0_u8, (received_length + (_outbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8))], to: _outbound_ip_address

        @rwLock.write_lock
        @sentBytes.add(value: received_length.to_u64) rescue @sentBytes.set(value: 0_u64)
        @rwLock.write_unlock

        return true
      end

      ####################
      # NortmalUDP handle.
      ####################

      if self.raw_mode?
        # for Relay.

        @destination.send message: buffer.to_slice[0_i32, received_length], to: _outbound_ip_address
      else
        # for Server (Endpoint).

        _fragment = Frames::Fragment.from_slice slice: buffer.to_slice[0_i32, received_length], ar_type: ARType::Ask, command_flag: Frames::CommandFlag::AssociateUDP
        raise Exception.new "SOCKS::Layer::AssociateUDP.process_send: Fragment.payload is Nil!" unless payload = _fragment.payload

        # Client (Inbound) -> UDP Relay -> Target (Outbound)

        @destination.send message: payload, to: _outbound_ip_address

        @rwLock.write_lock
        @sentBytes.add(value: received_length.to_u64) rescue @sentBytes.set(value: 0_u64)
        @rwLock.write_unlock
      end

      true
    end

    def forward_destination : Bool
      raise Exception.new "Layer::AssociateUDP.forward_destination: closed!" if self.closed?

      #
      #

      @rwLock.read_lock

      unless _inbound_ip_address = @inboundIpAddress.dup
        @rwLock.read_unlock

        sleep 0.05_f32.seconds
        return false
      end

      @rwLock.read_unlock

      #
      #

      modified_buffer = uninitialized UInt8[4096_i32]
      buffer = uninitialized UInt8[4096_i32]
      received_length, ip_address = @destination.receive message: buffer.to_slice
      @lastAliveTime.set value: Time.local.to_unix_ms

      #####################
      # EnhancedUDP handle.
      #####################

      @rwLock.read_lock
      _inbound_forward_ip_address = @inboundForwardIpAddress.dup
      @rwLock.read_unlock

      if destination_enhanced_associate_udp?
        forward_ip46_flag = Frames::ModifiedIp46Flag.from_value value: buffer.to_slice[0_u8]
        return false if received_length <= (forward_ip46_flag.ipv4? ? 8_u8 : 20_u8) # received_length <= minimum_length

        _outbound_forward_ip_address = Socket::IPAddress.parse slice: buffer.to_slice[1_u8..(forward_ip46_flag.ipv4? ? 6_u8 : 18_u8)], family: (forward_ip46_flag.ipv4? ? Socket::Family::INET : Socket::Family::INET6), with_port: true
        self.outbound_forward_ip_address = _outbound_forward_ip_address # Default Nil, Update value.

        #
        #

        if _inbound_forward_ip_address
          # EnhancedUDP => EnhancedUDP

          modified_buffer.to_slice[0_u8] = (_inbound_forward_ip_address.family.inet? ? Frames::Ip46Flag::Ipv4 : Frames::Ip46Flag::Ipv6).value
          _inbound_forward_ip_address.to_slice slice: modified_buffer.to_slice[1_u8..(_inbound_forward_ip_address.family.inet? ? 6_u8 : 18_u8)]
          modified_buffer.to_slice[(_inbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8)...].copy_from source: buffer.to_slice[(_outbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8)..(received_length - 1_u8)]
          @destination.send message: modified_buffer.to_slice[0_u8, (received_length - (_outbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8) + (_inbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8))], to: _inbound_ip_address
        else
          # EnhancedUDP => NormalUDP
          pos = (_outbound_forward_ip_address.family.inet? ? 7_u8 : 19_u8)
          @destination.send message: buffer.to_slice[pos..(received_length - 1_u8)], to: _inbound_ip_address
        end

        #
        #

        @rwLock.write_lock
        @receivedBytes.add(value: received_length.to_u64) rescue @receivedBytes.set(value: 0_u64)
        @rwLock.write_unlock

        return true
      end

      ####################
      # NortmalUDP handle.
      ####################

      if self.raw_mode?
        @rwLock.read_lock
        @source.send message: buffer.to_slice[0_i32, received_length], to: _inbound_ip_address
        @rwLock.read_unlock
      else
        frame_fragment = Frames::Fragment.new version: Frames::VersionFlag::V5, arType: ARType::Reply
        frame_fragment.forwardIpAddress = _inbound_forward_ip_address
        frame_fragment.fragmentId = 0_u8
        frame_fragment.payload = buffer.to_slice[0_i32, received_length]

        case target_address = @targetAddress
        in Socket::IPAddress
          frame_fragment.addressType = target_address.family.inet? ? Frames::AddressFlag::Ipv4 : Frames::AddressFlag::Ipv6
          frame_fragment.destinationIpAddress = target_address
        in Address
          frame_fragment.addressType = Frames::AddressFlag::Domain
          frame_fragment.destinationAddress = target_address
        end

        # Target (Outbound) -> UDP Relay -> Client (Inbound)

        @rwLock.read_lock
        @source.send message: frame_fragment.to_slice, to: _inbound_ip_address rescue nil
        @rwLock.read_unlock

        @rwLock.write_lock
        @receivedBytes.add(value: received_length.to_u64) rescue @receivedBytes.set(value: 0_u64)
        @rwLock.write_unlock
      end

      true
    end

    def read(slice : Bytes) : Int32
      @rwLock.write_lock

      if @running.get.zero? || @closed.get.zero?
        @rwLock.write_unlock
        sleep 1_i32.seconds

        return 0_i32
      end

      @running.set value: 0_i8
      @rwLock.write_unlock

      spawn do
        loop do
          begin
            forward_source
          rescue ex
            self.running = false

            break
          end
        end
      end

      spawn do
        loop do
          begin
            forward_destination
          rescue ex
            self.running = false

            break
          end
        end
      end

      loop do
        next sleep 0.5_f32.seconds if running?

        break
      end

      0_i32
    end

    def write(slice : Bytes) : Nil
    end

    def close
      @rwLock.write_lock

      if @closed.get.zero?
        @rwLock.write_unlock

        return
      end

      @running.set value: -1_i8
      @closed.set value: 0_i8
      @source.close rescue nil
      @destination.close rescue nil

      @rwLock.write_unlock
    end
  end
end

require "crystal/rw_lock"
