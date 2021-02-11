class SOCKS::Server
  class Processor
    property session : Session
    property closed : Bool?

    def initialize(@session : Session)
      @closed = nil
    end

    def alive_interval=(value : Time::Span)
      @aliveInterval = value
    end

    def alive_interval
      @aliveInterval || 1_i32.minutes
    end

    def udp_alive_interval=(value : Time::Span)
      @udpAliveInterval = value
    end

    def udp_alive_interval
      @udpAliveInterval ||= 5_i32.seconds
    end

    def heartbeat_interval=(value : Time::Span)
      @heartbeatInterval = value
    end

    def heartbeat_interval
      @heartbeatInterval ||= 3_i32.seconds
    end

    def keep_alive=(value : Bool?)
      @keepAlive = value
    end

    def keep_alive?
      @keepAlive
    end

    def perform(server : Server, reliable : Transport::Reliable = Transport::Reliable::Half)
      return session.close unless outbound = session.outbound
      perform outbound: outbound, reliable: reliable

      loop do
        break unless session.options.allowWebSocketKeepAlive
        break if session.closed?
        break unless keep_alive?

        begin
          server.establish! session
        rescue ex
          session.close rescue nil

          break
        end

        unless outbound = session.outbound
          session.close rescue nil

          break
        end

        perform outbound: outbound, reliable: reliable
      end
    end

    private def perform(outbound : IO, reliable : Transport::Reliable)
      self.keep_alive = nil

      transport = Transport.new session, outbound, heartbeat: heartbeat_proc
      transport.reliable = reliable
      set_transport_options transport
      transport.perform

      loop do
        break if check_inbound_keep_alive transport
        break if check_holding_keep_alive transport

        if transport.reliable_status.call
          transport.cleanup_all
          self.keep_alive = false

          break
        end

        next sleep 0.25_f32.seconds
      end
    end

    private def set_transport_options(transport : Transport)
      if transport.destination.is_a? UDPSocket
        udp_alive_interval.try { |_udp_alive_interval| transport.alive_interval = _udp_alive_interval }

        return
      end

      alive_interval.try { |_alive_interval| transport.alive_interval = _alive_interval }
      heartbeat_interval.try { |_heartbeat_interval| transport.heartbeat_interval = _heartbeat_interval }
    end

    private def check_inbound_keep_alive(transport : Transport) : Bool
      _session_inbound = session.inbound
      return false unless _session_inbound.is_a? Enhanced::WebSocket

      loop do
        next sleep 0.25_f32.seconds unless transport.reliable_status.call
        transport.destination.close rescue nil

        loop do
          next sleep 0.25_f32.seconds unless transport.finished?

          unless _session_inbound.keep_alive?
            transport.cleanup_all

            self.keep_alive = false
            _session_inbound.keep_alive = nil

            return true
          end

          begin
            _session_inbound.ping Enhanced::WebSocket::EnhancedPing::KeepAlive
            event = _session_inbound.receive_pong_event!
            raise Exception.new String.build { |io| io << "Received from IO to failure status (" << event.to_s << ")." } unless event.confirmed?
          rescue ex
            transport.cleanup_all

            self.keep_alive = false
            _session_inbound.keep_alive = nil

            return true
          end

          transport.cleanup_side Transport::Side::Destination, free_tls: true

          self.keep_alive = true
          _session_inbound.keep_alive = nil

          return true
        end
      end
    end

    private def check_holding_keep_alive(transport : Transport) : Bool
      _session_holding = session.holding
      return false unless _session_holding.is_a? Enhanced::WebSocket

      loop do
        _session_holding.process_enhanced_ping! rescue nil
        break if transport.reliable_status.call

        sleep 0.25_f32.seconds
      end

      transport.destination.close rescue nil

      loop do
        next sleep 0.25_f32.seconds unless transport.finished?

        unless _session_holding.keep_alive?
          transport.cleanup_all

          self.keep_alive = false
          _session_holding.keep_alive = nil

          return true
        end

        begin
          _session_holding.ping Enhanced::WebSocket::EnhancedPing::KeepAlive
          event = _session_holding.receive_pong_event!
          raise Exception.new String.build { |io| io << "Received from IO to failure status (" << event.to_s << ")." } unless event.confirmed?
        rescue ex
          transport.cleanup_all

          self.keep_alive = false
          _session_holding.keep_alive = nil

          return true
        end

        transport.cleanup_side Transport::Side::Destination, free_tls: true

        session.inbound.close rescue nil
        session.inbound = _session_holding
        session.holding = nil

        self.keep_alive = true
        _session_holding.keep_alive = nil

        return true
      end
    end

    private def heartbeat_proc : Proc(Nil)?
      ->do
        _session_inbound = session.inbound
        _session_inbound.ping if _session_inbound.is_a? Enhanced::WebSocket

        _session_holding = session.holding
        _session_holding.ping if _session_holding.is_a? Enhanced::WebSocket
      end
    end

    def close
      session.close rescue nil
      @closed = true
    end

    def closed?
      @closed
    end
  end
end
