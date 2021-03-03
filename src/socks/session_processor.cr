class SOCKS::SessionProcessor
  property session : Session
  property closed : Bool?

  def initialize(@session : Session)
    @closed = nil
  end

  private def keep_alive=(value : Bool?)
    @keepAlive = value
  end

  private def keep_alive?
    @keepAlive
  end

  def perform(server : Server)
    return session.close unless outbound = session.outbound
    perform outbound: outbound

    loop do
      break unless session.options.server.allowWebSocketKeepAlive
      break unless check_support_keep_alive?
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

      perform outbound: outbound
    end
  end

  private def perform(outbound : IO)
    self.keep_alive = nil

    transport = Transport.new source: session, destination: outbound, heartbeat: heartbeat_proc
    set_transport_options transport: transport
    transport.perform

    loop do
      break if check_inbound_keep_alive transport: transport
      break if check_holding_keep_alive transport: transport

      if transport.done?
        transport.cleanup
        self.keep_alive = false

        break
      end

      next sleep 0.25_f32.seconds
    end
  end

  private def set_transport_options(transport : Transport)
    if transport.destination.is_a? Quirks::Server::UDPOutbound
      transport.aliveInterval = session.options.session.udpAliveInterval
    else
      transport.aliveInterval = session.options.session.aliveInterval
    end

    transport.heartbeatInterval = session.options.session.heartbeatInterval
  end

  private def check_support_keep_alive? : Bool
    _session_inbound = session.inbound
    _session_holding = session.holding

    _session_inbound.is_a?(Enhanced::WebSocket) || _session_holding.is_a?(Enhanced::WebSocket)
  end

  private def check_inbound_keep_alive(transport : Transport) : Bool
    _session_inbound = session.inbound
    return false unless _session_inbound.is_a? Enhanced::WebSocket

    loop do
      next sleep 0.25_f32.seconds unless transport.done?
      transport.destination.close rescue nil

      loop do
        next sleep 0.25_f32.seconds unless transport.finished?

        unless _session_inbound.keep_alive?
          transport.cleanup

          self.keep_alive = false
          _session_inbound.keep_alive = nil

          return true
        end

        begin
          _session_inbound.ping Enhanced::WebSocket::EnhancedPing::KeepAlive
          event = _session_inbound.receive_pong_event!
          raise Exception.new String.build { |io| io << "Received from IO to failure status (" << event.to_s << ")." } unless event.confirmed?
        rescue ex
          transport.cleanup

          self.keep_alive = false
          _session_inbound.keep_alive = nil

          return true
        end

        transport.cleanup Transport::Side::Destination, free_tls: true

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
      next sleep 0.25_f32.seconds unless transport.done?

      transport.destination.close rescue nil
      _session_holding.process_enhanced_ping! rescue nil

      break
    end

    loop do
      next sleep 0.25_f32.seconds unless transport.finished?

      unless _session_holding.keep_alive?
        transport.cleanup

        self.keep_alive = false
        _session_holding.keep_alive = nil

        return true
      end

      begin
        _session_holding.ping Enhanced::WebSocket::EnhancedPing::KeepAlive
        event = _session_holding.receive_pong_event!
        raise Exception.new String.build { |io| io << "Received from IO to failure status (" << event.to_s << ")." } unless event.confirmed?
      rescue ex
        transport.cleanup

        self.keep_alive = false
        _session_holding.keep_alive = nil

        return true
      end

      transport.cleanup Transport::Side::Destination, free_tls: true

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
