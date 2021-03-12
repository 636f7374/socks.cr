class SOCKS::SessionProcessor
  property session : Session

  def initialize(@session : Session)
  end

  private def keep_alive=(value : Bool?)
    @keepAlive = value
  end

  private def keep_alive?
    @keepAlive
  end

  def perform(server : Server)
    return session.cleanup unless outbound = session.outbound

    transport = Transport.new source: session, destination: outbound, heartbeat: heartbeat_proc
    set_transport_options transport: transport
    session.set_transport_tls transport: transport
    perform transport: transport
    transport.reset!

    loop do
      break unless session.options.server.allowWebSocketKeepAlive
      break unless check_support_keep_alive?
      break if session.closed?
      break unless keep_alive?

      begin
        server.establish! session
      rescue ex
        session.cleanup rescue nil
        session.reset reset_tls: true

        break
      end

      unless outbound = session.outbound
        session.cleanup rescue nil
        session.reset reset_tls: true

        break
      end

      transport.destination = outbound
      perform transport: transport
      transport.reset!
    end
  end

  private def perform(transport : Transport)
    self.keep_alive = nil
    transport.perform

    loop do
      break if check_inbound_keep_alive transport: transport
      break if check_holding_keep_alive transport: transport

      if transport.done?
        transport.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        break
      end

      next sleep 0.25_f32.seconds
    end
  end

  def perform(outbound : IO, keepalive_pool : KeepAlivePool)
    transport = Transport.new source: session, destination: outbound, heartbeat: heartbeat_proc
    session.set_transport_tls transport: transport
    perform transport: transport, keepalive_pool: keepalive_pool
  end

  def perform(transport : Transport, keepalive_pool : KeepAlivePool)
    set_transport_options transport: transport
    self.keep_alive = nil
    transport.perform

    loop do
      break if check_outbound_keep_alive transport: transport, keepalive_pool: keepalive_pool

      if transport.done?
        transport.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        break
      end

      next sleep 0.25_f32.seconds
    end
  end

  private def set_transport_options(transport : Transport)
    transport.heartbeatInterval = session.options.session.heartbeatInterval
    transport.aliveInterval = session.options.session.aliveInterval

    return unless transport.destination.is_a? Quirks::Server::UDPOutbound
    transport.aliveInterval = session.options.session.udpAliveInterval
  end

  private def check_support_keep_alive? : Bool
    session.inbound.is_a?(Enhanced::WebSocket) || session.holding.is_a?(Enhanced::WebSocket)
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
          session.reset reset_tls: true

          self.keep_alive = false
          _session_inbound.keep_alive = nil

          return true
        end

        begin
          _session_inbound.ping Enhanced::WebSocket::EnhancedPing::KeepAlive
          received = _session_inbound.receive_pong_event!
          raise Exception.new String.build { |io| io << "SessionProcessor.check_inbound_keep_alive: Received from IO to failure status (" << received << ")." } unless received.confirmed?
        rescue ex
          transport.cleanup
          session.reset reset_tls: true

          self.keep_alive = false
          _session_inbound.keep_alive = nil

          return true
        end

        transport.cleanup side: Transport::Side::Destination, free_tls: true, reset: true
        session.reset_peer side: Transport::Side::Destination, reset_tls: true

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
        session.reset reset_tls: true

        self.keep_alive = false
        _session_holding.keep_alive = nil

        return true
      end

      begin
        _session_holding.ping Enhanced::WebSocket::EnhancedPing::KeepAlive
        received = _session_holding.receive_pong_event!
        raise Exception.new String.build { |io| io << "SessionProcessor.check_holding_keep_alive: Received from IO to failure status (" << received << ")." } unless received.confirmed?
      rescue ex
        transport.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        _session_holding.keep_alive = nil

        return true
      end

      transport.cleanup side: Transport::Side::Destination, free_tls: true, reset: true
      session.reset_peer side: Transport::Side::Destination, reset_tls: true

      session.inbound.close rescue nil
      session.inbound = _session_holding
      session.holding = nil

      self.keep_alive = true
      _session_holding.keep_alive = nil

      return true
    end
  end

  private def check_outbound_keep_alive(transport : Transport, keepalive_pool : KeepAlivePool) : Bool
    transport_destination = transport.destination
    return false unless transport_destination.is_a? Client
    enhanced_websocket = transport_destination.outbound
    return false unless enhanced_websocket.is_a? Enhanced::WebSocket

    loop do
      next sleep 0.25_f32.seconds unless transport.sent_done?
      enhanced_websocket.ping SOCKS::Enhanced::WebSocket::EnhancedPing::KeepAlive rescue nil

      break
    end

    loop do
      next sleep 0.25_f32.seconds unless transport.finished?

      unless enhanced_websocket.keep_alive?
        transport.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        enhanced_websocket.keep_alive = nil

        return true
      end

      begin
        received = enhanced_websocket.receive_ping_event!
        raise Exception.new String.build { |io| io << "SessionProcessor.check_outbound_keep_alive: Received from IO to failure status (" << received << ")." } unless received.keep_alive?
        enhanced_websocket.pong event: SOCKS::Enhanced::WebSocket::EnhancedPong::Confirmed
      rescue ex
        transport.cleanup
        session.reset reset_tls: true

        self.keep_alive = false
        enhanced_websocket.keep_alive = nil

        return true
      end

      transport.cleanup side: Transport::Side::Source, free_tls: true, reset: true
      session.reset_peer side: Transport::Side::Source, reset_tls: true
      transport.reset!

      session.holding.try &.close rescue nil
      session.holding = nil
      transport_destination.holding.try &.close rescue nil
      transport_destination.holding = nil

      self.keep_alive = true
      enhanced_websocket.keep_alive = nil
      keepalive_pool.unshift value: transport

      return true
    end
  end

  private def heartbeat_proc : Proc(Nil)?
    ->do
      _session_inbound = session.inbound
      _session_inbound.ping rescue nil if _session_inbound.is_a? Enhanced::WebSocket

      _session_holding = session.holding
      _session_holding.ping rescue nil if _session_holding.is_a? Enhanced::WebSocket

      _session_outbound = session.outbound
      return unless _session_outbound.is_a? Client
      enhanced_websocket = _session_outbound.outbound
      return unless enhanced_websocket.is_a? Enhanced::WebSocket
      enhanced_websocket.ping rescue nil
    end
  end
end
