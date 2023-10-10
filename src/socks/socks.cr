module SOCKS
  enum ARType : UInt8
    Ask   = 0_u8
    Reply = 1_u8
  end

  enum ConnectionIdentifierDecisionFlag : UInt8
    VALID_FORMAT   = 0_u8
    INVALID_FORMAT = 1_i8
    UNSUPPORTED    = 2_u8
  end

  enum ConnectionReuseDecisionFlag : UInt8
    SUPPORTED   = 0_u8
    UNSUPPORTED = 1_u8
  end

  enum ConnectionPauseDecisionFlag : UInt8
    VALID       = 0_u8
    PENDING     = 1_u8
    INVALID     = 2_u8
    SUPPORTED   = 3_u8
    UNSUPPORTED = 4_u8
  end

  def self.to_ip_address(host : String, port : Int32)
    Socket::IPAddress.new address: host, port: port rescue nil
  end

  def self.create_outbound_socket(command_flag : Frames::CommandFlag, destination_address : Socket::IPAddress | Address, dns_resolver : DNS::Resolver, tcp_timeout : TimeOut = TimeOut.new) : ::IPSocket
    case destination_address
    in Socket::IPAddress
      case destination_address.family
      when .inet6?
        create_outbound_socket command_flag: command_flag, destination_address: destination_address, tcp_timeout: tcp_timeout
      when .inet?
        create_outbound_socket command_flag: command_flag, destination_address: destination_address, tcp_timeout: tcp_timeout
      else
        raise Exception.new "SOCKS.create_outbound_socket: Unsupported Socket::IPAddress family, Server.create_outbound_socket failed!"
      end
    in Address
      create_outbound_socket command_flag: command_flag, destination_address: destination_address, dns_resolver: dns_resolver, tcp_timeout: tcp_timeout
    end
  end

  def self.create_outbound_socket(command_flag : Frames::CommandFlag, destination_address : Socket::IPAddress, tcp_timeout : TimeOut = TimeOut.new) : ::IPSocket
    case command_flag
    in .tcp_connection?
      socket = TCPSocket.new ip_address: destination_address, connect_timeout: tcp_timeout.connect
      socket.read_timeout = tcp_timeout.read
      socket.write_timeout = tcp_timeout.write
    in .tcp_binding?
      socket = TCPSocket.new ip_address: destination_address, connect_timeout: tcp_timeout.connect
      socket.read_timeout = tcp_timeout.read
      socket.write_timeout = tcp_timeout.write
    in .associate_udp?
      socket = UDPSocket.new family: destination_address.family
    in .enhanced_associate_udp?
      socket = UDPSocket.new family: destination_address.family
    end

    socket
  end

  def self.create_outbound_socket(command_flag : Frames::CommandFlag, destination_address : Address, dns_resolver : DNS::Resolver, tcp_timeout : TimeOut = TimeOut.new) : ::IPSocket
    case command_flag
    in .tcp_connection?
      socket = TCPSocket.new host: destination_address.host, port: destination_address.port, dns_resolver: dns_resolver, connect_timeout: tcp_timeout.connect, caller: nil
      socket.read_timeout = tcp_timeout.read
      socket.write_timeout = tcp_timeout.write
    in .tcp_binding?
      socket = TCPSocket.new host: destination_address.host, port: destination_address.port, dns_resolver: dns_resolver, connect_timeout: tcp_timeout.connect, caller: nil
      socket.read_timeout = tcp_timeout.read
      socket.write_timeout = tcp_timeout.write
    in .associate_udp?
      socket = UDPSocket.new
    in .enhanced_associate_udp?
      socket = UDPSocket.new
    end

    socket
  end

  def self.create_bind_socket(dns_resolver : DNS::Resolver, session : Session, command_flag : Frames::CommandFlag, destination_address : Socket::IPAddress | Address, tcp_timeout : TimeOut) : Tuple(Socket::IPAddress, TCPServer | Layer::AssociateUDP)
    case command_flag
    in .tcp_connection?
      raise Exception.new "SOCKS.create_bind_socket: Unsupported CommandType (Frames::CommandFlag::TCPConnection)."
    in .tcp_binding?
      create_tcp_bind_socket session: session, tcp_timeout: tcp_timeout
    in .associate_udp?
      create_udp_bind_socket dns_resolver: dns_resolver, session: session, command_flag: command_flag, destination_address: destination_address
    in .enhanced_associate_udp?
      create_udp_bind_socket dns_resolver: dns_resolver, session: session, command_flag: command_flag, destination_address: destination_address
    end
  end

  def self.create_tcp_bind_socket(session : Session, tcp_timeout : TimeOut) : Tuple(Socket::IPAddress, TCPServer)
    session_source = session.source
    session_local_address = session_source.local_address rescue nil if session_source.responds_to? :local_address

    unless session_local_address
      raise Exception.new String.build { |io| io << "SOCKS.create_tcp_bind_socket!: Failed to get client local_address." }
    end

    case session_local_address
    in Socket::UNIXAddress
      raise Exception.new String.build { |io| io << "SOCKS.create_tcp_bind_socket!: Get the client local_address is UNIXAddress." }
    in Socket::IPAddress
    in Socket::Address
      raise Exception.new String.build { |io| io << "SOCKS.create_tcp_bind_socket!: Get the client local_address is Address." }
    end

    socket = TCPServer.new host: session_local_address.address, port: 0_i32
    socket.read_timeout = tcp_timeout.read
    socket.write_timeout = tcp_timeout.write

    begin
      socket_local_address = socket.local_address
    rescue ex
      socket.close rescue nil

      raise ex
    end

    Tuple.new socket_local_address, socket
  end

  def self.create_udp_bind_socket(dns_resolver : DNS::Resolver, session : Session, command_flag : Frames::CommandFlag, destination_address : Socket::IPAddress | Address) : Tuple(Socket::IPAddress, Layer::AssociateUDP)
    session_source = session.source
    session_local_address = session_source.local_address rescue nil if session_source.responds_to? :local_address

    unless session_local_address
      raise Exception.new String.build { |io| io << "SOCKS.create_udp_bind_socket!: Failed to get client local_address." }
    end

    case session_local_address
    in Socket::UNIXAddress
      raise Exception.new String.build { |io| io << "SOCKS.create_udp_bind_socket!: Get the client local_address is UNIXAddress." }
    in Socket::IPAddress
    in Socket::Address
      raise Exception.new String.build { |io| io << "SOCKS.create_udp_bind_socket!: Get the client local_address is Address." }
    end

    socket = UDPSocket.new family: session_local_address.family

    begin
      socket.bind session_local_address.address, 0_i32
      socket_local_address = socket.local_address
    rescue ex
      socket.close rescue nil

      raise ex
    end

    socket = Layer::AssociateUDP.new dns_resolver: dns_resolver, target_address: destination_address, source: socket
    socket.source_enhanced_associate_udp = true if command_flag.enhanced_associate_udp?

    Tuple.new socket_local_address, socket
  end
end
