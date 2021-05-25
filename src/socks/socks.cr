module SOCKS
  enum ARType : UInt8
    Ask   = 0_u8
    Reply = 1_u8
  end

  def self.to_ip_address(host : String, port : Int32)
    Socket::IPAddress.new host, port rescue nil
  end

  def self.create_outbound_socket(command_type : Frames::CommandFlag, destination_address : Socket::IPAddress | Address, dns_resolver : DNS::Resolver, tcp_timeout : TimeOut = TimeOut.new, udp_timeout : TimeOut = TimeOut.udp_default) : ::IPSocket
    case destination_address
    in Socket::IPAddress
      case destination_address.family
      when .inet6?
        create_outbound_socket command_type: command_type, destination_address: destination_address, tcp_timeout: tcp_timeout, udp_timeout: udp_timeout
      when .inet?
        create_outbound_socket command_type: command_type, destination_address: destination_address, tcp_timeout: tcp_timeout, udp_timeout: udp_timeout
      else
        raise Exception.new "SOCKS.create_outbound_socket: Unsupported Socket::IPAddress family, Server.create_outbound_socket failed!"
      end
    in Address
      create_outbound_socket command_type: command_type, destination_address: destination_address, dns_resolver: dns_resolver, tcp_timeout: tcp_timeout, udp_timeout: udp_timeout
    end
  end

  def self.create_outbound_socket(command_type : Frames::CommandFlag, destination_address : Socket::IPAddress, tcp_timeout : TimeOut = TimeOut.new, udp_timeout : TimeOut = TimeOut.udp_default) : ::IPSocket
    case command_type
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
      socket.read_timeout = udp_timeout.read
      socket.write_timeout = udp_timeout.write

      begin
        socket.connect ip_address: destination_address, connect_timeout: udp_timeout.connect
      rescue ex
        socket.close

        raise ex
      end
    end

    socket
  end

  def self.create_outbound_socket(command_type : Frames::CommandFlag, destination_address : Address, dns_resolver : DNS::Resolver, tcp_timeout : TimeOut = TimeOut.new, udp_timeout : TimeOut = TimeOut.udp_default) : ::IPSocket
    case command_type
    in .tcp_connection?
      socket = TCPSocket.new host: destination_address.host, port: destination_address.port, dns_resolver: dns_resolver, delegator: nil, connect_timeout: tcp_timeout.connect
      socket.read_timeout = tcp_timeout.read
      socket.write_timeout = tcp_timeout.write
    in .tcp_binding?
      socket = TCPSocket.new host: destination_address.host, port: destination_address.port, dns_resolver: dns_resolver, delegator: nil, connect_timeout: tcp_timeout.connect
      socket.read_timeout = tcp_timeout.read
      socket.write_timeout = tcp_timeout.write
    in .associate_udp?
      socket = UDPSocket.new

      begin
        socket.connect host: destination_address.host, port: destination_address.port, dns_resolver: dns_resolver, connect_timeout: udp_timeout.connect
      rescue ex
        socket.close rescue nil

        raise ex
      end

      socket.read_timeout = udp_timeout.read
      socket.write_timeout = udp_timeout.write
    end

    socket
  end
end
