class SOCKS::Server
  private def check_destination_blocker!(destination_address : Address | Socket::IPAddress) : Bool
    # This function is used as an overridable.

    return true unless destination_blocker = options.server.destinationBlocker

    case destination_address
    in Address
      to_ip_address = Socket::IPAddress.new address: destination_address.host, port: destination_address.port rescue nil
      destination_address = to_ip_address if to_ip_address
    in Socket::IPAddress
    end

    case destination_address
    in Address
    in Socket::IPAddress
      case server_local_address = io.local_address
      in Socket::UNIXAddress
      in Socket::IPAddress
        _destination_address = IPAddress.new addr: destination_address.address

        any = destination_blocker.ipBlocks.any? do |destination_blocker_ip_block|
          case destination_blocker_ip_block
          in IPAddress::IPv4
            destination_blocker_ip_block.includes? _destination_address
          in IPAddress::IPv6
            destination_blocker_ip_block.includes? _destination_address
          in Tuple(IPAddress::IPv4 | IPAddress::IPv6, Int32)
            _destination_blocker_ip_block, port = destination_blocker_ip_block
            _destination_blocker_ip_block.includes?(_destination_address) && (destination_address.port == port)
          end
        end

        raise Exception.new "Server.check_destination_blocker!: Establish.destinationAddress conflicts with your server address (ipBlocks)!" if any
      in Socket::Address
      end
    end

    __check_destination_blocker! destination_address: destination_address
  end
end
