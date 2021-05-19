class SOCKS::Server
  private def check_destination_protection!(destination_address : Address | Socket::IPAddress) : Bool
    # This function is used as an overridable.

    return true unless destination_protection = options.server.destinationProtection

    case destination_address
    in Address
      to_ip_address = Socket::IPAddress.new address: destination_address.host, port: destination_address.port rescue nil
      destination_address = to_ip_address if to_ip_address
    in Socket::IPAddress
    end

    case destination_address
    in Address
    in Socket::IPAddress
      server_local_address = io.local_address

      case server_local_address
      in Socket::UNIXAddress
      in Socket::IPAddress
        _destination_address = IPAddress.new addr: destination_address.address
        raise Exception.new "Server.check_destination_protection!: Establish.destinationAddress conflicts with your server address (ipBlocks)!" if destination_protection.ipBlocks.any? { |protection_ip_block| protection_ip_block.includes? _destination_address }
      in Socket::Address
      end
    end

    __check_destination_protection! destination_address: destination_address
  end
end
