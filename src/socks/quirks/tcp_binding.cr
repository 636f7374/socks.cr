module SOCKS::Quirks
  class TCPBinding < IO
    getter server : TCPServer
    getter timeout : TimeOut
    getter socket : TCPSocket?
    getter closed : Bool?

    def initialize(@server : TCPServer, @timeout : TimeOut = TimeOut.new)
      @socket = nil
      @closed = nil
    end

    def read_timeout=(value : Int | Time::Span | Nil)
      _io = socket
      _io.read_timeout = value if value if _io.responds_to? :read_timeout=
    end

    def read_timeout
      _io = socket
      _io.read_timeout if _io.responds_to? :read_timeout
    end

    def write_timeout=(value : Int | Time::Span | Nil)
      _io = socket
      _io.write_timeout = value if value if _io.responds_to? :write_timeout=
    end

    def write_timeout
      _io = socket
      _io.write_timeout if _io.responds_to? :write_timeout
    end

    def local_address : Socket::Address?
      _io = socket
      _io.responds_to?(:local_address) ? _io.local_address : nil
    end

    def remote_address : Socket::Address?
      _io = socket
      _io.responds_to?(:remote_address) ? _io.remote_address : nil
    end

    def server_local_address : Socket::Address?
      _io = server
      _io.responds_to?(:local_address) ? _io.local_address : nil
    end

    def server_remote_address : Socket::Address?
      _io = server
      _io.responds_to?(:remote_address) ? _io.remote_address : nil
    end

    def read(slice : Bytes) : Int32
      return 0_i32 if slice.empty?
      raise Exception.new "TCPBinding.read: TCPBinding.socket cannot be Nil!" unless _socket = socket

      _socket.read slice
    end

    def write(slice : Bytes) : Nil
      return nil if slice.empty?
      raise Exception.new "TCPBinding.read: TCPBinding.socket cannot be Nil!" unless _socket = socket

      _socket.write slice
    end

    def accept?
      return unless socket = server.accept?

      @socket = socket
    end

    def close
      socket.try &.close rescue nil
      server.close rescue nil

      @closed = true
    end

    def closed?
      @closed
    end
  end
end
