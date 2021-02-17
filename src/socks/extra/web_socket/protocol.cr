class HTTP::WebSocket::Protocol
  def read_timeout=(value : Int | Float | Time::Span | Nil)
    _wrapped = @io
    _wrapped.read_timeout = value if value if _wrapped.responds_to? :read_timeout=
  end

  def write_timeout=(value : Int | Float | Time::Span | Nil)
    _wrapped = @io
    _wrapped.write_timeout = value if value if _wrapped.responds_to? :write_timeout=
  end

  def read_timeout
    _wrapped = @io
    _wrapped.read_timeout if _wrapped.responds_to? :read_timeout
  end

  def write_timeout
    _wrapped = @io
    _wrapped.write_timeout if _wrapped.responds_to? :write_timeout
  end

  def local_address : ::Socket::Address?
    _wrapped = @io
    _wrapped.responds_to?(:local_address) ? _wrapped.local_address : nil
  end

  def remote_address : ::Socket::Address?
    _wrapped = @io
    _wrapped.responds_to?(:remote_address) ? _wrapped.remote_address : nil
  end

  def flush
    @io.flush
  end

  def closed?
    @io.closed?
  end

  def io_close
    @io.close
  end
end
