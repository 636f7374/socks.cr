class SOCKS::PausePool
  getter clearInterval : Time::Span
  getter capacity : Int32
  getter connectionIdentifiers : Set(UUID)
  getter entries : Hash(UUID, Entry)
  getter lastCleanedUp : Time
  getter mutex : Mutex

  def initialize(@clearInterval : Time::Span = 60_i32.seconds, @capacity : Int32 = 128_i32)
    @connectionIdentifiers = Set(UUID).new
    @entries = Hash(UUID, Entry).new
    @lastCleanedUp = Time.local
    @mutex = Mutex.new :unchecked
  end

  def assign_connection_identifier : UUID
    @mutex.synchronize do
      loop do
        connection_identifier = UUID.random
        next if @connectionIdentifiers.includes? connection_identifier
        next if entries.includes? connection_identifier

        @connectionIdentifiers << connection_identifier
        return connection_identifier
      end
    end
  end

  def remove_connection_identifier(connection_identifier : UUID) : Bool
    @mutex.synchronize { @connectionIdentifiers.delete connection_identifier }

    true
  end

  def clear
    @mutex.synchronize do
      entries.each do |connection_identifier, entry|
        next unless entry = entries[connection_identifier]?

        @connectionIdentifiers.delete connection_identifier
        entries.delete connection_identifier

        entry.destination.close rescue nil
      end
    end
  end

  private def need_cleared?
    interval = Time.local - lastCleanedUp.dup
    interval > clearInterval
  end

  def inactive_entry_cleanup_mutex
    @mutex.synchronize { inactive_entry_cleanup }
  end

  private def inactive_entry_cleanup
    while capacity <= entries.size
      connection_identifier, entry = entries.first

      @connectionIdentifiers.delete connection_identifier
      entries.delete connection_identifier

      entry.destination.close rescue nil
    end

    return unless need_cleared?

    entries.each do |connection_identifier, entry|
      next unless clearInterval <= (Time.local - entry.created_at)

      @connectionIdentifiers.delete connection_identifier
      entries.delete connection_identifier

      entry.destination.close rescue nil
    end

    refresh_last_cleaned_up
  end

  private def refresh_last_cleaned_up
    @lastCleanedUp = Time.local
  end

  def size : Int32
    @mutex.synchronize { entries.size.dup }
  end

  def set(connection_identifier : UUID, destination : IO, state : Enhanced::State::WebSocket) : Bool
    if capacity.zero?
      destination.close rescue nil

      return false
    end

    @mutex.synchronize do
      inactive_entry_cleanup

      entries[connection_identifier]?.try do |_entry|
        _entry.destination.close rescue nil
      end

      entries[connection_identifier] = Entry.new destination: destination, state: state
    end

    true
  end

  def get?(connection_identifier : UUID) : Entry?
    @mutex.synchronize do
      inactive_entry_cleanup

      entry = entries[connection_identifier]?
      entries.delete connection_identifier

      entry
    end
  end

  def connection_identifier_includes?(connection_identifier : UUID) : Bool
    @mutex.synchronize { connectionIdentifiers.includes? connection_identifier }
  end

  struct Entry
    getter destination : IO
    getter state : Enhanced::State::WebSocket
    getter createdAt : Time

    def initialize(@destination : IO, @state : Enhanced::State::WebSocket)
      @createdAt = Time.local
    end

    def created_at : Time
      @createdAt
    end
  end
end
