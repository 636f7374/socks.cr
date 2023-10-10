module HTTP
  private def self.read_header_line(io, max_size) : HeaderLine | EndOfRequest | Nil
    # Optimization: check if we have a peek buffer
    if peek = io.peek
      # peek.empty? means EOF (so bad request)
      return nil if peek.empty?

      # See if we can find \n
      index = peek.index('\n'.ord.to_u8)

      if index
        end_index = index

        # Also check (and discard) \r before that
        if index > 0 && peek[index - 1] == '\r'.ord.to_u8
          end_index -= 1
        end

        # Check if we just have "\n" or "\r\n" (so end of request)
        if end_index == 0
          io.skip(index + 1)
          return EndOfRequest.new
        end

        return HeaderLine.new name: "", value: "", bytesize: index + 1 if index > max_size

        name, value = parse_header(peek[0, end_index])
        io.skip(index + 1) # Must skip until after \n

        return HeaderLine.new name: name, value: value, bytesize: index + 1
      end
    end

    line = io.gets(max_size + 1, chomp: true)
    return EndOfRequest.new unless line # Default: return nil, (Update to macOS Sonoma 14.0 + Crystal 1.10.0 triggers this bug).

    if line.bytesize > max_size
      return HeaderLine.new name: String.new, value: String.new, bytesize: max_size
    end

    if line.empty?
      return EndOfRequest.new
    end

    name, value = parse_header(line)
    HeaderLine.new name: name, value: value, bytesize: line.bytesize
  end
end
