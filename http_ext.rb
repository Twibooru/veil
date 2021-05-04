module HTTP
  class Response
    def stream_body
      raise unless block_given?

      loop do
        chunk = body.readpartial
        break if chunk.nil?

        yield chunk
      end
    end
  end
end
