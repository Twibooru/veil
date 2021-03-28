# frozen_string_literal: true
require 'cgi'
require 'http'
require 'openssl'
require 'addressable/uri'

class Veil
  DEFAULT_REQUEST_HEADERS = {
    'Via' => 'Veil Asset Proxy',
    'User-Agent' => 'Veil Asset Proxy'
  }.freeze

  DEFAULT_SECURITY_HEADERS = {
    'X-Frame-Options' => 'deny',
    'X-XSS-Protection' => '1; mode=block',
    'X-Content-Type-Options' => 'nosniff',
    'Content-Security-Policy' => "default-src 'none'; img-src data:; style-src 'unsafe-inline'",
    'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains'
  }.freeze

  def initialize(config)
    @config = config

    if @config[:proxy]
      proxy_uri = Addressable::URI.parse @config[:proxy]
      default_port = proxy_uri.scheme == 'https' ? 443 : 80

      @proxy = [proxy_uri.host, proxy_uri.port || default_port, proxy_uri.user, proxy_uri.password]
    end
  end

  def call(env)
    request = Rack::Request.new env

    return hwhat if !request.get? || request.path == '/'

    provided_digest = request.path.delete_prefix '/'
    provided_url    = request.params['url']

    return four_oh_four('Digest or URL missing') unless provided_digest && provided_url

    provided_url = CGI.unescape(provided_url)
    digest = OpenSSL::HMAC.hexdigest('sha1', @config[:key], provided_url)

    return four_oh_four('Invalid digest') unless provided_digest == digest

    process_url(request, provided_url)
  end

  private

  def process_url(request, url)
    headers_to_send = {
      'Accept' => request.get_header('Accept') || 'image/*',
      'Accept-Encoding' => request.get_header('Accept-Encoding') || ''
    }.merge(DEFAULT_REQUEST_HEADERS)

    response =
      begin
        http_client.headers(headers_to_send)
                   .follow(max_hops: 3)
                   .get(url)
      rescue HTTP::Redirector::TooManyRedirectsError
        return four_oh_four 'Too many redirects'
      end

    return four_oh_four("Bad status code #{response.status}") unless response.status.success?

    content_to_return = []
    headers_to_return = {
      'Cache-Control' => response['cache-control'] || 'public, max-age=31536000'
    }.merge(DEFAULT_SECURITY_HEADERS)

    %w[content-type etag expires last-modified transfer-encoding content-encoding].each do |h|
      headers_to_return[h] = response[h] if response[h]
    end

    content_length = 0

    loop do
      chunk = response.body.readpartial
      break if chunk.nil?

      content_length += chunk.length

      return four_oh_four('Content-Length limit exceeded') if content_length > @config[:length_limit]

      content_to_return << chunk
    end

    [200, headers_to_return, content_to_return]
  rescue StandardError => e
    four_oh_four "Internal server error: #{e.inspect}"
  end

  def four_oh_four(reason)
    $stderr.puts(reason)

    [404, { 'Content-Type' => 'text/plain' }, ['Not Found']]
  end

  def hwhat
    [200, { 'Content-Type' => 'text/plain' }, ['hwhat']]
  end

  def http_client
    (@proxy ? HTTP.via(*@proxy) : HTTP)
  end
end
