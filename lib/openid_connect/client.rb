module OpenIDConnect
  class Client < Rack::OAuth2::Client
    attr_optional :userinfo_endpoint, :expires_in

    def initialize(attributes = {})
      super attributes
      self.userinfo_endpoint ||= '/userinfo'
    end

    def authorization_uri(params = {})
      params[:scope] = setup_required_scope params[:scope]
      params[:prompt] = Array(params[:prompt]).join(' ')
      super
    end

    def userinfo_uri
      absolute_uri_for userinfo_endpoint
    end

    def access_token!(*args)
      headers, params, http_client, options = authenticated_context_from(*args)
      params[:scope] = Array(options.delete(:scope)).join(' ') if options[:scope].present?
      params.merge! @grant.as_json
      params.merge! options
      handle_response do
        http_client.get(
          absolute_uri_for(token_endpoint),
          Util.compact_hash(params),
          headers
        ) do |req|
          yield req if block_given?
        end
      end
    end

    private

    def setup_required_scope(scopes)
      _scopes_ = Array(scopes).join(' ').split(' ')
      _scopes_ << 'openid' unless _scopes_.include?('openid')
      _scopes_
    end

    def handle_success_response(response)
      token_hash = JSON.parse(response.body).with_indifferent_access
      token_type = (@forced_token_type || token_hash[:token_type]).try(:downcase)
      case token_type
      when 'bearer'
        AccessToken.new token_hash.merge(client: self)
      else
        raise Exception.new("Unexpected Token Type: #{token_type}")
      end
    rescue JSON::ParserError
      raise Exception.new("Unknown Token Type")
    end
  end
end

Dir[File.dirname(__FILE__) + '/client/*.rb'].each do |file|
  require file
end
