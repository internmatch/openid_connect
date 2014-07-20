module OpenIDConnect
  class ResponseObject < ConnectObject
  end
end

require 'openid_connect/response_object/user_info'
Dir[File.dirname(__FILE__) + '/response_object/*.rb'].each do |file|
  require file
end
