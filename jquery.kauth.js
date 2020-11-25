/*
	A javascript oAuth 1.0 implementation I wrote for Knotis, Inc.
	Joshua Marshall Moore
	
	Reproduced with permission from Knotis, Inc.
*/

(function($){
  
  var _percent_encode = function(s){
    if (s === null) {
        return "";
    }
    if (s instanceof Array) {
        var e = "";
        for (var i = 0; i < s.length; ++s) {
            if (e != "") e += '&';
            e += kauth._percent_encode(s[i]);
        }
        return e;
    }
    s = encodeURIComponent(s);
    // Now replace the values which encodeURIComponent doesn't do
    // encodeURIComponent ignores: - _ . ! ~ * ' ( )
    // OAuth dictates the only ones you can ignore are: - _ . ~
    // Source: http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Global_Functions:encodeURIComponent
    s = s.replace(/\!/g, "%21");
    s = s.replace(/\*/g, "%2A");
    s = s.replace(/\'/g, "%27");
    s = s.replace(/\(/g, "%28");
    s = s.replace(/\)/g, "%29");
    return s;
  };
  
  var _decode_percent = function(s){
    if(s != null){
      s = s.replace(/\+/g, " ");
    }
    
    return decodeURIComponent(s);
  };
  
  var _get_base_string_uri = function(request){
    var base_string_uri = request.url;
    var q = request.url.indexOf('?');
    if(q < 0){
      return base_string_uri;
    }else{
      return base_string_uri.substring(0, q);
    }
  };
  
  var _decode_form = function(url_query){
    var list = [];
    var nvps = url_query.split('&');
    for (var n = 0; n < nvps.length; ++n) {
      var nvp = nvps[n];
      if (nvp == "") {
        continue;
      }
      var equals = nvp.indexOf('=');
      var name;
      var value;
      if (equals < 0) {
        name = kauth._decode_percent(nvp);
        value = null;
      } else {
        name = _decode_percent(nvp.substring(0, equals));
        value = _decode_percent(nvp.substring(equals + 1));
      }
      list.push([name, value]);
    }
    return list;
  };

  var _get_base_string_parameters = function(request){
    var parameter_list = request.data || [];
    
    // url parameters/query component of http request uri
    var q = request.url.indexOf('?');
    if(q > -1){
      
      parameter_list.concat(_decode_form(request.url.substring(q+1)));
    }
    
    // OAuth HTTP Authorization header field
    for(var key in request.headers.Authorization){
      parameter_list.push([key, request.headers.Authorization[key]]);
    }
    
    // data parameters
    if(request.headers.hasOwnProperty('Content-Type') &&
       request.headers['Content-Type'] === 'application/x-www-urlencoded'){
      parameter_list = parameter_list.concat(_decode_form(request.data));
    }
    
    // encoding ...
    var encoded_parameters = [];
    for(var i=0; i<parameter_list.length; i++){
      encoded_parameters.push(
        _percent_encode(parameter_list[i][0]) +
        '=' +
        _percent_encode(parameter_list[i][1])
      );
    }
    
    encoded_parameters = encoded_parameters.sort(function(a, b){
      if(a < b) return -1;
      if(a > b) return 1;
      return 0;
    });
    
    var str = '';
    if(encoded_parameters.length > 0){
      str = str.concat(encoded_parameters[0]);
    }
    for(var i=1; i<encoded_parameters.length; i++){
      if(encoded_parameters[i]){
        str = str.concat('&');
        str = str.concat(encoded_parameters[i]);
      }
    }
    
    return str;
  };
  
  var _get_base_string = function(request){
    var base_string = '',
        raw,
        encoded;
        
    // method
    base_string = base_string.concat(request.method.toUpperCase());
    
    // base string uri
    base_string = base_string.concat('&');
    raw = _get_base_string_uri(request);
    encoded = _percent_encode(raw);
    base_string = base_string.concat(encoded);
    
    // base string parameters
    base_string = base_string.concat('&');
    raw = _get_base_string_parameters(request);
    encoded = _percent_encode(raw);
    base_string = base_string.concat(encoded);
    
    return base_string;
  };
  
  var _sign = function(base_string, kauth_settings){
    return kauth_settings.client.signature.method(base_string);
  };
  
  var _get_authorization_header = function(request){
    var header = 'OAuth ';
    
    for(var key in request.headers.Authorization){
      header += _percent_encode(key) + 
        '="' +  _percent_encode(request.headers.Authorization[key]) + '"';
    }
    
    return header;
  };
  
  var _prepare = function(request, kauth_settings){
    var base_string = _get_base_string(request);
    var signature = _sign(base_string, kauth_settings);
    var header = _get_authorization_header(request);
    request.headers.Authorization = header + 'oauth_signature="' + signature + '"';
  };
  
  var _get_nonce = function(length){
    length = length || 9;
    var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
    var result = '';
    for(var i=0; i<length; i++){
      var rnum = Math.floor(Math.random() * chars.length);
      result += chars.substring(rnum, rnum+1);
    }
    
    return result;
  };
  
  var _get_timestamp = function() {
    var t = (new Date()).getTime();
    return Math.floor(t / 1000);
  };
  
  var _pick = function(obj, keys){
    var ret = {};
    
    var key;
    for(var i=0; i<keys.length; i++){
      key = keys[i];
      ret[key] = this[key];
    }
    
    return ret;
  };
  
  var _omit_default_port = function(host, port_omissions){
    for(var scheme in port_omissions){
      if(new RegExp(scheme).test(host)){
        return host.replace(port_omissions[scheme], '');
      }
    }
    
    return host;
  };
  
  /*
    Private Members
  */

  var _working = {
    token_secret: localStorage.getItem('token_secret') || null,
    access_token: localStorage.getItem('access_token') || null
  };

  /*
    PUBLIC
  */

  $.kauth_reset = function(){
    _working = {
      token_secret: null,
      access_token: null
    };
  };

  $.kauth_has_token = function(){
    return _working.access_token !== null;
  },
  
  $.kauth = function(options, deferred){
    
    var settings = $.extend(true, {
      user: {
        username: '',
        password: ''
      },
      
      client: {
        consumer_key: '',
        consumer_secret: '',
        host: 'auth.domain',
        path_prefix: '/oauth/',
        paths: {
          access_token: 'access_token'
        },
        
        default_port_omissions: {
          '^http://': /:80/,
          '^https://': /:443/
        },
        
        signature: {
          method_name: 'HMAC-SHA2',
          method: function(base_string){
            var message = base_string;
            var key = _percent_encode(settings.client.consumer_secret) +
              '&' + _percent_encode(_working.token_secret);
            var signature = CryptoJS.HmacSHA256(message, key).toString(CryptoJS.enc.Base64);
            return signature;
          }
        },
        
        callback: 'cb'
      },
      
      request: {
        method: 'GET',
        path: 'test',
        data: null, // an array of key-value pairs
        error: function(){},
        success: function(){}
      }
    }, options);
    
    var deferred = deferred || $.Deferred();
    
    if(_working.access_token){
      /*
       * Make Authenticated Request
       */
      var client_request = {
        method: settings.request.method,
        url: 'http://' + settings.client.host + settings.client.path_prefix + settings.request.path,
        data: settings.request.data,
        headers: {
          'Authorization': {
            realm: 'all',
            oauth_consumer_key: settings.client.consumer_key,
            oauth_signature_method: settings.client.signature.method_name,
            oauth_token: _working.access_token,
            oauth_timestamp: _get_timestamp(),
            oauth_nonce: _get_nonce()
          }
        }
      };
      
      _prepare(client_request, settings);
      
      $.ajax(client_request.url, {
        crossDomain: true,
        beforeSend: function(xhr, settings){
          xhr.setRequestHeader('Authorization', client_request.headers.Authorization);
        },
        data: settings.request.data,
        success: function(data, status, xhr){
          deferred.resolve(data, status);
        },
        error: function(xhr, status, error){
          deferred.reject(status, error);
        }
      });
    }else{
      // obtain access token
      var oauth_request = {
        method: 'POST',
        url: 'http://' + _omit_default_port(settings.client.host, settings.client.default_port_omissions)
          + settings.client.path_prefix + settings.client.paths.access_token,
        headers: {
          'Authorization': {
            realm: 'all',
            username: settings.user.username,
            password: settings.user.password,
            oauth_consumer_key: settings.client.consumer_key,
            oauth_signature_method: settings.client.signature.method_name,
            oauth_timestamp: _get_timestamp(),
            oauth_callback: encodeURIComponent(settings.client.callback)
          }
        }
      };
      
      _prepare(oauth_request, settings);
      
      var args = arguments;
      
      $.ajax(oauth_request.url, {
        crossDomain: true,
        method: oauth_request.method,
        beforeSend: function(xhr, settings){
          xhr.setRequestHeader('Authorization', oauth_request.headers.Authorization);
        },
        success: function(data, status, xhr){
          // parse value pairs from response
          var response = (function(response){
            var kvps = response.split('&');
            var result = {};
            var kvp;
            for(var i=0; i<kvps.length; i++){
              kvp = kvps[i].split('=');
              if(kvp[1]){
                result[kvp[0]] = kvp[1];
              }
            }
            
            return result;
          })(data);
          
          // overwrite any previous access tokens and verifiers,
          // to force app to reauthorize with user once a request 
          // token has been obtained, or for short: use the newest
          // token available, no hoarding!          
          _working.access_token = response.oauth_token;
          _working.token_secret = response.oauth_token_secret;
          
          localStorage.setItem('access_token', response.oauth__token);
          localStorage.setItem('token_secret', response.oauth_token_secret);

          $.kauth(options, deferred);
        },
        error: function(xhr, status, error){
          deferred.reject(error);
        }
      });
    }
    
    return deferred.promise();
  };
  
})(jQuery);
