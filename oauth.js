/**
 * oauth.js
 * OAuth Client for Node.js
 * @author itea 2010-10-29
 * @version 0.1 2010-10-29
 */

var http = require('http');

/**
 *
 * @param config: Object
 */
function OAuth(configuration) {
    this.config = configuration || {};
}

OAuth.prototype.getRequestToken = function(body, callback, ctx){
    var client = OAuth.createClient(this.config.requestTokenURI);
    
    var oauthHeader = OAuth.buildRequestAuthorizationHeader(this.config);
    var signatureBaseString = OAuth.generateSignatureBaseString('POST',
        this.config.requestTokenURI, oauthHeader, body);
    console.log('baseString: '+ signatureBaseString);
    oauthHeader['oauth_signature'] = OAuth.sign(this, signatureBaseString);
    
    var headers = {
        'Host': this.config.server,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': OAuth.toAuthorizationHeaderString(oauthHeader)
    };
    console.log(JSON.stringify(headers));
    var request = client.request('POST', this.config.requestTokenURI, headers);
    request.write(OAuth.toBodyString(body));
    request.end();
    
    var oauth = this;
    request.on('response', function(response) {
        console.log('status: ' + response.statusCode);
        if(response.statusCode.toString() === '200') {
            response.setEncoding('utf8');
            response.on('data', function(data) {
                console.log('BODY: '+ data);
                OAuth.parseBody(data.toString(), oauth);
                callback.call(ctx, oauth);
            });
        }
    });
};

OAuth.prototype.getAuthorizeTokenURI = function(parameters){
    var s = [];
    parameters = parameters || {};
    s.push('oauth_token='+ encodeURIComponent(this.oauthToken));
    for(var p in parameters) s.push([p, '=', encodeURIComponent(parameters[p])].join(''));
    return [this.config.authorizeTokenURI, '?', s.join('&')].join('');
};

OAuth.prototype.authorizeToken = function(){};

OAuth.prototype.getAccessToken = function(){};

OAuth.createClient = function(uri) {
    var secure = /^https.+/.test(uri) ? true : false;
    var group = /^https?:\/\/([^\/:]+)(?:\:(\d+))?.*$/.exec(uri) || [];
    var port = group[2];
    var server = group[1];
    if(!port) port = secure ? 443 : 80;
    port = +port;
    return http.createClient(port, server, secure);
};
OAuth.parseBody = function(body, oauth) {
    var s = body.split('&'), i, idx, b = oauth || {};
    for(i=0; i<s.length; i++) {
        idx = s[i].indexOf('=');
        switch(s[i].substring(0, idx++)) {
        case 'oauth_token':
            b.oauthToken = decodeURIComponent(s[i].substring(idx)); break;
        case 'oauth_token_secret':
            b.oauthTokenSecret = decodeURIComponent(s[i].substring(idx)); break;
        }
    }
    return b;
};

OAuth.buildRequestAuthorizationHeader = function(config) {
    return {
        'oauth_consumer_key': config.consumerKey,
        'oauth_version': '1.0',
        'oauth_callback': config.callbackURI,
        'oauth_timestamp': (new Date().valueOf()/1000).toFixed().toString(),
        'oauth_nonce': new Date().valueOf().toString(),
        'oauth_signature_method': config.signatureMethod
    };
};

OAuth.toAuthorizationHeaderString = function(header) {
    var a = [];
    for(var v in header) {
        a.push([v, '="', encodeURIComponent(header[v]), '"'].join(''));
    }
    return 'OAuth ' + a.join(',');
};

OAuth.toBodyString = function(body) {
    var a = [];
    for(var v in body) {
        a.push([v, '=', encodeURIComponent(body[v])].join(''));
    }
    return a.join('&');
};

/**
 * @param method: string ('POST' or 'GET')
 * @param baseURL: string
 * @param headers: header parameters object
 * @param bodys: body parameter object
 */
OAuth.generateSignatureBaseString = function(method, baseURL, headers, bodys) {
    var params = [];
    headers = headers || {};
    bodys = bodys || {};

    for(var idx in headers) {
        params.push([idx, encodeURIComponent(headers[idx])].join('='));
    }
    for(var idx in bodys) {
        params.push([idx, encodeURIComponent(bodys[idx])].join('='));
    }
    return [method.toUpperCase(), encodeURIComponent(baseURL),
            encodeURIComponent(params.sort().join('&'))].join('&');
};

OAuth.sign = function(oauth, baseString) {
    var method = oauth.config.signatureMethod;
    var key = [oauth.config.consumerSecret ||'', '&', oauth.tokenSecret ||''].join('');
    if(method === 'HMAC-SHA1') return OAuth.signHmacSha1(baseString, key);
    else if(method === 'RSA-SHA1') return null;
};

OAuth.signHmacSha1 = function(baseString, key) {
    var signer = require('crypto').createHmac('SHA1', key);
    signer.update(baseString);
    return signer.digest('base64');
};

exports.OAuth = OAuth;

