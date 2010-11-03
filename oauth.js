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

OAuth.prototype.getRequestToken = function(body){
    var client = http.createClient(443, this.config.server, true);
    
    var oauthHeader = OAuth.buildRequestAuthorizationHeader(this.config);
    var signatureBaseString = OAuth.generateSignatureBaseString('POST',
        ['https://', this.config.server, this.config.requestTokenURI].join(''),
        oauthHeader, body);
    console.log('baseString: '+ signatureBaseString);
    oauthHeader['oauth_signature'] = (OAuth.sign(this.config.signatureMethod, signatureBaseString, this.config.signatureKey));
    
    var headers = {
        'Host': this.config.server,
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': OAuth.toAuthorizationHeaderString(oauthHeader)
    };
    console.log(JSON.stringify(headers));
    var request = client.request('POST', this.config.requestTokenURI, headers);
    request.write(OAuth.toBodyString(body));
    request.end();
    request.on('response', function(response) {
        console.log('status: ' + response.statusCode);
        console.log('HEADERS: '+ JSON.stringify(response.headers));
        response.setEncoding('utf8');
        response.on('data', function(data) {
            console.log('BODY: '+ data);
        });
    });
};

OAuth.prototype.authorizeToken = function(){};

OAuth.prototype.getAccessToken = function(){};

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

OAuth.sign = function(method, baseString, key) {
    if(method === 'HMAC-SHA1') return OAuth.signHmacSha1(baseString, key + '&');
    else if(method === 'RSA-SHA1') return null;
};

OAuth.signHmacSha1 = function(baseString, key) {
    var signer = require('crypto').createHmac('SHA1', key);
    signer.update(baseString);
    return signer.digest('base64');
};

exports.OAuth = OAuth;

