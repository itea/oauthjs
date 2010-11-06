
var OAuth = require('./oauth').OAuth;
/*
var s = OAuth.generateSignatureBaseString('GET',
    'http://www.google.com/calendar/feeds/default/allcalendars/full', {
    oauth_consumer_key: 'example.com',
    oauth_nonce: '4572616e48616d6d65724c61686176'
    }, {orderby: 'starttime'});
console.log(s);

console.log(OAuth.signHmacSha1(s, 'anonymous'));
*/
var config = {
    server: 'www.google.com',
    requestTokenURI: 'https://www.google.com/accounts/OAuthGetRequestToken',
    authorizeTokenURI: 'https://www.google.com/accounts/OAuthAuthorizeToken',
    accessTokenURI: 'https://www.google.com/accounts/OAuthGetAccessToken',
    signatureMethod: 'HMAC-SHA1',
    consumerKey: 'anonymous',
    consumerSecret: 'anonymous',
    callbackURI: 'http://itealabs.net/callback'
};

var oa = new OAuth(config);
oa.acquireRequestToken({scope: 'http://www.google.com/calendar/feeds http://picasaweb.google.com/data'}, function(oa){
    console.log(oa.oauthToken);
    console.log(oa.getAuthorizeTokenURI());
    console.log('------------PLEASE INPUT OAUTH_VERIFIER(NOT ENCODED):');
    
    var v = '';
    var stdin = process.openStdin();
    stdin.on('data', function(d){
        v = d.toString();
    });
    stdin.on('end', function() {
        console.log('stdinend');
        oa.setOAuthVerifier(v);
        oa.acquireAccessToken(function(oa){
            
        });
    });
});
