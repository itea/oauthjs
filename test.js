
var OAuth = require('./oauth').OAuth;

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
oa.acquireRequestToken({scope: 'http://www.google.com/calendar/feeds http://picasaweb.google.com/data', xoauth_displayname: 'my test'}, function(oa){
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
