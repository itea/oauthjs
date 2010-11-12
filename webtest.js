
var OAuth = require('./oauth').OAuth;
var express = require('express');

var app = express.createServer();
app.use(express.bodyDecoder());
app.use(express.errorHandler({showStack:true, dumpExceptions:true}));

var config = {
    server: 'www.google.com',
    requestTokenURI: 'https://www.google.com/accounts/OAuthGetRequestToken',
    authorizeTokenURI: 'https://www.google.com/accounts/OAuthAuthorizeToken',
    accessTokenURI: 'https://www.google.com/accounts/OAuthGetAccessToken',
    signatureMethod: 'HMAC-SHA1',
    consumerKey: 'anonymous',
    consumerSecret: 'anonymous',
    callbackURI: 'http://itea.sytes.net:8080/callback'
};

var oauth = new OAuth(config);

app.get('/', function(request, response) {
    response.send('<html><head></head><body><a href="requestToken">requestToekn</a></body></html>');
});
app.get('/requestToken', function(request, response) {
    oauth.acquireRequestToken({scope: 'http://www.google.com/calendar/feeds'},
        function(oa) {
            if(oa instanceof Error) {
                response.send(oa.statusCode +' '+ oa.toString());
            } else response.redirect(oa.getAuthorizeTokenURI());
        });
});
app.get('/callback', function(request, response) {
    oauth.setOAuthVerifier(request.param('oauth_verifier'));
    oauth.acquireAccessToken(function(oa){
            if(oa instanceof Error) {
                response.send(oa.statusCode +' '+ oa.toString());
            } else response.send(oa.oauthToken);
    });
});

app.listen(8080);

