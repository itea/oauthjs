
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
    requestTokenURI: '/accounts/OAuthGetRequestToken',
    signatureMethod: 'HMAC-SHA1',
    signatureKey: 'anonymous',
    consumerKey: 'anonymous',
    callbackURI: '/callback'
};

var oa = new OAuth(config);
oa.getRequestToken({scope: 'http://www.google.com/calendar/feeds http://picasaweb.google.com/data'});

