var express = require('express');
var open = require('open');
var axios = require('axios');
var querystring = require('querystring');

var dns = require('node:dns');
dns.setDefaultResultOrder('ipv4first');

var app = express();
app.use(express.static('callback'));

var server = app.listen(0);
var port = server.address().port;

console.info('Listening on port: ' + port + '\n');

// 2. Get redirected from Keycloak after user had authenticated and obtained authorization code.
app.get('/callback/', function (request, response) {
    response.send('<html><script>window.close();</script><body>Completed, please close this tab</body></html>');
    var code = request.query.code;
    server.close();

    // 2.1. Show authorization code.
    console.info('Authorization Code: ' + code + '\n');

    // 2.2. Send POST-request to Keycloak in order to exchange authorization code for Access Token.
    axios.post('http://127.0.0.1:8080/realms/myrealm/protocol/openid-connect/token', querystring.stringify({
        client_id: 'cli',
        grant_type: 'authorization_code',
        redirect_uri: 'http://127.0.0.1:' + port + '/callback',
        code: code
    })).then(res => {
        // 3. Show obtained Access Token.
        console.log('Access Token: ' + res.data.access_token + '\n');
    }).catch(error => {
        console.error(error);
    });
});

// 1. Apply to Keycloak to authenticate user, retrieve authorization code and get redirected to 'redirect_uri'
open('http://localhost:8080/realms/myrealm/protocol/openid-connect/auth?client_id=cli&redirect_uri=http://127.0.0.1:' + port + '/callback&response_type=code');
