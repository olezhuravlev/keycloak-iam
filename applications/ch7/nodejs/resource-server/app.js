var express = require('express');
var Keycloak = require('keycloak-connect');

var app = express();

// Create Keycloak object.
var keycloak = new Keycloak({});

// Install Keycloak Node.js adapter as middleware to use it to protect resources in the application.
app.use(keycloak.middleware());

// Protect resources in the application.
// The keycloak.protect method automatically adds bearer token authorization to the endpoints
// so that requests containing an Authorization header with a valid token can fetch the protected resources in the application.
app.get('/hello', keycloak.protect(), function (req, res) {
    res.setHeader('content-type', 'text/plain');
    res.send('Access granted to protected resource');
});

app.listen(8080, function () {
    console.log('Started at port 8080');
});