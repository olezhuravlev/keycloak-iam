var express = require('express');
var session = require('express-session');
var Keycloak = require('keycloak-connect');
var cors = require('cors');

var app = express();

app.use(cors());

var memoryStore = new session.MemoryStore();

app.use(session({
    secret: 'some secret',
    resave: false,
    saveUninitialized: true,
    store: memoryStore
}));

// Create Keycloak object with a MemoryStore.
var keycloak = new Keycloak({store: memoryStore});

// Install Keycloak Node.js adapter as middleware to use it to protect resources in the application.
app.use(keycloak.middleware());

// Protect resources in the application.
// The keycloak.protect method automatically adds the necessary capabilities to the endpoints,
// to check whether users are authenticated yet or not so that they can be redirected to Keycloak if not.
// After successful authentication, the middleware will automatically process the response from Keycloak and establish
// a local session for the user based on the tokens issued by the server.
app.get('/', keycloak.protect(), function (req, res) {
    res.setHeader('content-type', 'text/plain');
    res.send('Welcome!');
});

app.listen(8080, function () {
    console.log('Started at port 8080');
});