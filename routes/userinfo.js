var express = require('express');
var passport = require('passport');
var HTTPBearerStrategy = require('passport-http-bearer');
var paseto = require('paseto.js');
var db = require('../db');


passport.use(new HTTPBearerStrategy(function verify(token, cb) {
  var now = Date.now();
  var raw = Buffer.from('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', 'hex');
  var sk  = new paseto.SymmetricKey(new paseto.V2());
  sk.inject(raw)
    .then(function() {
      var decoder = sk.protocol();
      return decoder.decrypt(token, sk);
    })
    .then(function(message) {
      var payload = JSON.parse(message);
      if (payload.iss !== 'https://server.example.com') { return cb(null, false); }
      if (payload.aud !== 'https://api.example.com') { return cb(null, false); }
      if (Date.parse(payload.exp) <= now) { return cb(null, false); }
      
      var user = {
        id: parseInt(payload.sub)
      };
      // TODO: Pass scope as info
      return cb(null, user);
    })
    .catch(function(err) {
      return cb(null, false);
    });
}));


var router = express.Router();

router.get('/userinfo', passport.authenticate('bearer', { session: false }), function(req, res, next) {
  db.get('SELECT * FROM users WHERE id = ?', [ req.user.id ], function(err, row) {
    if (err) { return next(err); }
    // TODO: Handle undefined row.
    var info = {
      sub: row.id.toString()
    };
    // TODO: check scope
    if (row.name) { info.name = row.name; }
    if (row.username) { info.preferred_username = row.username; }
    res.json(info);
  });
});

module.exports = router;
