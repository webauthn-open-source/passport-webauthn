var passport = require("passport-strategy");
var Fido2Server = require("fido2-server");
var util = require("util");

function WebAuthnStrategy(options, verify) {
	console.log("New WebAuthnStrategy");

	// TODO: sanitize options

	// TODO: create options for Fido2Server
	var fidoOptions = {
		modules: {
			comm: {
				init: function() {}
			} // no communications module -- that will be managed by the stack that is managing passport
		}
	};

	this._usernameField = options.usernameField || "username";

	passport.Strategy.call(this);
	this.name = "webauthn";

	this._fidoServer = new Fido2Server(fidoOptions)
		.init()
		.then(function(server) {
			console.log("Server init complete");
			return server;
		}.bind(this))
		.catch(function(err) {
			console.log("!!! Error initializing FIDO Server");
			console.log(err);
			process.exit(-1); // TODO: something more graceful?
		});
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(WebAuthnStrategy, passport.Strategy);

WebAuthnStrategy.prototype.authenticate = function(req, options) {
	console.log("WebAuthnStrategy authenticate!");
	console.log("Body");
	console.log(req.body);
	console.log("Query");
	console.log(req.query);

	console.log("Options");
	console.log(options);

	var username = req.body[this._usernameField] || req.query[this._usernameField];
	console.log("Username:", username);

	if (!username) {
		console.log("username missing, failing");
		return this.fail({
			message: options.badRequestMessage || "Username missing"
		}, 400);
	}

	var op = req.body.op || req.query.op;

	if (!op) {
		console.log("no operation requested, failing");
		return this.fail({
			message: options.badRequestMessage || "Operation missing"
		}, 400);
	}

	console.log("USERNAME:", username, "; OP:", op);

	var _registerChallenge = function(req, options) {
		console.log("WebAuthnStrategy registerChallenge!");

		var username = req.body[this._usernameField] || req.query[this._usernameField];
		console.log("Username:", username);

		if (!username) {
			return this.fail({
				message: options.badRequestMessage || "Username missing"
			}, 400);
		}

		console.log("makeCredential challenge for:", username);
		// TODO: make sure user doesn't already exist
		var fidoServer;
		return this._fidoServer
			.then(function(server) {
				fidoServer = server;
				return fidoServer.account.createUser(username);
			})
			.then(function(user) {
				console.log("Register created user:", user);
				if (user === undefined) {
					console.log("Couldn't create user:", username);
					throw (new Error("Couldn't create user " + username));
				}
				return fidoServer.getAttestationChallenge(username);
			}.bind(this))
			.then(function(challenge) {
				// TODO: res.send(challenge)
				console.log(challenge);
				console.log("SUCCESS!");
				return this.raw(challenge, {
					json: true
				});
			}.bind(this))
			.catch(function(err) {
				// TODO: if failing and user already created, delete the user
				console.log(err);
				console.log("EPIC FAIL!");
				return this.fail(err.message);
			}.bind(this));
	}.bind(this);

	var _register = function(req, options) {
		console.log("WebAuthnStrategy register!");

		var username = req.body[this._usernameField] || req.query[this._usernameField];
		console.log("Username:", username);

		if (!username) {
			return this.fail({
				message: options.badRequestMessage || "Username missing"
			}, 400);
		}

		// if this isn't a request for a challenge, manage the response
		console.log("makeCredential for:", username);
		var fidoServer;
		return this._fidoServer
			.then(function(server) {
				fidoServer = server;
				return fidoServer.makeCredentialResponse(username, req.body);
			})
			.then(function(cred) {
				return this.success(username);
			}.bind(this))
			.catch(function(err) {
				return this.error(err);
			}.bind(this));
	}.bind(this);

	var _authChallenge = function(req, options) {
		console.log("WebAuthnStrategy authenticateChallenge!");

		var username = req.body[this._usernameField] || req.query[this._usernameField];
		console.log("Username:", username);

		if (!username) {
			return this.fail({
				message: options.badRequestMessage || "Username missing"
			}, 400);
		}

		return this._fidoServer.getAssertionChallenge(username)
			.then(function(challenge) {
				console.log("getAssertionChallenge challenge:");
				console.log(challenge);
				// TODO: res.send(cred)
				return this.raw(cred);
			}.bind(this))
			.catch(function(err) {
				console.log("ERROR:");
				console.log(err);
				return this.error(err);
			}.bind(this));
	}.bind(this);

	var _authenticate = function(req, options) {
		// TODO: server.getAssertionResponse
		return this._fidoServer.getAssertionResponse(username, req.body)
			.then(function(assertion) {
				console.log("Comm sending:", assertion);
				return this.success(assertion);
			})
			.catch(function(err) {
				console.log("ERROR:");
				console.log(err);
				return this.fail(err.message);
			});
	}.bind(this);

	console.log("Options:", options);

	switch (op) {
		case "registerChallenge":
			return _registerChallenge(req, options);
		case "register":
			return _register(req, options);
		case "authChallenge":
			return _authChallenge(req, options);
		case "auth":
			return _authenticate(req, options);
		default:
			return this.fail({
				message: "Unknown operation"
			});
	}
};

/**
 * Expose `WebAuthnStrategy`.
 */
module.exports = WebAuthnStrategy;