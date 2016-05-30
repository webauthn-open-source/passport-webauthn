var passport = require("passport-strategy");
var Fido2Server = require("fido2-server");
var util = require("util");

function WebAuthnStrategy(options) {
	console.log("New WebAuthnStrategy");

	options = options || {};

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

// TODO:
// register should handle the following options, basically duplicated from passport:
// options.failureFlash
// options.failureMessage
// options.failureRedirect
// options.successFlash
// options.successMessage
// options.assignProperty

/**
 * Returns Express / Connect middleware for managing register requests
 *
 * This looks for an "op" attribute in the body of the message and either
 * creates a challenge (op == registerChallenge) or performs the registration (op == register)
 */
WebAuthnStrategy.prototype.register = function(options) {
	var self = this;
	return function(req, res, next) {
		console.log("WebAuthnStrategy register!");

		// validate the username
		var username = req.body[self._usernameField] || req.query[self._usernameField];
		console.log("Username:", username);

		if (!username) {
			return self.fail({
				message: options.badRequestMessage || "Username missing"
			}, 400);
		}

		// validate the op
		var op = req.body.op || req.query.op;

		if (!op) {
			console.log("no operation requested, failing");
			return self.fail({
				message: options.badRequestMessage || "Operation missing"
			}, 400);
		}

		// if (op !== "register") {
		// 	console.log("wrong operation requested, failing");
		// 	return this.fail({
		// 		message: options.badRequestMessage || "Wrong operation"
		// 	}, 400);
		// }

		var _register = function(req, options) {
			// if this isn't a request for a challenge, manage the response
			console.log("makeCredential for:", username);
			var fidoServer;
			return self._fidoServer
				.then(function(server) {
					fidoServer = server;
					return fidoServer.makeCredentialResponse(username, req.body);
				})
				.then(function(cred) {
					res.send(username);
					// self.success(username);
					// next();
				})
				.catch(function(err) {
					console.log("ERROR");
					console.log(err);
					self.error(err);
					// next();
				});
		};

		switch (op) {
			case "registerChallenge":
				return _registerChallenge.call(self, req, res, next);
			case "register":
				return _register(req, options);
			default:
				return self.fail({ // XXX TODO: res.error()?
					message: "Unknown operation"
				});
		}
	};
};

/**
 * The Express / Connect middlware for managing a register challenge
 *
 * In essence this does two things:
 *   1) Registers the new user on the authentication server
 *   2) Creates a challenge associated with the new user and returns it
 */
function _registerChallenge(req, res, next) {
	var self = this;
	console.log("WebAuthnStrategy registerChallenge!");

	// validate the username
	var username = req.body[self._usernameField] || req.query[self._usernameField];
	console.log("Username:", username);

	if (!username) {
		return self.fail({
			message: options.badRequestMessage || "Username missing"
		}, 400);
	}

	// validate the op
	var op = req.body.op || req.query.op;

	if (!op) {
		console.log("no operation requested, failing");
		return this.fail({
			message: options.badRequestMessage || "Operation missing"
		}, 400);
	}

	if (op !== "registerChallenge") {
		console.log("wrong operation requested, failing");
		return this.fail({
			message: options.badRequestMessage || "Wrong operation"
		}, 400);
	}

	console.log("makeCredential challenge for:", username);

	// TODO: make sure user doesn't already exist
	var fidoServer;
	return self._fidoServer
		.then(function(server) {
			fidoServer = server;
			// create user's account
			return fidoServer.account.createUser(username);
		})
		.then(function(user) {
			console.log("Register created user:", user);
			if (user === undefined) {
				console.log("Couldn't create user:", username);
				throw (new Error("Couldn't create user " + username));
			}
			// create a challenge for the user
			return fidoServer.getAttestationChallenge(username);
		})
		.then(function(challenge) {
			// TODO: res.send(challenge)
			console.log(challenge);
			console.log("SUCCESS!");
			res.json(challenge);
			// next();
		})
		.catch(function(err) {
			// TODO: if failing and user already created, delete the user
			console.log(err);
			console.log("EPIC FAIL!");
			self.fail(err.message);
			// next();
		});
};

/**
 * Authenticates a user using WebAuthn and Passport
 *
 * Looks for an "op" attribute in the body
 * op == authChallenge, then just return a challenge to be signed
 * op == auth, then verify the challenge and login the user
 */
WebAuthnStrategy.prototype.authenticate = function(req, options) {
	var self = this;
	console.log("WebAuthnStrategy authenticate!");
	console.log("Body");
	console.log(req.body);
	console.log("Query");
	console.log(req.query);

	console.log("Options");
	console.log(options);

	console.log ("Success is:", self.success);

	// validate the username
	var username = req.body[self._usernameField] || req.query[self._usernameField];
	console.log("Username:", username);

	if (!username) {
		console.log("username missing, failing");
		return self.fail({
			message: options.badRequestMessage || "Username missing"
		}, 400);
	}

	// validate the op
	var op = req.body.op || req.query.op;

	if (!op) {
		console.log("no operation requested, failing");
		return self.fail({
			message: options.badRequestMessage || "Operation missing"
		}, 400);
	}

	console.log("USERNAME:", username, "; OP:", op);

	var _authenticate = function(req, options) {
		return self._fidoServer
			.then(function(fidoServer) {
				return fidoServer.getAssertionResponse(username, req.body);
			})
			.then(function(assertion) {
				console.log("Comm sending:", assertion);
				return self.success(assertion);
			})
			.catch(function(err) {
				console.log("ERROR:");
				console.log(err);
				return self.fail(err.message);
			});
	};

	console.log("Options:", options);

	switch (op) {
		// case "registerChallenge":
		// 	return this.registerChallenge(options);
		// case "register":
		// 	return this.register(options);
		case "authChallenge":
			return _authChallenge.call(self, req);
		case "auth":
			return _authenticate(req, options);
		default:
			return self.fail({
				message: "Unknown operation"
			});
	}
};

/**
 * Creates an assertion challenge and stores it with the user's account
 * When the signed assertion comes back, the server will verify that the
 * challenge was the same (and the signature was correct)
 */
function _authChallenge(req, res, next) {
	var self = this;
	console.log("WebAuthnStrategy authenticateChallenge!");

	// validate the username
	var username = req.body[self._usernameField] || req.query[self._usernameField];
	console.log("Username:", username);

	if (!username) {
		return self.fail({
			message: options.badRequestMessage || "Username missing"
		}, 400);
	}

	// validate the op
	var op = req.body.op || req.query.op;

	if (!op) {
		console.log("no operation requested, failing");
		return this.fail({
			message: options.badRequestMessage || "Operation missing"
		}, 400);
	}

	if (op !== "authChallenge") {
		console.log("wrong operation requested, failing");
		return this.fail({
			message: options.badRequestMessage || "Wrong operation"
		}, 400);
	}

	// create and return the challenge
	return self._fidoServer
		.then(function(fidoServer) {
			return fidoServer.getAssertionChallenge(username)
		})
		.then(function(challenge) {
			console.log("getAssertionChallenge challenge:");
			console.log(challenge);
			// TODO: res.send(cred)
			self.raw(challenge, {
				json: true
			});
			// next();
		})
		.catch(function(err) {
			console.log("ERROR:");
			console.log(err);
			self.error(err);
			// next();
		});
}

/**
 * Expose `WebAuthnStrategy`.
 */
module.exports = WebAuthnStrategy;