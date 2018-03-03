let jwt = require('jsonwebtoken');
let axios = require('axios');
const BASE_API_PATH = 'http://oauth.k1nd3rg4rt3n.com/';

module.exports.Oa00th = function (clientId, clientSecret, getUserFromId) {
    this.authenticate = function(scope, authFailedHandler) {
        let that = this;
        var h = function(req, res, next) {
            let header = req.headers['authorization'];
            if (!header) return authFailedHandler(req, res, next, {
                missingToken: true,
                message: 'Authentication header not passed'
            });
            header = header.split(' ');
            if (header.length !== 2) return authFailedHandler(req, res, next, {message: 'Authentication header malformed'});
            if (header[0] !== 'Bearer') return authFailedHandler(req, res, next, {message: 'Authentication header not Bearer type'});
            let token = header[1];
            if (!token) return authFailedHandler(req, res, next, {message: 'Authentication header not contain token'});
            jwt.verify(token, clientSecret, (err, decoded) => {
                if (err || !decoded || !decoded.inn) return authFailedHandler(req, res, next, {message: 'Invalid AccessToken'});
                console.log("BEFORE BUFFER")
                decoded.inn = new Buffer(decoded.inn, 'base64').toString('utf8');
                console.log("After BUFFER")
                if (!decoded.inn) return authFailedHandler(req, res, next, {message: 'Invalid AccessToken encoded format.'});
                jwt.decode(decoded.inn, (err, inner) => {
                    console.log(JSON.stringify(err))
                    console.log(JSON.stringify(inner))
                    if (err || !inner || !inner.usr || !inner.exp || inner.iss || inner.aud || !inner.scp) return authFailedHandler(req, res, next, {message: 'Token not contain valid informations'});
                    let usr = inner.usr;
                    let exp = inner.exp;
                    let aud = inner.aud;
                    let scp = inner.scp.split(' ');
                    let iss = inner.iss;
                    if ((new Date()).getTime() >= exp) return authFailedHandler(req, res, next, {
                        isExpired: true,
                        message: 'Token is expired'
                    });
                    if (aud !== clientId) return authFailedHandler(req, res, next, {message: 'Token has invalid audience'});
                    if (iss !== 'n00z_oauth_server') return authFailedHandler(req, res, next, {message: 'Token has invalid issuer'});
                    if (scp.filter((el) => {
                            return scope.indexOf(el) !== -1
                        }).length !== scope.length) return authFailedHandler(req, res, next, {
                        insufficientScopes: true,
                        message: 'User not has sufficient privileges'
                    });
                    getUserFromId(usr).then((user) => {
                        req.user = user;
                        next();
                    }).catch((err) => {
                        authFailedHandler(req, res, next, err);
                    });
                })
            })
        }
        return h;
    };

    this.login = function(username, password, scopes) {
        let that = this;
        return new Promise((resolve, reject) => {
            axios.post(BASE_API_PATH + 'oauth/token', {
                client_id: clientId,
                client_secret: clientSecret,
                username: username,
                password: password,
                grant_type: 'password',
                scopes: scopes.join(' ')
            }).then((response) => {
                if (!response) return reject('Unexpected response');
                return resolve(response);
            }).catch((err) => {
                return reject(err.message);
            });
        });
    };

    this.refresh = function(refreshToken) {
        let that = this;
        return new Promise((resolve, reject) => {
            axios.post(BASE_API_PATH + 'oauth/token', {
                client_id: clientId,
                client_secret: clientSecret,
                grant_type: 'refresh_token',
                refresh_token: refreshToken
            }).then((response) => {
                if (!response) return reject('Unexpected response');
                return resolve(response);
            }).catch((err) => {
                return reject(err.message);
            })
        });
    };

    this.logout = function(refreshToken) {
        return new Promise((resolve, reject) => {
            axios.post(BASE_API_PATH + 'oauth/revoke', {refresh_token: refreshToken}).then((response) => {
                if (!response || response.status !== 'revoked') return reject('Unexpected response');
                resolve();
            }).catch((err) => {
                return reject(err.message);
            });
        });
    };

    this.createUser = function(username, password, scopes) {
        let that = this;
        return new Promise((resolve, reject) => {
            if (!scopes) return reject('Scopes not defined');
            axios.post(BASE_API_PATH + "app/" + clientId + "/users/create", {
                client_id: clientId,
                client_secret: clientSecret,
                username: username,
                password: password,
                scope: scopes.join(' ')
            }).then((user) => {
                if (!user) return reject('Unexpected response');
                return resolve(user);
            }).catch((err) => {
                return reject(err.message);
            });
        });
    };

    this.deleteUser = function(userId) {
        let that = this;
        return new Promise((resolve, reject) => {
            axios.delete(BASE_API_PATH + 'app/' + clientId + '/users/' + userId).then((response) => {
                if (!response || response.status !== 'deleted') return reject('Unexpected response');
                return resolve();
            }).catch((err) => {
                return reject(err.message);
            });
        });
    };
};

