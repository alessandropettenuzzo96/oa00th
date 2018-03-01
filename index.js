import * as jwt from 'jsonwebtoken';
let axios = require('axios');

export class Oa00th {
    private BASE_API_PATH = 'http://oauth.k1nd3rg4rt3n.com/';
    clientId = null;
    clientSecret = null;
    getUserFromId = (userId) => {};

    public constructor(clientId, clientSecret, getUserFromId) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.getUserFromId = getUserFromId;
    }

    authenticate(scope, authFailedHandler) {
        let that = this;
        return (req, res, next) => {
            let header = req.headers['authorization'];
            if (!header) return authFailedHandler({
                missingToken: true,
                message: 'Authentication header not passed'
            });
            header = header.split(' ');
            if (header.length !== 2) return authFailedHandler({message: 'Authentication header malformed'});
            if (header[0] !== 'Bearer') return authFailedHandler({message: 'Authentication header not Bearer type'});
            let token = header[1];
            if (!token) return authFailedHandler({message: 'Authentication header not contain token'});
            jwt.verify(token, that.clientSecret, (err, decoded) => {
                if (err || !decoded || !decoded.inn) return authFailedHandler({message: 'Invalid AccessToken'});
                decoded.inn = new Buffer(decoded.inn, 'base64').toString('utf8');
                if (!decoded.inn) return authFailedHandler({message: 'Invalid AccessToken encoded format.'});
                jwt.decode(decoded.inn, (err, inner) => {
                    if (err || !inner || !inner.usr || !inner.exp || inner.iss || inner.aud || !inner.scp) return authFailedHandler({message: 'Token not contain valid informations'});
                    let usr = inner.usr;
                    let exp = inner.exp;
                    let aud = inner.aud;
                    let scp = inner.scp.split(' ');
                    let iss = inner.iss;
                    if ((new Date()).getTime() >= exp) return authFailedHandler({
                        isExpired: true,
                        message: 'Token is expired'
                    });
                    if (aud !== that.clientId) return authFailedHandler({message: 'Token has invalid audience'});
                    if (iss !== 'n00z_oauth_server') return authFailedHandler({message: 'Token has invalid issuer'});
                    if (scp.filter((el) => {
                            scope.indexOf(el)
                        }).length !== scope.length) return authFailedHandler({
                        insufficientScopes: true,
                        message: 'User not has sufficient privileges'
                    });
                    that.getUserFromId(usr).then((user) => {
                        req.user = user;
                        next();
                    }).catch((err) => {
                        authFailedHandler(err);
                    });
                })
            })
        }
    }

    login(username, password, scopes) {
        let that = this;
        return new Promise((resolve, reject) => {
            axios.post(that.BASE_API_PATH + 'oauth/token', {
                client_id: that.clientId,
                client_secret: that.clientSecret,
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
    }

    refresh(refreshToken) {
        let that = this;
        return new Promise((resolve, reject) => {
            axios.post(that.BASE_API_PATH + 'oauth/token', {
                client_id: that.clientId,
                client_secret: that.clientSecret,
                grant_type: 'refresh_token',
                refresh_token: refreshToken
            }).then((response) => {
                if (!response) return reject('Unexpected response');
                return resolve(response);
            }).catch((err) => {
                return reject(err.message);
            })
        });
    }

    logout(refreshToken) {
        return new Promise((resolve, reject) => {
            axios.post(that.BASE_API_PATH + 'oauth/revoke', {refresh_token: refreshToken}).then((response) => {
                if (!response || response.status !== 'revoked') return reject('Unexpected response');
                resolve();
            }).catch((err) => {
                return reject(err.message);
            });
        });
    }

    createUser(username, password, scopes) {
        let that = this;
        return new Promise((resolve, reject) => {
            if (!scopes) return reject('Scopes not defined');
            axios.post(that.BASE_API_PATH + "app/" + that.clientId + "/users/create", {
                client_id: that.clientId,
                client_secret: that.clientSecret,
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
    }

    deleteUser(userId) {
        let that = this;
        return new Promise((resolve, reject) => {
            axios.delete(that.BASE_API_PATH + 'app/' + that.clientId + '/users/' + userId).then((response) => {
                if (!response || response.status !== 'deleted') return reject('Unexpected response');
                return resolve();
            }).catch((err) => {
                return reject(err.message);
            });
        });
    }
}

