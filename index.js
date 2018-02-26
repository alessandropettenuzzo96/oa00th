import * as jwt from 'jsonwebtoken';
let axios = require('axios');

exports = (clientId, clientSecret, getUserFromid) => {
    let BASE_API_PATH = 'http://oauth.k1nd3rg4rt3n.com/';
    return {
        authenticate: (scope, authFailedHandler) => {
            return (req, res, next) => {
                let header = req.headers['Authentication'];
                if(!header) return authFailedHandler('Authentication header not passed');
                header = header.split(' ');
                if(header.length !== 2) return authFailedHandler('Authentication header malformed');
                if(header[0] !== 'Bearer') return authFailedHandler('Authentication header not Bearer type');
                let token = header[1];
                if(!token) return authFailedHandler('Authentication header not contain token')
                jwt.verify(token, clientSecret, (err, decoded) => {
                    if(err || !decoded || !decoded.inn) return authFailedHandler('Invalid AccessToken');
                    decoded.inn = new Buffer(decoded.inn, 'base64').toString('utf8');
                    if(!decoded.inn) return authFailedHandler('Invalid AccessToken encoded format.');
                    jwt.decode(decoded.inn, (err, inner) => {
                        if(err || !inner || !inner.usr || !inner.exp || inner.iss || inner.aud || !inner.scp) return authFailedHandler('Token not contain valid informations');
                        let usr = inner.usr;
                        let exp = inner.exp;
                        let aud = inner.aud;
                        let scp = inner.scp.split(' ');
                        let iss = inner.iss;
                        if((new Date()).getTime() >= exp) return authFailedHandler('Token is expired');
                        if(aud !== clientId) return authFailedHandler('Token has invalid audience');
                        if(iss !== 'n00z_oauth_server') return authFailedHandler('Token has invalid issuer');
                        if(scp.filter((el) => { scope.indexOf(el) }).length !== scope.length) return authFailedHandler('User not has sufficient privileges');
                        getUserFromid(usr).then((user) => {
                            req.user = user;
                            next();
                        }).catch((err) => {
                            authFailedHandler(err);
                        });
                    })
                })
            }
        },

        login: (username, password, scopes) => {
            return new Promise((resolve, reject) => {
                axios.post(BASE_API_PATH+'oauth/token', { client_id: clientId, client_secret: clientSecret, username: username, password: password, grant_type: 'password', scopes: scopes.join(' ') }).then((response) => {
                    if(!response) return reject('Unexpected response');
                    return resolve(response);
                }).catch((err) => {
                    return resolve(err.message);
                });
            });
        },

        refresh: (refreshToken) => {
            return new Promise((resolve, reject) => {
                axios.post(BASE_API_PATH+'oauth/token', { client_id: clientId, client_secret: clientSecret, grant_type: 'refresh_token', refresh_token: refreshToken }).then((response) => {
                    if(!response) return reject('Unexpected response');
                    return resolve(response);
                }).catch((err) => {
                    return resolve(err.message);
                })
            });
        },

        logout: (accessToken) => {
            return new Promise((resolve, reject) => {

            });
        },

        createUser: (username, password, scopes) => {
            return new Promise((resolve, reject) => {
                if(!scopes) return reject('Scopes not defined');
                axios.post(BASE_API_PATH+"app/"+clientId+"/users/create", { client_id: clientId, client_secret: clientSecret, username: username, password: password, scope: scopes.join(' ')}).then((user) => {
                    if(!user) return reject('Unexpected response');
                    return resolve(user);
                }).catch((err) => {
                    return reject(err.message);
                });
            });
        }
    }
};
