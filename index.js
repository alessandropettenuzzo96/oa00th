import * as jwt from 'jsonwebtoken';

exports = (clientId, clientSecret, getUserFromid) => {
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
    }
};
