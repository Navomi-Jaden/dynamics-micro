const axios = require('axios');
const querystring = require('querystring');

module.exports = function (options = {}) { // eslint-disable-line no-unused-vars
	return function authenticateToDynamics (hook) {
		let app = hook.app;
		
		return new Promise(function(resolve, reject) {
			let strategy = hook.data.strategy || '';
			
			let client_id = hook.data.client_id || '';
			let client_secret = hook.data.client_secret || '';
			let token = (hook.params.headers.authorization || hook.data.access_token || hook.data.code).replace(/Bearer\s/, '');
			let redirect = hook.data.redirect || '';
			
			if (strategy !== '') {
				if (token !== '') {
					if (strategy === 'local') {
						if (hook.path === 'authentication') {
							return axios.post(`https://login.microsoftonline.com/common/oauth2/token`, querystring.stringify({
								grant_type: 'authorization_code',
								code: token,
								client_id,
								client_secret,
								redirect_uri: redirect,
								scope: 'openid'
							})).then(res => {
								hook.result = app.passport.createJWT({
									access_token: res.data.access_token,
									refresh_token: res.data.refresh_token,
									id_token: res.data.id_token,
									iss: app.passport.options('jwt').jwt.issuer
								}, { secret: app.passport.options('jwt').secret });
								
								return resolve(hook);
							}).catch(err => {
								console.log(err);
								return reject(err);
							});
						}

						return reject('Local is only available on the /authentication path');
					} else if (strategy === 'jwt') {
						console.log('Token: ', token);
						return app.passport.verifyJWT(token, { secret: app.passport.options('jwt').secret }).then(res => {
							if (hook.path === 'authentication')
								hook.result = res;
							else
								hook.params.payload = res;
							
							return resolve(hook);
						}).catch(err => {
							console.log('NOOOOOO', err);
							return reject(err);
						});
					}
					
					return reject('Strategy must either be `local` or `jwt`.');
				}
				
				return reject('A token (auth code or access token) must be provided.');
			}
			
			return reject('`strategy` must be defined');
		});
	};
};
