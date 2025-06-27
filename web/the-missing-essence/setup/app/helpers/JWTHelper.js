const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Config = require('../config');

const APP_SECRET = crypto.randomBytes(69).toString('hex');
const APP_SECRET_FILE = (() => {
	// Check if the file exists
	if (Config.authKeyFile && fs.existsSync(Config.authKeyFile)) {
		return fs.readFileSync(Config.authKeyFile, 'utf8');
	}
	return false;
})();

module.exports = {
	sign(data) {
		data = Object.assign(data);
		return (jwt.sign(data, Config.authKeyFile ? APP_SECRET_FILE : APP_SECRET, { algorithm:'HS256' }))
	},
	async verify(token) {
		console.log('verify', ({ algorithm:'HS256' }).algorithms);
		return (jwt.verify(token, Config.authKeyFile ? APP_SECRET_FILE : APP_SECRET, { algorithm:'HS256' }));
	}
}
