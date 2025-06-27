const path = require('path');

// Select config
function ConfigGen(mode) {
	switch(mode){
		case 'dev':
			return {
				authKeyFile : path.join(__dirname, 'auth.key'),
				databaseFile : 'database.db'
			};
		case 'prod':
			return {
				databaseFile : 'database.db'
			};
		default:
			new Error('Invalid config mode.');
	}
}

module.exports = ConfigGen('prod');
