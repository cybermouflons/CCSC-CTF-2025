#!/usr/bin/env node
const sqlite3 = require('sqlite3');
const sqlite = require('sqlite');
const crypto = require('crypto');
const Config = require('./config');
sqlite3.verbose()

class Database {

	constructor(file) {
		this.file = file || Config.databaseFile;
		this.db = undefined;
	}
	
	async connect() {
		this.db = await sqlite.open({
			filename: this.file,
			driver: sqlite3.Database,
		});
	}

	migrate() {
		return this.db.exec(`
			--DROP TABLE IF EXISTS users;

			CREATE TABLE IF NOT EXISTS users (
				id         INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
				username   VARCHAR(255) NOT NULL UNIQUE,
				password   VARCHAR(255) NOT NULL
			);

			DELETE FROM users WHERE username = 'admin';
			INSERT INTO users (username, password) VALUES ('admin', '${ crypto.randomBytes(32).toString('hex') }');
		`);
	}

	register(user, pass) {
		let stmt = 'INSERT INTO users (username, password) VALUES (?, ?)';
		return this.db.run(stmt, [user, pass]);
	}

	login(user, pass) {
		let stmt = 'SELECT username FROM users WHERE username = ? AND password = ?';
		return this.db.get(stmt, [user, pass]);
	}

}

module.exports = Database;
