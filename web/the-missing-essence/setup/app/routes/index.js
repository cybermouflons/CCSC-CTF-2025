#!/usr/bin/env node
const fs = require('fs');
const express = require('express');
const router = express.Router();
const JWTHelper = require('../helpers/JWTHelper');
const AuthMiddleware = require('../middleware/AuthMiddleware');

const response = data => ({ message: data });
const params = (data, def) => {
	for (let [key, value] of Object.entries(data)) {
		let keys = key.split('.').filter(s => s.length > 0);
		if (!keys.length) continue;

		let obj = def;
		do {
			obj = obj[keys.shift()];
		} while (obj != undefined && keys.length > 1);

		if (obj) obj[keys.shift()] = value;
	}
	return def;
};

router.get('/', (req, res) => {
	return res.render('index.html');
});

router.post('/api/login', async (req, res) => {
	const { auth, } = params(req.body, {auth: {username: false, password: false}});

	console.log('algorithms', ({}).algorithms);

	if (typeof auth.username === 'string' && typeof auth.password === 'string') {
		return db.login(auth.username, auth.password)
			.then((user) => {
				if (!user) new Error('User now found!');
				let token = JWTHelper.sign({ username: user.username });
				res.cookie('session', token, { maxAge: 3600000 });
				return res.send(response('User authenticated successfully!'));
			})
			.catch((err) => {
				console.log(err);
				return res.status(403).send(response('Invalid username or password!'));
			});
	}

	return res.status(500).send(response('User authenticated failed!'));
});

router.post('/api/register', async (req, res) => {
	const { user, } = params(req.body, {user: {username: false, password: false}});

	if (typeof user.username === 'string' && typeof user.password === 'string') {
		return db.register(user.username, user.password)
			.then(() => {
				return res.send(response('User registered successfully!'));
			})
			.catch((err) => {
				console.log(err);
				return res.status(403).send(response('Registration failed!'));
			});
	}

	return res.status(500).send(response('Registration failed!'));
});

router.get('/panel', AuthMiddleware, async (req, res) => {
	let message = 'Login as admin to manage this vote';
	
	if (req.data.username === 'admin')
		message = fs.readFileSync('/flag.txt', 'utf8').trim();

	return res.render('panel.html', { message, user: req.data.username });
});

router.get('/logout', (req, res) => {
	res.clearCookie('session');
	return res.redirect('/');
});

module.exports = database => {
	db = database;
	return router;
};
