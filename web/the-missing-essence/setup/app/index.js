#!/usr/bin/env node
const express = require('express');
const app = express();
const path = require('path');
const nunjucks = require('nunjucks');
const cookieParser = require('cookie-parser');
const routes = require('./routes');
const Database = require('./database');

const db = new Database();

app.use(express.json());
app.use(cookieParser());
app.disable('etag');
app.disable('x-powered-by');

nunjucks.configure('views', {
	autoescape: true,
	express: app
});

app.set('views', './views');
app.use('/static', express.static(path.resolve('static')));

app.use(routes(db));

app.all('*', (req, res) => {
	return res.status(404).send({
		message: '404 page not found'
	});
});

(async () => {
	await db.connect();
	await db.migrate();

	let port = process.env.APP_PORT || 5000;
	app.listen(port, '0.0.0.0', () => console.log('Listening on port ' + port));
})();
