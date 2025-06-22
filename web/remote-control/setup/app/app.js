const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { serialize, unserialize } = require('php-serialize');


// Load actions
const Action = require('./Action');
const Command = require('./Command');
const FileRead = require('./FileRead');

// App paremeters
const secret = crypto.randomBytes(32).toString("base64url");
const port = 1337;
const index = {
	path: path.join(__dirname, 'index.html'),
	cached: null
};
const log_file = path.join(__dirname, 'server.log');

// Handle requests
const server = http.createServer((req, res) => {
	if (req.method === 'GET') {
		if (index.cached) {
			res.writeHead(200, { 'Content-Type': 'text/html' });
			res.end(index.cached);
			return;
		}
		fs.readFile(index.path, 'utf-8', (err, html) => {
			if (err) {
				res.writeHead(500, { 'Content-Type': 'text/plain' });
				res.end('Internal Server Error');
			}
			else {
				try {
					index.cached = html.replace(/<option data-[a-zA-Z0-9]+="{{[^"]+}}">/g, (code) => {
						const action = 
							code.match('data-command=') ? new Command(code.match(/data-command="{{([^"]+)}}"/)[1]) :
							code.match('data-readfile=') ? new FileRead(code.match(/data-readfile="{{([^"]+)}}"/)[1]) :
							null;
						if (!action) return `<option value="unknown">`;
						action.sign(secret);
						const s = btoa(serialize(action));
						return `<option value="${s}">`
					});
					res.writeHead(200, { 'Content-Type': 'text/html' });
					res.end(index.cached);
				}
				catch (e) {
					console.log(e);
					res.writeHead(500, { 'Content-Type': 'text/plain' });
					res.end('Invalid index template');
				}
			}
		});
	}
	else if (req.method === 'POST') {
		let body = '';

		req.on('data', chunk => {
			body += chunk.toString();
		});

		req.on('end', () => {
			try {
				const action = unserialize(atob(body), { Command, FileRead });
				if (!(action instanceof Action)) throw new Error('Given object is not an action');
				if (!action.verify(secret)) throw new Error('Action was not authorisated to run');
				const result = action.toString();
				log(`Executed action on server.`);
				res.writeHead(200, { 'Content-Type': 'text/plain' });
				res.end(result);
			}
			catch (err) {
				console.log(err);
				const message = `[Error] ${err}`;
				log(message);
				res.writeHead(400, { 'Content-Type': 'text/plain' });
				res.end(message);
			}
		});
	}
	else {
		res.writeHead(405, { 'Content-Type': 'text/plain' });
		res.end('Invalid request');
	}
});

// Handle loggin
const log = (message) => {
	const timestamp = new Date().toISOString();
	const line = `[${timestamp}] ${message}\n`;

	fs.appendFile(log_file, line, (err) => {
		if (err) {
			console.error('Failed to write log:', err);
		}
	});
}

server.listen(port, () => {
	console.log(`Server listening on http://localhost:${port}`);
	log(`Server listening on http://localhost:${port}`);
});
