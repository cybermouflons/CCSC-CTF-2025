const fs = require('fs');
const path = require('path');
const Action = require('./Action');

class FileRead extends Action {
	content;

	// Prepare file
	constructor(file) {
		super();
		this.params.path = path.join(__dirname, file);
		this.content = null;
	}

	// Execute command
	execute() {
		if (this.content) return this.content;
		try {
			this.content = fs.readFileSync(this.params.path, 'utf8');
		} catch (err) {
			this.content = `Error: ${err.message}`;
		}
		return this.content;
	}
}

module.exports = FileRead;
