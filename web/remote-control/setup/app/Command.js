const { execSync } = require('child_process');
const Action = require('./Action');

class Command extends Action {
	res;

	// Prepare command
	constructor(cmd) {
		super();
		this.params.cmd = cmd;
		this.res = null;
	}

	// Execute command
	execute() {
		if (this.res) return this.res;
		try {
			const output = execSync(this.params.cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
			this.res = output.trim();
		} catch (err) {
			this.res = `Error: ${err.message}`;
		}
		return this.res;
	}
}

module.exports = Command;
