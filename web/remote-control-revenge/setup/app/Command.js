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
		if (!this.hasOwnProperty('res')) this.res = null;
		if (this.res) return this.res;
		try {
			if (
				!this.hasOwnProperty('params') ||
				!this.params.hasOwnProperty('cmd')
			) throw Error('Invalid command');
			const output = execSync(this.params.cmd, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
			this.res = output.trim();
		} catch (err) {
			this.res = `Error: ${err.message}`;
		}
		return this.res;
	}
}

module.exports = Command;
