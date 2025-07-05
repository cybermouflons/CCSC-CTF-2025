const crypto = require('crypto');

class Action {
	sig;
	params;

	// Prepare action
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
		const data = JSON.parse(JSON.stringify(JSON.parse(raw)));
		this.sig = data.s;
		this.params = data.p;
	}

	// Verify permission to run action
	toSign() {
		this.params = JSON.parse(JSON.stringify(this.params));
		return JSON.stringify({p: this.params});
	}
	sign(key) {
		const hmac = crypto.createHmac('sha256', key);
		hmac.update(this.toSign());
		this.sig = hmac.digest('hex');
		return this.sig;
	}
	verify(key) {
		const hmac = crypto.createHmac('sha256', key);
		hmac.update(this.toSign());
		const expectedSig = hmac.digest('hex');
		return this.sig === expectedSig;
	}

	// Execute action
	execute() {
		throw new Error('Not implemented');
	}

	toString() {
		return this.execute();
	}
}

module.exports = Action;
