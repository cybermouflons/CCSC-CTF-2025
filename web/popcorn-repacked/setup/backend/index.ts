import express from "express";
import session from "express-session";
import { parse } from 'url';
import path from 'path';
import { randomBytes } from "crypto";
import {router, admin_api_key} from "./api";

const app = express();

const PORT = Bun.env.PORT ?? 8080;

const flag = Bun.env.flag ?? "CCSC{fake_flag}";

app.use(express.json());

app.get("/api", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "docs.html"));
});
app.use("/api", router);

app.use(session({
  secret: randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60,
    httpOnly: true,
    secure: false,
    sameSite: 'lax'
  }
}));

app.set("view engine", "ejs");

// Serve static files from the 'images' directory at the '/images' route
app.use('/static', express.static(path.join(__dirname, 'static')));

//Authentication middleware
const authenticate = (req, res, next) => {
  if (req.session.user){
    req.user = req.session.user;
    next();
  }
  else{
    return res.status(403).redirect("/login");
  }
}

// Login endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await fetch(`http://localhost:8080/api/login`,{
    method: "POST",
    headers: {"Content-Type":"application/json", "x-api-key":admin_api_key},
    body: JSON.stringify({username,password})
  }).then(r=>r.json());

  if (user?.error) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  req.session.user = { id: user.id, username: user.username };
  res.status(200).json({message:"Login Successful!", success:true});

});

// Register endpoint
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const api_res = await fetch("http://localhost:8080/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json","x-api-key":admin_api_key},
    body: JSON.stringify({ username, password }),
  }).then((r) => r.json());

  if (api_res?.error) {
    res.status(400).json({ message: api_res?.error });
  }

  res.status(200).json({ message: "User registered successfully!", success: true });
});

app.get('/movies', authenticate, async (req, res) => {
  const movies = await fetch(`http://localhost:8080/api/movies`, {headers:{"x-api-key":admin_api_key}}).then(r=>r.json());
  res.render('movies', movies);
});

// Show review page for a specific movie
app.get("/movies/:id", authenticate, async (req, res) => {
  const movieId = Number(req.params.id);

  const api_res = await fetch(`http://localhost:8080/api/movies/${movieId}`,{headers:{"x-api-key":admin_api_key}}).then(r=>r.json());

  if (api_res?.error) {
    return res.status(404).send(api_res?.error);
  }

  res.render("review", {
    movie:api_res?.movie,
    reviews:api_res?.reviews
  });
});


// Handle new review submission
app.post("/movies/:id/review", authenticate, async (req, res) => {
  const movieId = Number(req.params.id);
  const review = req.body.review;

  if (!review || review.trim() === "") {
    return res.status(400).json({ message: "Review cannot be empty" });
  }

  const api_res = await fetch(`http://localhost:8080/api/movies/${movieId}/review`,{
    method: "POST",
    headers: {"Content-Type":"application/json", "x-api-key":admin_api_key},
    body: JSON.stringify({review:review, userID:req.user.id}),
  }).then(r=>r.json());

  if (api_res?.error){
    return res.status(400).json({ message: api_res?.error});   
  }

  res.redirect(`/movies/${movieId}`);
});

app.get("/profile*", authenticate, async (req, res) => {
  const userId = req.user.id;

  console.log(`/profile visited from userID ${userId}!`);

  let api_res = await fetch(`http://localhost:8080/api/users/${userId}/reviews`, {headers:{"x-api-key":admin_api_key}});
  const { reviews } = await api_res.json();

  let apikey = "";
  if (userId == 1)
    apikey = admin_api_key;


  res.render("profile", {
    user: req.user,
    reviews,
    apikey: apikey
  });
});

app.post("/admin", authenticate, (req, res) => {
  const user = req.user;
  if (user?.username !== "admin") {
    return res.status(403).json({ flag: "Forbidden. No admin permissions." });
  }

  res.json({ flag: flag });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  console.log("/login visited");
  res.render("login");
});

app.post("/logout", authenticate, (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/favicon.ico", (req, res) => {
  res.sendFile("favicon.ico", { root: "./static" });
});

app.get("/*", (req, res) => {
  res.redirect("/login");
});

app
  .listen(PORT, () => {
    console.log(`backend-service listening on port ${PORT}...`);
  })
  .setTimeout(10 * 1000);
