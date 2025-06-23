import express from "express";
import db from "./db-init";
import { randomBytes } from "crypto";

const router = express.Router();

const admin_api_key = randomBytes(16).toString("hex");

router.use(express.json());

router.use((req, res, next) => {
    const apiKey = req.headers["x-api-key"];
  
    if (apiKey !== admin_api_key) {
      return res.status(403).json({ error: "Forbidden - Invalid API key" });
    }
  
    next();
  });

// Login endpoint
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password){
    return res.json({ error: "Denied" });
  }

  const user = db
    .query(`SELECT * FROM users WHERE username = $username LIMIT 1`)
    .get({
      $username: username,
    });

  if (!user) {
    return res.json({ error:"User does not exist!" });
  }

  // @ts-ignore
  if (Bun.password.verifySync(password, user?.password)) {
    return res.json({ ...user, password: "" });
  }

  res.json({ error: "Denied" });
});

// Register endpoint
router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const pHash = await Bun.password.hash(password);

  const exists = db
    .query(`SELECT * FROM users WHERE username = $username LIMIT 1`)
    .get({ $username: username });

  if (exists) {
    res.status(400).json({ error: "User already exists!" });
  }

  db.prepare(
    `INSERT INTO users (username, password)
    SELECT $username, $password
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = $username);`
  ).run({
    $username: username,
    $password: pHash,
  });

  res.status(200).json({ message: "User registered successfully!", success: true });
});

router.get('/movies', (req, res) => {
  const movies = db.query(`SELECT id, title, image FROM movies`).all();
  res.json({ movies });
});

// Show review page for a specific movie
router.get("/movies/:id", (req, res) => {
  const movieId = Number(req.params.id);
  const movie = db.query(`SELECT * FROM movies WHERE id = $id`).get({ $id: movieId });

  if (!movie) {
    return res.json({error:"Movie not found"});
  }

  const reviews = db.query(`
    SELECT r.review, u.username 
    FROM reviews r 
    JOIN users u ON r.user_id = u.id 
    WHERE r.movie_id = $movie_id
  `).all({ $movie_id: movieId });

  res.json({movie:movie,reviews:reviews});
});

router.post("/movies", (req, res) => {
  const { title, image, trailer, description } = req.body;

  if (!title || !image || !trailer || !description) {
    return res.status(400).json({ error: "All fields are required." });
  }

  db.prepare(
    `INSERT INTO movies (title, image, trailer, description)
     VALUES ($title, $image, $trailer, $description)`
  ).run({
    $title: title,
    $image: image,
    $trailer: trailer,
    $description: description,
  });

  res.status(201).json({ message: "Movie added successfully!" });
});

// Handle new review submission
router.post("/movies/:id/review", (req, res) => {
  const movieId = Number(req.params.id);
  const {review, userID} = req.body;

  if (!review || review.trim() === "") {
    return res.status(400).json({ error: "Review cannot be empty" });
  }

  db.prepare(
    `INSERT INTO reviews (user_id, movie_id, review)
     VALUES ($user_id, $movie_id, $review)`
  ).run({
    // @ts-ignore
    $user_id: userID,
    $movie_id: movieId,
    $review: review.trim()
  });

  res.status(201).json({message:"Review added"});
});

router.get("/users/:id/reviews", (req, res) => {
  const userId = Number(req.params.id);

  const reviews = db.query(`
    SELECT r.review, m.title AS movie_title
    FROM reviews r
    JOIN movies m ON r.movie_id = m.id
    WHERE r.user_id = $user_id
  `).all({ $user_id: userId });

  res.json({ reviews });
});


export {router,admin_api_key};
