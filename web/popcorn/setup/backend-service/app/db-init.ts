import { Database } from "bun:sqlite";
import { randomBytes } from "crypto";

const db = new Database();

db.query(
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);`
).run();

const Users = [
  { username: 'admin', password: 'F6vF0Q3OXZbK5QZOSBlDzGU1LTn6ieol'},
  { username: 'alice', password: 'alice123' },
  { username: 'bob', password: 'bob123' },
  { username: 'charlie', password: 'charlie123' }
];

const UserIDs = {admin:1,alice:2,bob:3,charlie:4};

for (const user of Users) {
  const hashedPassword = await Bun.password.hash(user.password);
  db.prepare(`
    INSERT INTO users (username, password)
    SELECT $username, $password
    WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = $username);
  `).run({
    $username: user.username,
    $password: hashedPassword
  });
}

db.query(
    `CREATE TABLE IF NOT EXISTS movies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      image TEXT NOT NULL,
      trailer TEXT NOT NULL,
      description TEXT NOT NULL
  );`
  ).run();

// Insert movies only if table is empty
const existing = db.query(`SELECT COUNT(*) as count FROM movies`).get();
if (existing.count === 0) {
  const movies = [
    {
      title: 'Cash',
      image: '/static/images/cash.jpg',
      trailer: 'https://www.youtube.com/embed/kN-HQAM92kQ?si=Bj2c4ev445BbrTm6',
      description: 'A fast-paced heist thriller that explores greed and deception.'
    },
    {
      title: 'Inception',
      image: '/static/images/inception.jpg',
      trailer: 'https://www.youtube.com/embed/8hP9D6kZseM?si=zvh6QnxqQcy4Xj8E',
      description: 'A mind-bending sci-fi journey through the architecture of dreams.'
    },
    {
      title: 'Interstellar',
      image: '/static/images/interstellar.jpg',
      trailer: 'https://www.youtube.com/embed/zSWdZVtXT7E?si=qLZGscrDytK1ULWS',
      description: 'A space exploration epic centered on survival and human connection.'
    },
    {
      title: 'The Dark Knight',
      image: '/static/images/darkknight.jpg',
      trailer: 'https://www.youtube.com/embed/EXeTwQWrcwY?si=EkBT7AD-GQHnnX87',
      description: 'A gritty crime drama exploring justice, chaos, and duality.'
    },
    {
      title: 'Avatar',
      image: '/static/images/avatar.jpg',
      trailer: 'https://www.youtube.com/embed/5PSNL1qE6VY?si=p1pPPClz1aFnZ6WB',
      description: 'A visually stunning tale of ecological struggle on an alien world.'
    }
  ];

  const insert = db.prepare(
    `INSERT INTO movies (title, image, trailer, description) VALUES ($title, $image, $trailer, $description)`
  );

  for (const movie of movies) {
    insert.run({
      $title: movie.title,
      $image: movie.image,
      $trailer: movie.trailer,
      $description: movie.description
    });
  }
} 

const movieIDs = {cash:1,inception:2, interstellar:3, darkKnight:4, avatar:5};

// Create reviews table
db.query(
    `CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      movie_id INTEGER NOT NULL,
      review TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (movie_id) REFERENCES movies(id)
    );`
  ).run();

const reviewInsert = db.prepare(`
  INSERT INTO reviews (user_id, movie_id, review)
  VALUES ($user_id, $movie_id, $review)
`);

const sampleReviews = [
  { user: 'alice', movie: 'inception', review: 'Mind-blowing concept and visuals!' },
  { user: 'bob', movie: 'interstellar', review: 'Amazing soundtrack and storytelling.' },
  { user: 'charlie', movie: 'cash', review: 'Surprisingly intense and fast-paced!' },
  { user: 'alice', movie: 'avatar', review: 'Beautiful world-building and visuals.' },
  { user: 'bob', movie: 'darkKnight', review: 'Heath Ledger stole the show!' },
  { user: 'admin', movie: 'inception', review: 'This movie is a CTF in itself.' }
];

for (const r of sampleReviews) {
  reviewInsert.run({
    $user_id: UserIDs[r.user],
    $movie_id: movieIDs[r.movie],
    $review: r.review
  });
}

export default db;