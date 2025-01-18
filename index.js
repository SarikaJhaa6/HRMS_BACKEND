require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const pool = require('./dbcon');

const app = express();
app.use(bodyParser.json());

// Initialize Passport
app.use(passport.initialize());

// Passport Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_REDIRECT_URI,
    },
    (accessToken, refreshToken, profile, done) => {
      const googleId = profile.id;
      const email = profile.emails[0].value;
      const username = profile.displayName;

      // Check if user exists
      pool.query('SELECT * FROM users WHERE google_id = ?', [googleId], (err, results) => {
        if (err) return done(err);
        if (results.length > 0) {
          return done(null, results[0]);
        } else {
          // Register new user
          pool.query(
            'INSERT INTO users (username, email, google_id, role_id) VALUES (?, ?, ?, ?)',
            [username, email, googleId, 3], // Default to Employee
            (err, results) => {
              if (err) return done(err);
              pool.query('SELECT * FROM users WHERE id = ?', [results.insertId], (err, results) => {
                if (err) return done(err);
                return done(null, results[0]);
              });
            }
          );
        }
      });
    }
  )
);

// Routes
app.post('/register', async (req, res) => {
  const { username, email, password, role_id } = req.body;

  if (!username || !email || !password || !role_id) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const [existingUser ] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existingUser .length > 0) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, email, password, role_id) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, role_id]
    );
    res.status(201).json({ message: 'User  registered successfully' });
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const [results] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

    console.log('Query results:', results); // Log the results

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = results[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log('Password valid:', isPasswordValid); // Log the password check result

    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user.id, role: user.role_id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
    res.status(200).json({ message: 'Login successful', token });
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ error: 'Database error' });
  }
});
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    const token = jwt.sign({ id: req.user.id, role: req.user.role_id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
    res.redirect(`/?token=${token}`);
  }
);

app.listen(process.env.PORT, () => {
  console.log(`Server is running on http://localhost:${process.env.PORT}`);
});
