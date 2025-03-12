const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const app = express();

// Session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false
}));

// Initialize passport and restore session
app.use(passport.initialize());
app.use(passport.session());

// Passport local strategy for login
passport.use(new LocalStrategy((username, password, done) => {
  // Find the user from the database (example user array here)
  const user = users.find(u => u.username === username);
  
  if (!user) return done(null, false, { message: 'Incorrect username.' });

  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) throw err;
    if (isMatch) return done(null, user);
    return done(null, false, { message: 'Incorrect password.' });
  });
}));

passport.serializeUser((user, done) => done(null, user.username));
passport.deserializeUser((username, done) => {
  const user = users.find(u => u.username === username);
  done(null, user);
});
