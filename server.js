const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const crypto = require("crypto");
const { sendVerificationEmail } = require("./emailUtils");
const flash = require("connect-flash");

// Load environment variables
dotenv.config();

const app = express();
const port = 3000;

// Setting up ejs
app.set("view engine", "ejs");

// Middleware to parse POST data
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration
app.use(
  session({
    secret: "your_secret_key", // Change this in production
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize Passport.js middleware
app.use(passport.initialize());
app.use(passport.session());

// Initialize connect-flash
app.use(flash()); // Place this after session and passport middleware

// Middleware to set locals for flash messages
app.use((req, res, next) => {
  res.locals.isAuthenticated = req.isAuthenticated
    ? req.isAuthenticated()
    : false;
  res.locals.message = req.flash("message"); // Make flash messages available in views
  next();
});

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1); // Gracefully exit the process if the connection fails
  });

// Define User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verificationCode: { type: String, required: true }, // Verification code sent via email
  verificationExpires: { type: Date }, // Expiry time for verification code
  isVerified: { type: Boolean, default: false }, // Whether the account is verified
  verificationNo: { type: String },
  authProvider: {
    type: String,
    enum: ["local", "google", "phone"],
    default: "local",
  },
});

// Create User model
const User = mongoose.model("User", userSchema);

// Serve static files (CSS, JS, images)
app.use(express.static(path.join(__dirname, "public")));

// Passport.js configuration
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username });
      if (!user) {
        return done(null, false, { message: "Incorrect username." });
      }

      const match = await bcrypt.compare(password, user.password);
      if (match) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Incorrect password." });
      }
    } catch (err) {
      return done(err);
    }
  })
);

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// Route for the homepage (index.html)
app.get("/", (req, res) => {
  res.render("home", {
    isAuthenticated: req.isAuthenticated(),
    username: req.user ? req.user.username : null,
  });
});

// Route for profile page
app.get("/profile", (req, res) => {
  if (req.isAuthenticated()) {
    return res.render("profile", {
      isAuthenticated: true,
      username: req.user.username, // Pass username
      email: req.user.email, // Pass email
      message: req.flash("message"), // Pass any flash messages
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/login", (req, res) => {
  res.render("login", {
    isAuthenticated: req.isAuthenticated(),
    username: req.user ? req.user.username : null,
  });
});

/*
// Route for login page
app.get("/login", (req, res) => {
  res.render("login", { isAuthenticated: req.isAuthenticated() });
});*/

// Route for login
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/profile",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

// Route for signup page
app.get("/signup", (req, res) => {
  res.render("signup", {
    isAuthenticated: req.isAuthenticated(),
    username: req.user ? req.user.username : null,
    message: null, // Ensure `message` is always passed
  });
});

// register user now called signup
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Check if the username or email already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.render("signup", {
        isAuthenticated: req.isAuthenticated(),
        message: "Email or username already signuped.",
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate verification code
    const verificationCode = Math.floor(100000 + Math.random() * 900000); // Generates a 6-digit number
    const verificationExpires = Date.now() + 3600000; // 1 hour expiry time
    const verificationNo = crypto.randomBytes(20).toString("hex");
    // Create the verification URL
    const verificationUrl = `${process.env.BASE_URL}/verify-email/${verificationNo}`;
    console.log("Verification code 1:", verificationCode);
    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      verificationCode,
      verificationNo,
      verificationExpires,
    });
    console.log("Verification code 2:", verificationCode);

    // Save new user to the database
    await newUser.save();
    console.log("Verification code 3:", verificationCode);

    // Send the verification email with the verification URL
    console.log("Verification URL:", verificationUrl);
    await sendVerificationEmail(email, verificationUrl, verificationCode);
    console.log("Verification code 4:", verificationCode);

    // Redirect to the verification page (not login page)
    return res.redirect(verificationUrl);
  } catch (err) {
    console.error(err);
    next(err); // Send the error to the global error handler
    return res.render("signup", {
      isAuthenticated: req.isAuthenticated(),
      message: "Something went wrong. Please try again.",
    });
  }
});

// Route to handle email verification
// Verification route (to verify the user's email with the code)
app.get("/verify-email/:verificationNo", async (req, res) => {
  const { verificationNo } = req.params;

  try {
    const user = await User.findOne({ verificationNo });

    if (!user) {
      return res.render("verify-email", {
        message: "Invalid or expired verification code.",
        isAuthenticated: req.isAuthenticated(), // Pass isAuthenticated
        username: req.user ? req.user.username : null, // Pass username if authenticated
      });
    }

    // Check if the verification code has expired
    if (user.verificationExpires < Date.now()) {
      return res.render("verify-email", {
        message: "Verification code has expired. Please request a new one.",
        isAuthenticated: req.isAuthenticated(), // Pass isAuthenticated
        username: req.user ? req.user.username : null, // Pass username if authenticated
      });
    }
    // Render the verification form with a message
    res.render("verify-email", {
      message: "Please enter the verification code sent to your email.",
      isAuthenticated: req.isAuthenticated(),
      username: req.user ? req.user.username : null,
    });
  } catch (err) {
    console.error(err);
    res.render("verify-email", {
      message: "Something went wrong, try again later.",
    });
  }
});

// Handle verification code submission (POST)
app.post("/verify-email", async (req, res) => {
  const { verificationCode } = req.body;

  try {
    const user = await User.findOne({ verificationCode });

    if (!user) {
      return res.render("verify-email", {
        message: "Invalid or expired verification code.",
      });
    }

    // Check if the verification code has expired
    if (user.verificationExpires < Date.now()) {
      return res.render("verify-email", {
        message: "Verification code has expired. Please request a new one.",
      });
    }

    // Activate the user's account (remove the verification code)
    user.verificationNo = undefined;
    user.verificationExpires = undefined;
    user.isVerified = true; // Flag to mark the account as verified
    await user.save();

    // Redirect to a success page (e.g., login page)
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.render("verify-email", {
      message: "Something went wrong, try again later.",
      isAuthenticated: req.isAuthenticated(), // Pass isAuthenticated
      username: req.user ? req.user.username : null, // Pass username if authenticated
    });
  }
});

app.use((req, res, next) => {
  res.locals.isAuthenticated = req.isAuthenticated
    ? req.isAuthenticated()
    : false;
  next();
});

// Route for logging out
app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

app.use((req, res, next) => {
  res.locals.isAuthenticated = req.isAuthenticated
    ? req.isAuthenticated()
    : false;
  next();
});

app.use(flash());

app.use((req, res, next) => {
  res.locals.message = req.flash();
  next();
});
app.use((err, req, res, next) => {
  console.error(err.stack);

  res.status(500).render("error", {
    message:
      err.message || "An unexpected error occurred. Please try again later.",
    isAuthenticated: req.isAuthenticated ? req.isAuthenticated() : false,
  });
});

// for google login

const GoogleStrategy = require("passport-google-oauth20").Strategy;

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ email: profile.emails[0].value });

        if (!user) {
          user = new User({
            username: profile.displayName,
            email: profile.emails[0].value,
            password: crypto.randomBytes(16).toString("hex"), // random fallback
            isVerified: true,
          });
          await user.save();
        }

        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "/profile",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.use(express.static(path.join(__dirname, "public/css")));

const jwt = require("jsonwebtoken");

app.post("/auth/firebase", async (req, res) => {
  const { email, phone, displayName, provider } = req.body;

  if (!email && !phone)
    return res.status(400).json({ message: "No email or phone found." });

  try {
    // Try finding user by email or phone
    const query = email ? { email } : { phone };
    let user = await User.findOne(query);

    if (!user) {
      // Register new user
      user = new User({
        email,
        phone,
        username: displayName || email || phone,
        authProvider: provider,
        isVerified: true,
      });
      await user.save();
    }

    // Manual login (mock session)
    req.login(user, (err) => {
      if (err) {
        console.error("Login error:", err);
        return res.status(500).json({ message: "Session failed." });
      }
      return res
        .status(200)
        .json({ message: "Login successful", redirect: "/profile" });
    });
  } catch (err) {
    console.error("Firebase Auth error:", err);
    res.status(500).json({ message: "Something went wrong" });
  }
});
