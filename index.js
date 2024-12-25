const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const path = require('path');
const cookieParser = require('cookie-parser');
const cors = require('cors'); // Add CORS for cross-origin requests

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware for parsing JSON, form-urlencoded data, and cookies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS Configuration
app.use(cors({
  origin: 'https://kheti-mitra-only-frontend.vercel.app', // Your frontend URL
  credentials: true, // Allow credentials (cookies)
}));

// Serve static files (HTML, CSS, JS) from 'views' folder
app.use(express.static(path.join(__dirname, 'views')));

// Connect to MongoDB first
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('MongoDB connected');

    // Start the server after successful MongoDB connection
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit process if MongoDB connection fails
  });

// Define User schema and model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Generate JWT token function
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.cookies.jwt; // Token stored in cookies
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.userId = decoded.userId; // Attach user ID to request
    next();
  });
};

// Register route
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'Registration successful. Please log in.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = generateToken(user._id);

    // Store token in HttpOnly cookie
    res.cookie('jwt', token, {
      httpOnly: true, // Cookie can't be accessed by JavaScript
      secure: process.env.NODE_ENV === 'production', // Ensure HTTPS in production
      sameSite: 'Strict', // Prevent CSRF attacks
      maxAge: 24 * 60 * 60 * 1000, // Cookie expiry time (1 day)
    });

    res.status(200).redirect('https://kheti-mitra-only-frontend.vercel.app/login.html');

    // res.status(200).json({ message: 'Login successful' }); // Send JSON response for frontend handling
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Validate token route (for frontend to call)
app.get('/validate-token', verifyToken, (req, res) => {
  res.status(200).json({ message: 'Token is valid', userId: req.userId });
});

// Logout route
app.post('/logout', (req, res) => {
  res.clearCookie('jwt', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
  });
  res.status(200).json({ message: 'Logout successful' });
});
