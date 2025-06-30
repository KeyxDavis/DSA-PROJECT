// server.js
const express = require('express');
const cors = require('cors');
const { Sequelize, DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(cors());
app.use(express.json());

const sequelize = new Sequelize('postgres://username:password@localhost:5432/mentorship_db');

// User model
const User = sequelize.define('User', {
  email: { type: DataTypes.STRING, unique: true, allowNull: false },
  passwordHash: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.ENUM('admin', 'mentor', 'mentee'), allowNull: false },
  name: DataTypes.STRING,
  bio: DataTypes.TEXT,
  skills: DataTypes.ARRAY(DataTypes.STRING),
  goals: DataTypes.TEXT,
});

// Sync DB
sequelize.sync({ alter: true }).then(() => console.log('DB synced'));

// JWT secret
const JWT_SECRET = 'your_jwt_secret_here';

// Middleware to authenticate and attach user to req
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.sendStatus(401);
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Role-based middleware
const authorizeRoles = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.sendStatus(403);
  next();
};

// Register route (only Admin can create users)
app.post('/auth/register',
  authenticateJWT,
  authorizeRoles('admin'),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  body('role').isIn(['admin', 'mentor', 'mentee']),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password, role } = req.body;
    const passwordHash = await bcrypt.hash(password, 10);

    try {
      const user = await User.create({ email, passwordHash, role });
      res.status(201).json({ id: user.id, email: user.email, role: user.role });
    } catch (e) {
      res.status(400).json({ error: 'Email already exists' });
    }
  });

// Login route
app.post('/auth/login',
  body('email').isEmail(),
  body('password').exists(),
  async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  });

// Get current user profile
app.get('/users/me', authenticateJWT, async (req, res) => {
  const user = await User.findByPk(req.user.id);
  if (!user) return res.sendStatus(404);
  res.json({
    id: user.id,
    email: user.email,
    role: user.role,
    name: user.name,
    bio: user.bio,
    skills: user.skills,
    goals: user.goals,
  });
});

// Update profile
app.put('/users/me/profile', authenticateJWT, async (req, res) => {
  const { name, bio, skills, goals } = req.body;
  const user = await User.findByPk(req.user.id);
  if (!user) return res.sendStatus(404);

  user.name = name || user.name;
  user.bio = bio || user.bio;
  user.skills = skills || user.skills;
  user.goals = goals || user.goals;
  await user.save();

  res.json({ message: 'Profile updated' });
});

// Start server
app.listen(3000, () => console.log('Server running on http://localhost:3000'));
// Error handling middleware