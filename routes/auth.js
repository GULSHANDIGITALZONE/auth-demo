
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const router = express.Router();

const User = require('../models/User');
const Otp = require('../models/Otp');
const { generateNumericOTP, generateTokenHex } = require('../utils/generate');
const { sendOTPEmail, sendResetLinkEmail } = require('../utils/sendEmail');

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS || '10');
const JWT_SECRET = process.env.JWT_SECRET || 'change_this';
const JWT_EXPIRES = '7d';

// Helper: hash string (otp/token)
const crypto = require('crypto');
function hashString(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

// RATE LIMITING SKIP HERE - add global limiter in server.js

// Signup (phone + password, email optional)
router.post('/signup', async (req, res) => {
  try {
    const { name, phone, password, email } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'phone and password required' });

    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const existing = await User.findOne({ phone });
    if (existing) return res.status(409).json({ error: 'Phone already registered' });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const user = new User({ name, phone, email, passwordHash: hash });
    await user.save();
    const token = jwt.sign({ id: user._id, phone: user.phone }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.json({ message: 'Signup success', token, user: { id: user._id, name: user.name, phone: user.phone, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

// Login (phone + password)
router.post('/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: 'phone and password required' });
    const user = await User.findOne({ phone });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    user.lastLoginAt = new Date();
    await user.save();
    const token = jwt.sign({ id: user._id, phone: user.phone }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.json({ message: 'Login success', token, user: { id: user._id, name: user.name, phone: user.phone, email: user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * FORGOT PASSWORD - SEND EMAIL OTP
 * POST /forgot-password/otp
 * body: { email }    (we support email-based OTP)
 */
router.post('/forgot-password/otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !validator.isEmail(email)) return res.status(400).json({ error: 'Valid email required' });
    const otp = generateNumericOTP(6); // e.g., 6-digit
    const otpHash = hashString(otp);
    const expiresAt = new Date(Date.now() + 10*60*1000); // 10 minutes

    // store hashed otp
    await Otp.create({ identifier: email, otpHash, type: 'PASSWORD_RESET_OTP', expiresAt });

    // send via SendGrid
    await sendOTPEmail(email, otp, { from: process.env.EMAIL_FROM });

    res.json({ message: 'OTP sent to email (check inbox/SPAM)' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * VERIFY OTP
 * POST /forgot-password/verify-otp
 * body: { email, otp }
 */
router.post('/forgot-password/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'email and otp required' });
    const otpHash = hashString(otp);
    const rec = await Otp.findOne({ identifier: email, otpHash, type: 'PASSWORD_RESET_OTP', used: false });
    if (!rec) return res.status(400).json({ error: 'Invalid or expired OTP' });
    if (rec.expiresAt < new Date()) return res.status(400).json({ error: 'OTP expired' });

    // mark used
    rec.used = true;
    await rec.save();

    // create short-lived reset token for client to call /reset-password
    const resetToken = generateTokenHex(20); // raw token
    const resetTokenHash = hashString(resetToken);
    const tokenExpiresAt = new Date(Date.now() + 60*60*1000); // 1 hour

    await Otp.create({ identifier: email, tokenHash: resetTokenHash, type: 'PASSWORD_RESET_LINK', expiresAt: tokenExpiresAt });

    res.json({ message: 'OTP verified', resetToken }); // send raw resetToken to client to call reset endpoint
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * FORGOT PASSWORD - SEND RESET LINK
 * POST /forgot-password/link
 * body: { email }
 */
router.post('/forgot-password/link', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !validator.isEmail(email)) return res.status(400).json({ error: 'Valid email required' });

    // create reset token and save its hash
    const rawToken = generateTokenHex(32);
    const tokenHash = hashString(rawToken);
    const expiresAt = new Date(Date.now() + 60*60*1000); // 1 hour
    await Otp.create({ identifier: email, tokenHash, type: 'PASSWORD_RESET_LINK', expiresAt });

    // Send email with link to front-end reset page
    const frontendResetUrl = process.env.FRONTEND_RESET_URL; // e.g., https://your-front.netlify.app/reset-password
    await sendResetLinkEmail(email, rawToken, frontendResetUrl, { from: process.env.EMAIL_FROM });

    res.json({ message: 'Reset link sent to email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * RESET PASSWORD (by token)
 * POST /reset-password
 * body: { email, token, newPassword }
 */
router.post('/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    if (!email || !token || !newPassword) return res.status(400).json({ error: 'email, token and newPassword required' });
    const tokenHash = hashString(token);

    const rec = await Otp.findOne({ identifier: email, tokenHash, type: 'PASSWORD_RESET_LINK', used: false });
    if (!rec) return res.status(400).json({ error: 'Invalid or expired token' });
    if (rec.expiresAt < new Date()) return res.status(400).json({ error: 'Token expired' });

    // find user
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // update password
    const newHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    user.passwordHash = newHash;
    await user.save();

    rec.used = true;
    await rec.save();

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * CHANGE PASSWORD (logged-in)
 * POST /change-password
 * header Authorization: Bearer <token>
 * body: { oldPassword, newPassword }
 */
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Missing auth' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

router.post('/change-password', authMiddleware, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const ok = await bcrypt.compare(oldPassword, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Old password incorrect' });
    user.passwordHash = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await user.save();
    res.json({ message: 'Password changed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'server error' });
  }
});

module.exports = router;
