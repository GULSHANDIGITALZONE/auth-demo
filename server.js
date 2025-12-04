require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const { initSendGrid } = require('./utils/sendEmail');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || '*'
}));

// Rate limiting (global)
app.use(rateLimit({
  windowMs: 60*1000,
  max: 100
}));

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=>console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connect error', err));

// Init SendGrid
if (process.env.SENDGRID_API_KEY) initSendGrid(process.env.SENDGRID_API_KEY);
else console.warn('SENDGRID_API_KEY not provided. Email sending disabled.');

// Routes
app.use('/api', authRoutes);

// Health
app.get('/', (req,res)=>res.send('Auth demo running'));

// Start
const port = process.env.PORT || 8080;
app.listen(port, ()=> console.log('Server listening on', port));
