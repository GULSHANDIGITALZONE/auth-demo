
const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
  identifier: { type: String, required: true }, // email or phone (we use email for email OTP)
  otpHash: { type: String }, // hashed OTP (if using numeric OTP)
  tokenHash: { type: String }, // hashed reset token (if using link)
  type: { type: String, enum: ['PASSWORD_RESET_OTP', 'PASSWORD_RESET_LINK'], required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  used: { type: Boolean, default: false }
});
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index
module.exports = mongoose.model('Otp', otpSchema);
