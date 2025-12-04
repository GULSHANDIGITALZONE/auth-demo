const crypto = require('crypto');

function generateNumericOTP(length = 6) {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < length; i++) otp += digits[Math.floor(Math.random() * digits.length)];
  return otp;
}

function generateTokenHex(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex'); // secure random token
}

module.exports = { generateNumericOTP, generateTokenHex };

