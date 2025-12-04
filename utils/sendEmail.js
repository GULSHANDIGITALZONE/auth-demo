
const sgMail = require('@sendgrid/mail');

function initSendGrid(apiKey) {
  sgMail.setApiKey(apiKey);
}

async function sendOTPEmail(to, otp, options = {}) {
  const { from, subject = 'Your OTP code' } = options;
  const text = `Your OTP code is ${otp}. It will expire in 10 minutes.`;
  const html = `<p>Your OTP code is <strong>${otp}</strong>. It will expire in 10 minutes.</p>`;
  await sgMail.send({ to, from, subject, text, html });
}

async function sendResetLinkEmail(to, token, frontendResetUrl, options = {}) {
  const { from, subject = 'Password Reset Link' } = options;
  const link = `${frontendResetUrl}?token=${token}&email=${encodeURIComponent(to)}`;
  const text = `Reset your password using this link: ${link} (expires in 1 hour)`;
  const html = `<p>Click the link below to reset your password (expires in 1 hour):</p>
                <p><a href="${link}">${link}</a></p>`;
  await sgMail.send({ to, from, subject, text, html });
}

module.exports = { initSendGrid, sendOTPEmail, sendResetLinkEmail };
