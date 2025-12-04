# auth-demo

This repository contains a ready-to-use authentication demo:
- Backend: Node/Express with MongoDB Atlas, SendGrid email (OTP & reset link), JWT auth
- Frontend: single static HTML (Netlify-ready) with Signup, Login, Forgot password (OTP / Link), Reset, Change password

## Quick start (local)
1. Copy `.env.example` to `.env` and fill values (MongoDB URI, SendGrid key, EMAIL_FROM, JWT_SECRET).
2. Install deps:
   ```
   npm install
   ```
3. Start:
   ```
   npm run dev
   ```
4. Open `index.html` (frontend) or host it with a static server and set `API_BASE` in the HTML to your backend URL.

## Deployment
- Backend: Deploy to Render / Railway / Heroku (set env vars).
- Frontend: Deploy `index.html` to Netlify (drag & drop) and update `API_BASE` in the HTML.

