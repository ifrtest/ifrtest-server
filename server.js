// ─── IFRTEST.ca — Stripe Payment Backend ─────────────────────────────────────
// Handles creating Stripe Checkout sessions and verifying payments.
// Run with: node server.js
// ─────────────────────────────────────────────────────────────────────────────

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const stripe     = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { Resend } = require('resend');
const Anthropic  = require('@anthropic-ai/sdk');
const { Pool }   = require('pg');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const crypto     = require('crypto');

const resend    = new Resend(process.env.RESEND_API_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const JWT_SECRET  = process.env.JWT_SECRET || 'ifrtest-jwt-secret-2024';
const JWT_EXPIRES = '30d';

function signToken(email) {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired token' });
  req.userEmail = payload.email;
  next();
}

// ─── Database ─────────────────────────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

async function dbSaveStudent({ email, sessionId, customerId, plan }) {
  try {
    await db.query(
      `INSERT INTO students (email, stripe_session_id, stripe_customer_id, plan, access_granted)
       VALUES ($1, $2, $3, $4, true)
       ON CONFLICT (stripe_session_id) DO UPDATE
       SET email = $1, stripe_customer_id = $3, plan = $4, updated_at = NOW()`,
      [email, sessionId, customerId || null, plan]
    );
  } catch (err) {
    console.error('[db] saveStudent failed:', err.message);
  }
}

async function dbGetStudent(email) {
  try {
    const { rows } = await db.query(
      `SELECT * FROM students WHERE email = $1 ORDER BY created_at DESC LIMIT 1`,
      [email]
    );
    return rows[0] || null;
  } catch (err) {
    console.error('[db] getStudent failed:', err.message);
    return null;
  }
}

async function dbSetAccess(email, granted) {
  try {
    await db.query(
      `UPDATE students SET access_granted = $1, updated_at = NOW() WHERE email = $2`,
      [granted, email]
    );
  } catch (err) {
    console.error('[db] setAccess failed:', err.message);
  }
}

async function dbSaveQuizSession({ email, score, correctCount, totalQuestions, passed, mode }) {
  try {
    await db.query(
      `INSERT INTO quiz_sessions (student_email, score, correct_count, total_questions, passed, mode)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [email, score, correctCount, totalQuestions, passed, mode || 'practice']
    );
  } catch (err) {
    console.error('[db] saveQuizSession failed:', err.message);
  }
}

const app = express();

// ─── CORS ─────────────────────────────────────────────────────────────────────
// Allow requests from your frontend. In development this is typically
// http://localhost:8080 (or wherever you serve the static files).
// In production it will be https://ifrtest.ca
const FRONTEND_URL = (process.env.FRONTEND_URL || '').trim().replace(/\/$/, '');

// Build allowed origins: include FRONTEND_URL plus www/non-www variant automatically
const allowedOrigins = (() => {
  const base = FRONTEND_URL.split(',').map(s => s.trim()).filter(Boolean);
  const extras = [];
  base.forEach(url => {
    if (url.includes('://www.')) {
      extras.push(url.replace('://www.', '://'));
    } else if (url.startsWith('https://') || url.startsWith('http://')) {
      const proto = url.split('://')[0];
      const host  = url.split('://')[1];
      extras.push(`${proto}://www.${host}`);
    }
  });
  return [...new Set([...base, ...extras, 'http://localhost:8080', 'http://localhost:3001'])];
})();

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (e.g. curl, Postman) or matching origins
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS: origin ${origin} not allowed`));
    }
  }
}));

// ─── Body parsing ─────────────────────────────────────────────────────────────
// The /webhook route needs the raw request body (not JSON) so Stripe can verify
// the signature. All other routes use JSON.
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook') {
    next(); // raw body handled on the route itself
  } else {
    express.json()(req, res, next);
  }
});

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'ifrtest-stripe-server' });
});

// ─── Free question tracking (fingerprint-based) ───────────────────────────────
// Tracks free question usage server-side so incognito users can't reset by
// clearing localStorage. Fingerprint is generated client-side from browser
// characteristics (canvas, screen, UA) — consistent across incognito sessions.
const freeUsageMap = new Map(); // fp -> { count, lastSeen }

// Clean up entries older than 30 days every hour
setInterval(() => {
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
  for (const [key, val] of freeUsageMap) {
    if (val.lastSeen < cutoff) freeUsageMap.delete(key);
  }
}, 60 * 60 * 1000);

// ─── POST /auth/set-password ──────────────────────────────────────────────────
// Called after payment or by existing users to create/update their password.
// Body: { sessionId, email, password }
app.post('/auth/set-password', async (req, res) => {
  const { sessionId, email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  try {
    // Verify the student exists and has access
    const { rows } = await db.query(
      `SELECT * FROM students WHERE email = $1 AND access_granted = true ORDER BY created_at DESC LIMIT 1`,
      [email.toLowerCase()]
    );
    // Also allow if sessionId matches (fresh payment not yet in DB)
    let student = rows[0];
    if (!student && sessionId) {
      const { rows: r2 } = await db.query(
        `SELECT * FROM students WHERE stripe_session_id = $1 LIMIT 1`,
        [sessionId]
      );
      student = r2[0];
    }
    if (!student) return res.status(403).json({ error: 'No active subscription found for this email.' });

    const hash = await bcrypt.hash(password, 10);
    await db.query(
      `UPDATE students SET password_hash = $1, updated_at = NOW() WHERE email = $2`,
      [hash, email.toLowerCase()]
    );
    const token = signToken(email.toLowerCase());
    res.json({ ok: true, token, email: email.toLowerCase(), plan: student.plan });
  } catch (err) {
    console.error('[auth/set-password]', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /auth/login ─────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

  try {
    const { rows } = await db.query(
      `SELECT * FROM students WHERE email = $1 ORDER BY created_at DESC LIMIT 1`,
      [email.toLowerCase()]
    );
    const student = rows[0];
    if (!student || !student.password_hash) {
      return res.status(401).json({ error: 'No account found. Please set your password first.', needsPassword: true });
    }
    const ok = await bcrypt.compare(password, student.password_hash);
    if (!ok) return res.status(401).json({ error: 'Incorrect email or password.' });
    if (!student.access_granted) return res.status(403).json({ error: 'Your access has been revoked. Please contact support.' });

    const token = signToken(email.toLowerCase());
    res.json({ ok: true, token, email: email.toLowerCase(), plan: student.plan });
  } catch (err) {
    console.error('[auth/login]', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── GET /auth/me ─────────────────────────────────────────────────────────────
app.get('/auth/me', requireAuth, async (req, res) => {
  try {
    const { rows } = await db.query(
      `SELECT email, plan, access_granted FROM students WHERE email = $1 LIMIT 1`,
      [req.userEmail]
    );
    const student = rows[0];
    if (!student || !student.access_granted) return res.status(403).json({ error: 'Access revoked.' });
    res.json({ email: student.email, plan: student.plan });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// ─── POST /auth/forgot-password ───────────────────────────────────────────────
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });

  try {
    const { rows } = await db.query(
      `SELECT * FROM students WHERE email = $1 AND access_granted = true LIMIT 1`,
      [email.toLowerCase()]
    );
    if (rows[0]) {
      const token = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 1000 * 60 * 60); // 1 hour
      await db.query(
        `INSERT INTO password_reset_tokens (email, token, expires_at) VALUES ($1, $2, $3)`,
        [email.toLowerCase(), token, expires]
      );
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password.html?token=${token}`;
      await resend.emails.send({
        from: 'IFRTEST.ca <noreply@ifrtest.ca>',
        to: email,
        subject: 'Reset your IFRTEST.ca password ✈️',
        html: `
          <div style="background:#05080f;color:#e8edf5;font-family:Arial,sans-serif;padding:40px;max-width:600px;margin:0 auto;border-radius:8px;">
            <h1 style="color:#00d4a0;font-size:24px;">Reset your password</h1>
            <p style="color:rgba(200,210,230,0.75);line-height:1.7;">Click the button below to set a new password. This link expires in 1 hour.</p>
            <div style="text-align:center;margin:32px 0;">
              <a href="${resetUrl}" style="background:#00d4a0;color:#05080f;text-decoration:none;padding:14px 32px;border-radius:6px;font-weight:bold;font-size:16px;">Reset Password →</a>
            </div>
            <p style="color:rgba(200,210,230,0.4);font-size:13px;">If you didn't request this, ignore this email.</p>
          </div>`,
      });
    }
    res.json({ ok: true }); // Always return ok to prevent email enumeration
  } catch (err) {
    console.error('[auth/forgot-password]', err.message);
    res.json({ ok: true });
  }
});

// ─── POST /auth/reset-password ────────────────────────────────────────────────
app.post('/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password required.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  try {
    const { rows } = await db.query(
      `SELECT * FROM password_reset_tokens WHERE token = $1 AND used = false AND expires_at > NOW()`,
      [token]
    );
    const record = rows[0];
    if (!record) return res.status(400).json({ error: 'Invalid or expired reset link.' });

    const hash = await bcrypt.hash(password, 10);
    await db.query(`UPDATE students SET password_hash = $1, updated_at = NOW() WHERE email = $2`, [hash, record.email]);
    await db.query(`UPDATE password_reset_tokens SET used = true WHERE id = $1`, [record.id]);

    const jwtToken = signToken(record.email);
    res.json({ ok: true, token: jwtToken, email: record.email });
  } catch (err) {
    console.error('[auth/reset-password]', err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});

app.get('/free-status', (req, res) => {
  const { fp } = req.query;
  if (!fp || typeof fp !== 'string' || fp.length > 32) return res.json({ count: 0 });
  const entry = freeUsageMap.get(fp);
  res.json({ count: entry ? entry.count : 0 });
});

app.post('/track-free', (req, res) => {
  const { fp } = req.body;
  if (!fp || typeof fp !== 'string' || fp.length > 32) return res.json({ ok: true });
  const entry = freeUsageMap.get(fp) || { count: 0, lastSeen: Date.now() };
  entry.count = Math.min(entry.count + 1, 20);
  entry.lastSeen = Date.now();
  freeUsageMap.set(fp, entry);
  res.json({ count: entry.count });
});

// ─── POST /create-checkout-session ────────────────────────────────────────────
// Called by the frontend when a user clicks "Get Pro Access".
// Body: { plan: 'monthly' | 'lifetime' }
// Returns: { url: 'https://checkout.stripe.com/...' }
app.post('/create-checkout-session', async (req, res) => {
  const { plan } = req.body;

  if (plan !== 'monthly' && plan !== 'lifetime') {
    return res.status(400).json({ error: 'Invalid plan. Must be "monthly" or "lifetime".' });
  }

  const isMonthly = plan === 'monthly';

  try {
    const session = await stripe.checkout.sessions.create({
      mode: isMonthly ? 'subscription' : 'payment',
      line_items: [
        {
          price: isMonthly
            ? process.env.STRIPE_MONTHLY_PRICE_ID
            : process.env.STRIPE_LIFETIME_PRICE_ID,
          quantity: 1,
        },
      ],
      // After payment, Stripe appends ?session_id={CHECKOUT_SESSION_ID} automatically
      success_url: `${FRONTEND_URL}/payment_success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${FRONTEND_URL}/index.html#pricing`,
      // Let Stripe collect the billing address for Canadian tax compliance
      billing_address_collection: 'auto',
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('[create-checkout-session]', err.message);
    res.status(500).json({ error: 'Could not create checkout session.' });
  }
});

// ─── GET /verify-session ──────────────────────────────────────────────────────
// Called by payment_success.html to confirm a payment actually went through.
// Query param: ?session_id=cs_xxx
// Returns: { success: true, plan: 'monthly' | 'lifetime' }
//       or { success: false }
app.get('/verify-session', async (req, res) => {
  const { session_id } = req.query;

  if (!session_id || !session_id.startsWith('cs_')) {
    return res.status(400).json({ error: 'Missing or invalid session_id.' });
  }

  try {
    const session = await stripe.checkout.sessions.retrieve(session_id, {
      expand: ['subscription'],
    });

    let success = false;
    let plan    = 'lifetime';

    if (session.mode === 'payment') {
      // One-time lifetime purchase — valid forever as long as payment was made
      success = session.payment_status === 'paid';
      plan    = 'lifetime';
    } else if (session.mode === 'subscription') {
      // Monthly subscription — check the subscription is still active
      plan = 'monthly';
      const sub = session.subscription;
      if (sub && typeof sub === 'object') {
        // active / trialing / past_due all get access (past_due = payment retry in progress)
        success = ['active', 'trialing', 'past_due'].includes(sub.status);
        console.log('[verify-session] subscription status:', sub.status, '→ access:', success);
      } else {
        // Subscription object missing — fall back to payment_status check
        success = session.payment_status === 'paid';
      }
    }

    res.json({ success, plan });
  } catch (err) {
    console.error('[verify-session]', err.message);
    res.status(500).json({ error: 'Could not verify session.' });
  }
});

// ─── POST /ai-explain ─────────────────────────────────────────────────────────
// Called when a Pro user taps "Ask AI Instructor" after answering a question.
// Body: { question, answers, correct, selected, explanation, category }
// Returns: { response: '...' }
app.post('/ai-explain', async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'AI Instructor is not configured.' });
  }

  const { question, answers, correct, selected, explanation, category } = req.body;

  if (!question || !answers || correct === undefined) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  const letters  = ['A', 'B', 'C', 'D'];
  const answerList = answers.map((a, i) => `${letters[i]}) ${a}`).join('\n');
  const correctAnswer  = `${answers[correct]}`;
  const selectedAnswer = selected !== undefined && selected !== null
    ? `${answers[selected]}`
    : null;
  const gotItRight = Number(selected) === Number(correct);

  const prompt = gotItRight
    ? `You are an experienced Canadian IFR flight instructor. A student just answered a practice question correctly.

Question: ${question}

Answer choices:
${answerList}

Correct answer: ${correctAnswer}
${explanation ? `Reference note: ${explanation}` : ''}

Briefly reinforce why ${correctAnswer} is correct. Keep it under 120 words. Plain language, no bullet points, no headers. Reference the specific Canadian regulation, AIM section, or principle where relevant.`

    : `You are an experienced Canadian IFR flight instructor. A student just answered a practice question INCORRECTLY.

Question: ${question}

Answer choices:
${answerList}

The student chose: ${selectedAnswer || 'unknown'} — this is WRONG.
The correct answer is: ${correctAnswer}
${explanation ? `Reference note: ${explanation}` : ''}

IMPORTANT: Do NOT say the student answered correctly. Do NOT use phrases like "you got it right", "correct", "well done", or any praise. The student got this wrong.

Explain clearly why ${correctAnswer} is the correct answer${selectedAnswer ? `, and briefly explain why "${selectedAnswer}" is incorrect` : ''}. Keep it under 150 words. Plain language, no bullet points, no headers. Reference the specific Canadian regulation, AIM section, or principle where relevant.`;

  try {
    const message = await anthropic.messages.create({
      model:      'claude-haiku-4-5-20251001',
      max_tokens: 300,
      messages:   [{ role: 'user', content: prompt }],
    });

    res.json({ response: message.content[0].text });
  } catch (err) {
    console.error('[ai-explain]', err.message);
    res.status(500).json({ error: 'AI Instructor is unavailable right now.' });
  }
});

// ─── POST /send-restore-link ──────────────────────────────────────────────────
// Called when a returning customer wants to restore access on a new device.
// Body: { email: 'user@example.com' }
// Always returns { sent: true } to avoid leaking whether an email exists.
app.post('/send-restore-link', async (req, res) => {
  const { email } = req.body;

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required.' });
  }

  try {
    // Look up Stripe customers by email
    const customers = await stripe.customers.list({ email: email.toLowerCase().trim(), limit: 5 });

    let sessionId = null;
    for (const customer of customers.data) {
      const sessions = await stripe.checkout.sessions.list({ customer: customer.id, limit: 20 });
      const paid = sessions.data.find(s => s.payment_status === 'paid');
      if (paid) {
        sessionId = paid.id;
        break;
      }
    }

    if (sessionId) {
      const accessUrl = `${FRONTEND_URL}/payment_success.html?session_id=${sessionId}`;
      await resend.emails.send({
        from: 'IFRTEST.ca <noreply@ifrtest.ca>',
        to: email,
        subject: 'Your IFRTEST Pro access link ✈️',
        html: `
          <div style="background:#05080f;color:#e8edf5;font-family:Arial,sans-serif;padding:40px;max-width:600px;margin:0 auto;border-radius:8px;">
            <div style="text-align:center;margin-bottom:32px;">
              <h1 style="color:#00d4a0;font-size:28px;margin:0;">IFRTEST.ca</h1>
              <p style="color:rgba(200,210,230,0.5);margin:4px 0 0;">Canadian IFR Exam Prep</p>
            </div>
            <h2 style="color:#e8edf5;font-size:20px;">Here's your access link</h2>
            <p style="color:rgba(200,210,230,0.75);line-height:1.7;">
              Click the button below to restore your Pro access on this device. The link will verify your purchase and unlock full access automatically.
            </p>
            <div style="text-align:center;margin:32px 0;">
              <a href="${accessUrl}" style="background:#00d4a0;color:#05080f;text-decoration:none;padding:14px 32px;border-radius:6px;font-weight:bold;font-size:16px;">Restore My Access →</a>
            </div>
            <p style="color:rgba(200,210,230,0.4);font-size:13px;line-height:1.6;">
              If you didn't request this, you can ignore this email.<br>
              Questions? Contact us at <a href="mailto:ifrtest.ca@gmail.com" style="color:#00d4a0;">ifrtest.ca@gmail.com</a>
            </p>
            <hr style="border:none;border-top:1px solid rgba(0,212,160,0.1);margin:24px 0;">
            <p style="color:rgba(200,210,230,0.25);font-size:11px;text-align:center;">IFRTEST.ca · Canadian IFR Written Exam Prep</p>
          </div>
        `,
      });
      console.log('[send-restore-link] Access email sent to', email);
    } else {
      console.log('[send-restore-link] No paid session found for', email);
    }
  } catch (err) {
    console.error('[send-restore-link]', err.message);
  }

  // Always respond with success to prevent email enumeration
  res.json({ sent: true });
});

// ─── POST /verify-email ───────────────────────────────────────────────────────
// Instantly verifies if an email has an active Pro subscription in Stripe.
// Returns { success: true, plan, sessionId } or { success: false }
app.post('/verify-email', async (req, res) => {
  const { email } = req.body;
  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required.' });
  }

  try {
    const customers = await stripe.customers.list({ email: email.toLowerCase().trim(), limit: 5 });

    for (const customer of customers.data) {
      const sessions = await stripe.checkout.sessions.list({
        customer: customer.id,
        limit: 20,
        expand: ['data.subscription'],
      });

      for (const session of sessions.data) {
        // Lifetime purchase
        if (session.mode === 'payment' && session.payment_status === 'paid') {
          console.log('[verify-email] lifetime access granted for', email);
          return res.json({ success: true, plan: 'lifetime', sessionId: session.id });
        }
        // Monthly subscription — check it's still active
        if (session.mode === 'subscription' && session.subscription) {
          const sub = session.subscription;
          if (['active', 'trialing', 'past_due'].includes(sub.status)) {
            console.log('[verify-email] subscription access granted for', email, '- status:', sub.status);
            return res.json({ success: true, plan: 'monthly', sessionId: session.id });
          }
        }
      }
    }

    console.log('[verify-email] no active subscription found for', email);
    return res.json({ success: false });
  } catch (err) {
    console.error('[verify-email]', err.message);
    return res.status(500).json({ success: false });
  }
});

// ─── Email helpers ────────────────────────────────────────────────────────────
async function sendWelcomeEmail(to, plan, isNewUser = true) {
  if (!process.env.RESEND_API_KEY) {
    console.error('[email] RESEND_API_KEY is not set — skipping welcome email');
    return;
  }

  const isLifetime = plan === 'lifetime';
  const ctaUrl  = isNewUser
    ? `https://ifrtest.ca/set-password.html?email=${encodeURIComponent(to)}`
    : 'https://ifrtest.ca/ifrtest_quiz.html';
  const ctaText = isNewUser ? 'Set Your Password & Start Studying →' : 'Go to Your Study Dashboard →';
  const cancelNote = isLifetime
    ? 'This is a one-time purchase — you will never be charged again.'
    : 'Your subscription renews monthly. To cancel, just reply to this email and we\'ll take care of it within 24 hours.';

  await resend.emails.send({
    from: 'IFRTEST.ca <noreply@ifrtest.ca>',
    reply_to: 'ifrtest.ca@gmail.com',
    to,
    subject: `You're in — IFRTEST Pro is ready`,
    html: `
      <div style="background:#05080f;color:#e8edf5;font-family:Arial,sans-serif;max-width:580px;margin:0 auto;">

        <!-- Logo bar -->
        <div style="background:#05080f;padding:18px 40px;border-radius:8px 8px 0 0;border-bottom:1px solid rgba(0,212,160,0.15);">
          <img src="https://ifrtest.ca/images/ifr_logo.png" alt="IFRTEST.ca" style="height:36px;display:block;">
        </div>

        <!-- Header image -->
        <img src="https://ifrtest.ca/images/email-hero.jpg" alt="Cockpit" style="width:100%;display:block;max-height:220px;object-fit:cover;object-position:center 40%;">

        <div style="padding:36px 40px;">

          <p style="margin:0 0 24px;color:rgba(200,210,230,0.5);font-size:13px;">IFRTEST.ca — Canadian IFR Exam Prep</p>

          <h1 style="color:#e8edf5;font-size:22px;margin:0 0 16px;font-weight:700;">Your Pro access is active.</h1>

          <p style="color:rgba(200,210,230,0.72);line-height:1.75;font-size:15px;margin:0 0 24px;">
            Payment confirmed. You now have full access to 513 INRAT practice questions across all 13 exam categories, the timed exam simulator, AI Instructor, flashcards, and your readiness dashboard.
          </p>

          ${isNewUser ? `
          <div style="background:rgba(0,212,160,0.08);border-left:3px solid #00d4a0;padding:14px 18px;margin:0 0 28px;border-radius:0 6px 6px 0;">
            <p style="margin:0;color:#e8edf5;font-size:14px;font-weight:600;">One quick step first</p>
            <p style="margin:6px 0 0;color:rgba(200,210,230,0.6);font-size:13px;line-height:1.6;">Set a password so you can log in from any device. Takes 30 seconds.</p>
          </div>` : ''}

          <div style="margin:0 0 36px;">
            <a href="${ctaUrl}" style="background:#00d4a0;color:#05080f;text-decoration:none;padding:14px 28px;border-radius:6px;font-weight:700;font-size:15px;display:inline-block;">${ctaText}</a>
          </div>

          <!-- Install instructions -->
          <div style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.07);border-radius:8px;padding:22px 24px;margin-bottom:28px;">
            <p style="margin:0 0 6px;font-size:15px;font-weight:700;color:#e8edf5;">Save it to your phone — study anywhere</p>
            <p style="margin:0 0 18px;font-size:13px;color:rgba(200,210,230,0.5);line-height:1.6;">Add IFRTEST.ca to your home screen and it opens like an app — no app store required.</p>
            <table style="width:100%;border-collapse:collapse;">
              <tr>
                <td style="vertical-align:top;padding-right:16px;width:33%;">
                  <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#00d4a0;text-transform:uppercase;letter-spacing:0.05em;">iPhone / iPad</p>
                  <ol style="margin:0;padding-left:16px;font-size:12px;color:rgba(200,210,230,0.6);line-height:1.9;">
                    <li>Open in <strong style="color:#e8edf5;">Safari</strong></li>
                    <li>Tap the <strong style="color:#e8edf5;">Share</strong> button</li>
                    <li>Tap <strong style="color:#e8edf5;">"Add to Home Screen"</strong></li>
                    <li>Tap <strong style="color:#e8edf5;">Add</strong></li>
                  </ol>
                </td>
                <td style="vertical-align:top;padding-right:16px;width:33%;">
                  <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#00d4a0;text-transform:uppercase;letter-spacing:0.05em;">Android</p>
                  <ol style="margin:0;padding-left:16px;font-size:12px;color:rgba(200,210,230,0.6);line-height:1.9;">
                    <li>Open in <strong style="color:#e8edf5;">Chrome</strong></li>
                    <li>Tap the <strong style="color:#e8edf5;">⋮</strong> menu</li>
                    <li>Tap <strong style="color:#e8edf5;">"Add to Home Screen"</strong></li>
                    <li>Tap <strong style="color:#e8edf5;">Add</strong></li>
                  </ol>
                </td>
                <td style="vertical-align:top;width:33%;">
                  <p style="margin:0 0 8px;font-size:12px;font-weight:700;color:#00d4a0;text-transform:uppercase;letter-spacing:0.05em;">Desktop</p>
                  <ol style="margin:0;padding-left:16px;font-size:12px;color:rgba(200,210,230,0.6);line-height:1.9;">
                    <li>Open in <strong style="color:#e8edf5;">Chrome or Edge</strong></li>
                    <li>Click the <strong style="color:#e8edf5;">install icon</strong> in the address bar</li>
                    <li>Click <strong style="color:#e8edf5;">"Install"</strong></li>
                  </ol>
                </td>
              </tr>
            </table>
          </div>

          <div style="border-top:1px solid rgba(255,255,255,0.06);padding-top:20px;">
            <p style="color:rgba(200,210,230,0.35);font-size:12px;line-height:1.8;margin:0;">
              ${cancelNote}<br>
              Questions? Just reply to this email — we read every one.<br><br>
              Good luck on the exam.
            </p>
          </div>

        </div>
      </div>
    `,
  });
  console.log('[email] Welcome email sent to', to);
}

// ─── GET /admin/students ──────────────────────────────────────────────────────
app.get('/admin/students', async (req, res) => {
  const ADMIN_SECRET = process.env.ADMIN_SECRET || 'ifrtest-admin-2024';
  if (req.query.secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  try {
    const { rows } = await db.query(`
      SELECT s.*,
        COUNT(q.id)::int AS quiz_count,
        ROUND(AVG(q.score)::numeric, 1) AS avg_score,
        MAX(q.created_at) AS last_quiz
      FROM students s
      LEFT JOIN quiz_sessions q ON q.student_email = s.email
      GROUP BY s.id
      ORDER BY s.created_at DESC
    `);
    res.json({ students: rows, total: rows.length });
  } catch (err) {
    console.error('[admin/students]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── GET /admin/students/:email/quizzes ───────────────────────────────────────
app.get('/admin/students/:email/quizzes', async (req, res) => {
  const ADMIN_SECRET = process.env.ADMIN_SECRET || 'ifrtest-admin-2024';
  if (req.query.secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  try {
    const { rows } = await db.query(
      `SELECT * FROM quiz_sessions WHERE student_email = $1 ORDER BY created_at DESC`,
      [decodeURIComponent(req.params.email)]
    );
    res.json({ quizzes: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /admin/set-access ───────────────────────────────────────────────────
app.post('/admin/set-access', async (req, res) => {
  const ADMIN_SECRET = process.env.ADMIN_SECRET || 'ifrtest-admin-2024';
  const { secret, email, granted, grant } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  const grantAccess = granted !== undefined ? granted : grant;
  try {
    const lc = email.toLowerCase();
    if (grantAccess) {
      const { rows } = await db.query(`SELECT id FROM students WHERE email = $1 LIMIT 1`, [lc]);
      if (rows.length > 0) {
        await db.query(`UPDATE students SET access_granted = true, updated_at = NOW() WHERE email = $1`, [lc]);
      } else {
        await db.query(`INSERT INTO students (email, plan, access_granted) VALUES ($1, 'pro', true)`, [lc]);
      }
    } else {
      await dbSetAccess(email, false);
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /quiz-result ────────────────────────────────────────────────────────
app.post('/quiz-result', async (req, res) => {
  const { sessionId, score, correctCount, totalQuestions, passed, mode } = req.body;
  if (score === undefined || !totalQuestions) return res.json({ ok: true });
  try {
    // Try JWT auth first, fall back to sessionId lookup
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    const payload = token ? verifyToken(token) : null;
    let email = payload?.email;

    if (!email && sessionId) {
      const { rows } = await db.query(
        `SELECT email FROM students WHERE stripe_session_id = $1 LIMIT 1`,
        [sessionId]
      );
      email = rows[0]?.email;
    }
    if (email) {
      await dbSaveQuizSession({ email, score, correctCount, totalQuestions, passed, mode });
    }
  } catch (err) {
    console.error('[quiz-result]', err.message);
  }
  res.json({ ok: true });
});

// ─── POST /admin/backfill ─────────────────────────────────────────────────────
// One-time: pulls all paid Stripe customers into the database.
app.post('/admin/backfill', async (req, res) => {
  const ADMIN_SECRET = process.env.ADMIN_SECRET || 'ifrtest-admin-2024';
  if (req.body.secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
  try {
    const customers = await stripe.customers.list({ limit: 100 });
    let imported = 0;
    for (const customer of customers.data) {
      const sessions = await stripe.checkout.sessions.list({
        customer: customer.id, limit: 20, expand: ['data.subscription'],
      });
      for (const session of sessions.data) {
        const email = customer.email;
        if (!email) continue;
        let plan = null;
        if (session.mode === 'payment' && session.payment_status === 'paid') plan = 'lifetime';
        else if (session.mode === 'subscription' && session.subscription) {
          const sub = session.subscription;
          if (['active', 'trialing', 'past_due', 'canceled'].includes(sub.status)) plan = 'monthly';
        }
        if (plan) {
          await dbSaveStudent({ email, sessionId: session.id, customerId: customer.id, plan });
          imported++;
          break;
        }
      }
    }
    res.json({ ok: true, imported });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── POST /admin/resend-welcome ───────────────────────────────────────────────
// Manual resend for cases where webhook email failed (e.g. DNS not yet verified).
// Body: { secret: '...', email: '...', plan: 'monthly' | 'lifetime' }
app.post('/admin/resend-welcome', async (req, res) => {
  const { secret, email, plan } = req.body;
  const ADMIN_SECRET = process.env.ADMIN_SECRET || 'ifrtest-admin-2024';

  if (secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (!email || !plan) {
    return res.status(400).json({ error: 'email and plan required' });
  }

  try {
    await sendWelcomeEmail(email, plan);
    res.json({ sent: true });
  } catch (err) {
    console.error('[admin/resend-welcome]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── GET /checkout/config ─────────────────────────────────────────────────────
app.get('/checkout/config', (req, res) => {
  res.json({ publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || '' });
});

// ─── POST /checkout/create-intent ────────────────────────────────────────────
// Body: { plan: 'monthly'|'lifetime', email: string }
// Returns: { clientSecret, type, subscriptionId? }
app.post('/checkout/create-intent', async (req, res) => {
  const { plan, email } = req.body;
  if (!plan || !email || !email.includes('@')) {
    return res.status(400).json({ error: 'plan and email required' });
  }
  if (plan !== 'monthly' && plan !== 'lifetime') {
    return res.status(400).json({ error: 'Invalid plan' });
  }
  try {
    const lc = email.toLowerCase().trim();

    // Find or create Stripe customer
    const existing = await stripe.customers.list({ email: lc, limit: 1 });
    let customer = existing.data[0];
    if (!customer) {
      customer = await stripe.customers.create({ email: lc, metadata: { source: 'ifrtest_embedded' } });
    }

    if (plan === 'monthly') {
      // Prevent double billing — check for existing active subscription
      const subs = await stripe.subscriptions.list({ customer: customer.id, status: 'active', limit: 1 });
      if (subs.data.length > 0) {
        return res.status(409).json({ error: 'already_subscribed' });
      }
      const subscription = await stripe.subscriptions.create({
        customer: customer.id,
        items: [{ price: process.env.STRIPE_MONTHLY_PRICE_ID }],
        payment_behavior: 'default_incomplete',
        payment_settings: { save_default_payment_method: 'on_subscription' },
        expand: ['latest_invoice.payment_intent'],
      });
      const pi = subscription.latest_invoice.payment_intent;
      return res.json({ clientSecret: pi.client_secret, subscriptionId: subscription.id, type: 'subscription' });
    }

    // Lifetime one-time payment
    const pi = await stripe.paymentIntents.create({
      amount: 7900,
      currency: 'cad',
      customer: customer.id,
      metadata: { plan: 'lifetime', email: lc },
      automatic_payment_methods: { enabled: true },
    });
    res.json({ clientSecret: pi.client_secret, type: 'payment' });
  } catch (err) {
    console.error('[checkout/create-intent]', err.message);
    res.status(500).json({ error: 'Could not create payment intent.' });
  }
});

// ─── POST /checkout/activate ──────────────────────────────────────────────────
// Called after Stripe confirms payment client-side.
// Body: { email, plan, paymentIntentId?, subscriptionId? }
// Returns: { ok, token, email, isNewUser, plan }
app.post('/checkout/activate', async (req, res) => {
  const { email, plan, paymentIntentId, subscriptionId } = req.body;
  if (!email || !plan) return res.status(400).json({ error: 'email and plan required' });

  try {
    const lc = email.toLowerCase().trim();

    // Verify payment actually went through before granting access
    if (plan === 'lifetime' && paymentIntentId) {
      const pi = await stripe.paymentIntents.retrieve(paymentIntentId);
      if (pi.status !== 'succeeded') return res.status(402).json({ error: 'Payment not confirmed' });
    } else if (plan === 'monthly' && subscriptionId) {
      const sub = await stripe.subscriptions.retrieve(subscriptionId);
      if (!['active', 'trialing', 'past_due'].includes(sub.status)) {
        return res.status(402).json({ error: 'Subscription not active' });
      }
    }

    // Grant DB access
    const { rows } = await db.query(`SELECT id, password_hash FROM students WHERE email = $1 LIMIT 1`, [lc]);
    let isNewUser = true;
    if (rows.length > 0) {
      isNewUser = !rows[0].password_hash;
      await db.query(`UPDATE students SET access_granted = true, plan = $1, updated_at = NOW() WHERE email = $2`, [plan, lc]);
    } else {
      await db.query(`INSERT INTO students (email, plan, access_granted) VALUES ($1, $2, true)`, [lc, plan]);
    }

    const token = signToken(lc);

    // Send welcome email non-blocking
    sendWelcomeEmail(lc, plan, isNewUser).catch(e => console.error('[checkout/activate] email:', e.message));

    res.json({ ok: true, token, email: lc, isNewUser, plan });
  } catch (err) {
    console.error('[checkout/activate]', err.message);
    res.status(500).json({ error: 'Could not activate account.' });
  }
});

// ─── POST /webhook ────────────────────────────────────────────────────────────
// Stripe calls this URL automatically when payment events happen.
// You register this URL in the Stripe Dashboard → Webhooks.
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('[webhook] Signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const customerEmail = session.customer_details?.email;
      const plan = session.mode === 'subscription' ? 'monthly' : 'lifetime';
      console.log('[webhook] Payment complete:', session.id, customerEmail, plan);
      if (customerEmail) {
        dbSaveStudent({
          email: customerEmail,
          sessionId: session.id,
          customerId: session.customer,
          plan,
        }).then(() => console.log('[webhook] Student saved to DB'));
        sendWelcomeEmail(customerEmail, plan)
          .then(() => console.log('[webhook] Welcome email dispatched OK'))
          .catch(err => console.error('[webhook] Welcome email FAILED:', err.message, err.statusCode || ''));
      } else {
        console.warn('[webhook] No customer email in session:', session.id);
      }
      break;
    }

    case 'customer.subscription.deleted':
      console.log('[webhook] Subscription cancelled:', event.data.object.id);
      break;

    case 'invoice.payment_failed':
      console.log('[webhook] Payment failed for subscription:', event.data.object.id);
      break;

    default:
      break;
  }

  res.json({ received: true });
});

// ─── Lead capture: cheat sheet (double opt-in) ────────────────────────────────
function cheatsheetEmail(token) {
  const verifyUrl = `https://ifrtest-server.onrender.com/lead/verify?token=${token}`;
  return `
  <div style="background:#05080f;color:#e8edf5;font-family:Arial,sans-serif;max-width:580px;margin:0 auto;border-radius:8px;overflow:hidden;">
    <div style="background:#05080f;padding:18px 40px;border-bottom:1px solid rgba(0,212,160,0.15);">
      <img src="https://ifrtest.ca/images/ifr_logo.png" alt="IFRTEST.ca" style="height:36px;display:block;">
    </div>
    <img src="https://ifrtest.ca/images/email-hero.jpg" alt="Cockpit" style="width:100%;display:block;max-height:200px;object-fit:cover;object-position:center 40%;">
    <div style="padding:36px 40px;">
      <p style="margin:0 0 20px;color:rgba(200,210,230,0.5);font-size:13px;">IFRTEST.ca — Canadian IFR Exam Prep</p>
      <h1 style="color:#e8edf5;font-size:22px;margin:0 0 16px;font-weight:700;">One quick step — confirm your email</h1>
      <p style="color:rgba(200,210,230,0.72);line-height:1.75;font-size:15px;margin:0 0 28px;">
        Click the button below to confirm your email. Your free Canadian IFR Cheat Sheet will be sent immediately after.
      </p>
      <div style="margin:0 0 28px;">
        <a href="${verifyUrl}" style="background:#00d4a0;color:#05080f;text-decoration:none;padding:14px 28px;border-radius:6px;font-weight:700;font-size:15px;display:inline-block;">Confirm Email & Get Cheat Sheet →</a>
      </div>
      <div style="border-top:1px solid rgba(255,255,255,0.06);padding-top:20px;">
        <p style="color:rgba(200,210,230,0.35);font-size:12px;line-height:1.8;margin:0;">
          If you didn't request this, just ignore this email.<br>
          Questions? Reply to this email — we read every one.
        </p>
      </div>
    </div>
  </div>`;
}

function cheatsheetDeliveryEmail() {
  return `
  <div style="background:#05080f;color:#e8edf5;font-family:Arial,sans-serif;max-width:580px;margin:0 auto;border-radius:8px;overflow:hidden;">
    <div style="background:#05080f;padding:18px 40px;border-bottom:1px solid rgba(0,212,160,0.15);">
      <img src="https://ifrtest.ca/images/ifr_logo.png" alt="IFRTEST.ca" style="height:36px;display:block;">
    </div>
    <img src="https://ifrtest.ca/images/email-hero.jpg" alt="Cockpit" style="width:100%;display:block;max-height:200px;object-fit:cover;object-position:center 40%;">
    <div style="padding:36px 40px;">
      <p style="margin:0 0 20px;color:rgba(200,210,230,0.5);font-size:13px;">IFRTEST.ca — Canadian IFR Exam Prep</p>
      <h1 style="color:#e8edf5;font-size:22px;margin:0 0 16px;font-weight:700;">Your Canadian IFR Cheat Sheet</h1>
      <p style="color:rgba(200,210,230,0.72);line-height:1.75;font-size:15px;margin:0 0 28px;">
        Here's your quick-reference guide for the INRAT — airspace, nav aids, GPS, alternates, fuel, icing, approaches, and more. All values are Canadian-specific (CARS, not FAR).
      </p>
      <div style="margin:0 0 36px;">
        <a href="https://ifrtest.ca/cheat-sheet.html" style="background:#00d4a0;color:#05080f;text-decoration:none;padding:14px 28px;border-radius:6px;font-weight:700;font-size:15px;display:inline-block;">Open Your Cheat Sheet →</a>
      </div>
      <div style="background:rgba(0,212,160,0.08);border-left:3px solid #00d4a0;padding:14px 18px;margin:0 0 28px;border-radius:0 6px 6px 0;">
        <p style="margin:0;color:#e8edf5;font-size:14px;font-weight:600;">Want all 513 INRAT questions?</p>
        <p style="margin:6px 0 0;color:rgba(200,210,230,0.6);font-size:13px;line-height:1.6;">Get Pro access for $14.99/mo — timed simulator, AI Instructor, flashcards, and full explanations on every question.</p>
        <a href="https://ifrtest.ca/#pricing" style="display:inline-block;margin-top:10px;color:#00d4a0;font-size:13px;font-weight:600;text-decoration:none;">See pricing →</a>
      </div>
      <div style="border-top:1px solid rgba(255,255,255,0.06);padding-top:20px;">
        <p style="color:rgba(200,210,230,0.35);font-size:12px;line-height:1.8;margin:0;">
          Questions? Just reply to this email — we read every one.<br>Good luck on the exam.
        </p>
      </div>
    </div>
  </div>`;
}

app.post('/lead/cheatsheet', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required.' });
  const em = email.toLowerCase().trim();
  const token = crypto.randomBytes(24).toString('hex');

  try {
    await db.query(
      `INSERT INTO leads (email, source, verified, verify_token, created_at)
       VALUES ($1, 'cheatsheet', FALSE, $2, NOW())
       ON CONFLICT (email) DO UPDATE SET verify_token = $2, created_at = NOW()`,
      [em, token]
    );
  } catch (e) {
    console.error('Lead save error:', e.code, e.message, e.detail);
    return res.status(500).json({ error: 'Could not save.', code: e.code, detail: e.message || e.detail || String(e) });
  }

  // Send verification email
  try {
    await resend.emails.send({
      from: 'IFRTEST.ca <noreply@ifrtest.ca>',
      to: em,
      reply_to: 'ifrtest.ca@gmail.com',
      subject: 'Confirm your email — IFR Cheat Sheet',
      html: cheatsheetEmail(token)
    });
  } catch (e) {
    console.error('Verify email error:', e.message);
  }

  res.json({ ok: true });
});

// ─── Lead verify: confirms email, sends cheat sheet ───────────────────────────
app.get('/lead/verify', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Invalid link.');

  let email;
  try {
    const { rows } = await db.query(
      `UPDATE leads SET verified = TRUE, verify_token = NULL
       WHERE verify_token = $1 AND verified = FALSE
       RETURNING email`,
      [token]
    );
    if (!rows.length) {
      // Already verified or invalid — redirect to cheat sheet anyway
      return res.redirect(`${FRONTEND_URL}/verify-lead.html?status=already`);
    }
    email = rows[0].email;
  } catch (e) {
    console.error('Lead verify error:', e.message);
    return res.status(500).send('Server error.');
  }

  // Send the actual cheat sheet
  try {
    await resend.emails.send({
      from: 'IFRTEST.ca <noreply@ifrtest.ca>',
      to: email,
      reply_to: 'ifrtest.ca@gmail.com',
      subject: 'Your Canadian IFR Cheat Sheet',
      html: cheatsheetDeliveryEmail()
    });
  } catch (e) {
    console.error('Cheatsheet delivery error:', e.message);
  }

  res.redirect(`${FRONTEND_URL}/verify-lead.html?status=verified`);
});

// ─── Start server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;

async function initDB() {
  try {
    await db.query(`CREATE TABLE IF NOT EXISTS leads (
      email TEXT PRIMARY KEY,
      source TEXT,
      verified BOOLEAN DEFAULT FALSE,
      verify_token TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await db.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE`).catch(() => {});
    await db.query(`ALTER TABLE leads ADD COLUMN IF NOT EXISTS verify_token TEXT`).catch(() => {});
    console.log('✓ leads table ready');
  } catch (e) {
    console.error('initDB error:', e.message);
  }
}

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✓ IFRTEST Stripe server running on port ${PORT}`);
    console.log(`  Allowed origins: ${allowedOrigins.join(', ') || '(none set — check FRONTEND_URL in .env)'}`);
  });
});
