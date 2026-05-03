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

const resend    = new Resend(process.env.RESEND_API_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

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
async function sendWelcomeEmail(to, plan) {
  if (!process.env.RESEND_API_KEY) {
    console.error('[email] RESEND_API_KEY is not set — skipping welcome email');
    return;
  }

  const isLifetime = plan === 'lifetime';
  const planLabel  = isLifetime ? 'Pro Lifetime' : 'Pro Monthly';
  const planDetail = isLifetime
    ? 'You have lifetime access — you will never be charged again.'
    : 'Your subscription renews monthly. You can cancel anytime by emailing ifrtest.ca@gmail.com.';

  await resend.emails.send({
    from: 'IFRTEST.ca <noreply@ifrtest.ca>',
    to,
    subject: `Welcome to IFRTEST Pro — You're all set! ✈️`,
    html: `
      <div style="background:#05080f;color:#e8edf5;font-family:Arial,sans-serif;padding:40px;max-width:600px;margin:0 auto;border-radius:8px;">
        <div style="text-align:center;margin-bottom:32px;">
          <h1 style="color:#00d4a0;font-size:28px;margin:0;">IFRTEST.ca</h1>
          <p style="color:rgba(200,210,230,0.5);margin:4px 0 0;">Canadian IFR Exam Prep</p>
        </div>
        <h2 style="color:#e8edf5;font-size:22px;">Welcome to ${planLabel}! ✈️</h2>
        <p style="color:rgba(200,210,230,0.75);line-height:1.7;">
          Your payment was successful and your Pro access is now active. You have full access to all 382 IFR written exam questions, the timed exam simulator, flashcards, and all study tools.
        </p>
        <div style="background:rgba(0,212,160,0.08);border:1px solid rgba(0,212,160,0.25);border-radius:6px;padding:16px 20px;margin:24px 0;">
          <p style="margin:0;color:#00d4a0;font-weight:bold;">Plan: ${planLabel}</p>
          <p style="margin:6px 0 0;color:rgba(200,210,230,0.6);font-size:14px;">${planDetail}</p>
        </div>
        <div style="text-align:center;margin:32px 0;">
          <a href="https://ifrtest.ca/ifrtest_quiz.html" style="background:#00d4a0;color:#05080f;text-decoration:none;padding:14px 32px;border-radius:6px;font-weight:bold;font-size:16px;">Start Studying →</a>
        </div>
        <p style="color:rgba(200,210,230,0.4);font-size:13px;line-height:1.6;">
          Questions? Reply to this email or contact us at <a href="mailto:ifrtest.ca@gmail.com" style="color:#00d4a0;">ifrtest.ca@gmail.com</a>
        </p>
        <hr style="border:none;border-top:1px solid rgba(0,212,160,0.1);margin:24px 0;">
        <p style="color:rgba(200,210,230,0.25);font-size:11px;text-align:center;">IFRTEST.ca · Canadian IFR Written Exam Prep</p>
      </div>
    `,
  });
  console.log('[email] Welcome email sent to', to);
}

// ─── GET /admin/customers ─────────────────────────────────────────────────────
// Returns all Stripe customers with their subscription/payment status.
// Query param: ?secret=...
app.get('/admin/customers', async (req, res) => {
  const ADMIN_SECRET = process.env.ADMIN_SECRET || 'ifrtest-admin-2024';
  if (req.query.secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const customers = await stripe.customers.list({ limit: 100 });
    const results = [];

    for (const customer of customers.data) {
      const sessions = await stripe.checkout.sessions.list({
        customer: customer.id,
        limit: 10,
        expand: ['data.subscription'],
      });

      let plan = null;
      let status = 'no_purchase';
      let sessionId = null;
      let amount = null;
      let date = null;

      for (const session of sessions.data) {
        if (session.mode === 'payment' && session.payment_status === 'paid') {
          plan = 'lifetime';
          status = 'active';
          sessionId = session.id;
          amount = session.amount_total;
          date = session.created;
          break;
        }
        if (session.mode === 'subscription' && session.subscription) {
          const sub = session.subscription;
          if (['active', 'trialing', 'past_due'].includes(sub.status)) {
            plan = 'monthly';
            status = sub.status;
            sessionId = session.id;
            amount = session.amount_total;
            date = session.created;
            break;
          } else if (sub.status === 'canceled') {
            plan = 'monthly';
            status = 'canceled';
            sessionId = session.id;
            amount = session.amount_total;
            date = session.created;
          }
        }
      }

      if (sessions.data.length > 0) {
        results.push({
          id: customer.id,
          email: customer.email,
          name: customer.name,
          plan,
          status,
          sessionId,
          amount,
          date,
          created: customer.created,
        });
      }
    }

    results.sort((a, b) => b.created - a.created);
    res.json({ customers: results, total: results.length });
  } catch (err) {
    console.error('[admin/customers]', err.message);
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

// ─── Start server ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`✓ IFRTEST Stripe server running on port ${PORT}`);
  console.log(`  Allowed origins: ${allowedOrigins.join(', ') || '(none set — check FRONTEND_URL in .env)'}`);
});
