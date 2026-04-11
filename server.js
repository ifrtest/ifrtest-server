// ─── IFRTEST.ca — Stripe Payment Backend ─────────────────────────────────────
// Handles creating Stripe Checkout sessions and verifying payments.
// Run with: node server.js
// ─────────────────────────────────────────────────────────────────────────────

require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const stripe  = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

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
    const session = await stripe.checkout.sessions.retrieve(session_id);
    const paid = session.payment_status === 'paid';

    res.json({
      success: paid,
      plan: session.mode === 'subscription' ? 'monthly' : 'lifetime',
    });
  } catch (err) {
    console.error('[verify-session]', err.message);
    res.status(500).json({ error: 'Could not verify session.' });
  }
});

// ─── Email helpers ────────────────────────────────────────────────────────────
async function sendWelcomeEmail(to, plan) {
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
        sendWelcomeEmail(customerEmail, plan).catch(err =>
          console.error('[webhook] Failed to send welcome email:', err.message)
        );
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
