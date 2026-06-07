# Stripe Billing Setup Guide

## Overview

Hexor uses Stripe for subscription billing. This guide walks through complete setup.

## 1. Create Stripe Account

1. Go to https://stripe.com
2. Sign up for account
3. Complete verification (may take 1-2 days for production access)

## 2. Get API Keys

### Test Mode (Development)

Dashboard → Developers → API keys

You'll see:
- **Publishable key:** `pk_test_...` (frontend)
- **Secret key:** `sk_test_...` (backend) ← Add to `.env`

### Production Mode

Switch toggle from "Test mode" to "Live mode"

- **Publishable key:** `pk_live_...`
- **Secret key:** `sk_live_...` ← Add to `.env`

## 3. Create Products & Prices

Dashboard → Products → Add Product

### Starter Tier

- **Name:** Hexor Starter
- **Description:** 10 scans/month, basic features
- **Pricing:** $99/month (recurring)
- **Billing period:** Monthly
- Save product
- Copy **Price ID:** `price_...` → Add to `.env` as `STRIPE_PRICE_STARTER`

### Pro Tier

- **Name:** Hexor Pro
- **Description:** 100 scans/month, exploit generation, API access
- **Pricing:** $499/month
- **Billing period:** Monthly
- Copy **Price ID** → `STRIPE_PRICE_PRO`

### Enterprise Tier

- **Name:** Hexor Enterprise
- **Description:** Unlimited scans, private deployment, SLA
- **Pricing:** $2,999/month
- **Billing period:** Monthly
- Copy **Price ID** → `STRIPE_PRICE_ENTERPRISE`

### APT Tier

- **Name:** Hexor APT
- **Description:** Full 0-day hunting, advanced chains, consulting
- **Pricing:** $9,999/month
- **Billing period:** Monthly
- Copy **Price ID** → `STRIPE_PRICE_APT`

## 4. Configure Webhooks

Webhooks notify your backend about payment events (success/failure, subscription changes).

### Local Development (using Stripe CLI)

```bash
# Install Stripe CLI
# Mac
brew install stripe/stripe-cli/stripe

# Linux
wget https://github.com/stripe/stripe-cli/releases/download/v1.19.0/stripe_1.19.0_linux_x86_64.tar.gz
tar -xvf stripe_1.19.0_linux_x86_64.tar.gz
sudo mv stripe /usr/local/bin/

# Login
stripe login

# Forward webhooks to local backend
stripe listen --forward-to localhost:8000/api/webhooks/stripe
```

This will output:
```
> Ready! Your webhook signing secret is whsec_... (^C to quit)
```

Copy `whsec_...` → Add to `.env` as `STRIPE_WEBHOOK_SECRET`

### Production (via Dashboard)

Dashboard → Developers → Webhooks → Add endpoint

**Endpoint URL:** `https://yourdomain.com/api/webhooks/stripe`

**Events to send:**
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.payment_succeeded`
- `invoice.payment_failed`

After creating, click on webhook → **Signing secret** → Reveal
Copy `whsec_...` → Add to `.env`

## 5. Update .env File

```bash
# Stripe Billing
STRIPE_SECRET_KEY=sk_test_51abc...
STRIPE_WEBHOOK_SECRET=whsec_xyz...
STRIPE_PRICE_STARTER=price_123...
STRIPE_PRICE_PRO=price_456...
STRIPE_PRICE_ENTERPRISE=price_789...
STRIPE_PRICE_APT=price_abc...

# Frontend URL (for redirects)
FRONTEND_URL=http://localhost:3000  # dev
# FRONTEND_URL=https://hexor.app    # production
```

## 6. Install Stripe Python SDK

```bash
cd backend
pip install stripe
```

Or add to `requirements.txt`:
```
stripe>=8.0.0
```

## 7. Test Integration

### Create Test Subscription

```bash
# Start backend
python main.py

# In another terminal, test API
curl -X POST http://localhost:8000/api/billing/subscription \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tier": "pro"}'
```

### Use Test Cards

Stripe provides test cards:

**Success:**
- Card: `4242 4242 4242 4242`
- Expiry: Any future date
- CVC: Any 3 digits
- ZIP: Any 5 digits

**Decline:**
- Card: `4000 0000 0000 0002`

**Requires 3D Secure:**
- Card: `4000 0025 0000 3155`

Full list: https://stripe.com/docs/testing

### Test Webhooks

```bash
# Trigger test event
stripe trigger payment_intent.succeeded
```

Check your backend logs for webhook receipt.

## 8. Customer Portal

The billing portal allows customers to:
- Update payment methods
- View invoices
- Cancel subscription
- Download receipts

**Enable in Dashboard:**
Settings → Billing → Customer portal → Activate

**Features to enable:**
- ✅ Invoice history
- ✅ Update payment method
- ✅ Cancel subscription

## 9. Production Checklist

Before going live:

- [ ] Switch to Live mode keys
- [ ] Update webhook URL to production domain
- [ ] Test with real (small) payment
- [ ] Enable 3D Secure (SCA compliance for EU)
- [ ] Set up email notifications (payment failed, etc)
- [ ] Configure tax rates if needed
- [ ] Set up fraud detection rules
- [ ] Add Terms of Service & Privacy Policy links

## 10. Monitoring

Dashboard → Payments → Monitor:
- Successful payments
- Failed payments
- Churn rate
- MRR (Monthly Recurring Revenue)

Set up email alerts for:
- Failed payments
- Subscription cancellations
- Disputes/chargebacks

## API Usage Examples

### Create Subscription

```python
POST /api/billing/subscription
{
  "tier": "pro",
  "payment_method_id": "pm_..." # Optional, from Stripe.js
}

Response:
{
  "subscription_id": "sub_...",
  "client_secret": "pi_..._secret_...", # For payment confirmation
  "status": "incomplete" # or "active" if using trial
}
```

### Get Billing Portal

```python
GET /api/billing/portal

Response:
{
  "url": "https://billing.stripe.com/session/..."
}

# Redirect user to this URL
```

### Check Usage

```python
GET /api/billing/usage

Response:
{
  "subscription_tier": "pro",
  "subscription_status": "active",
  "monthly_scan_limit": 100,
  "monthly_scans_used": 23,
  "scans_remaining": 77,
  "trial_ends_at": null
}
```

### Cancel Subscription

```python
DELETE /api/billing/subscription

Response:
{
  "status": "canceling",
  "message": "Subscription will cancel at period end"
}
```

## Troubleshooting

### "No signature" error

Check webhook secret is correct in `.env`

### "Invalid signature" error

- Clock skew (server time wrong)
- Using wrong webhook secret
- Payload modified in transit

### Payment fails in production

- Check 3D Secure enabled
- Verify payment method
- Check fraud rules not blocking legitimate payments

### Webhook not received

- Check endpoint URL accessible from internet
- Verify webhook events selected
- Check firewall/CORS settings

## Support

- Stripe Docs: https://stripe.com/docs
- Stripe Support: https://support.stripe.com
- Status: https://status.stripe.com

---

**Security Notes:**

⚠️ **Never** commit real API keys to git
⚠️ Use `.env` files (gitignored)
⚠️ Use separate keys for test/production
⚠️ Rotate keys if compromised
⚠️ Always validate webhooks with signature
