"""
Hexor Billing — Stripe Integration

Handles:
- Subscription creation/cancellation
- Payment processing
- Webhooks (payment events)
- Customer portal
- Usage-based billing
"""
import os
from typing import Optional
from datetime import datetime, timedelta

import stripe
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from db import Organization, SubscriptionTier

# Stripe configuration
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

# Price IDs from Stripe Dashboard
PRICE_IDS = {
    SubscriptionTier.STARTER: os.getenv("STRIPE_PRICE_STARTER"),
    SubscriptionTier.PRO: os.getenv("STRIPE_PRICE_PRO"),
    SubscriptionTier.ENTERPRISE: os.getenv("STRIPE_PRICE_ENTERPRISE"),
    SubscriptionTier.APT: os.getenv("STRIPE_PRICE_APT"),
}


class BillingService:
    """Service for handling Stripe billing operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_customer(self, org: Organization, email: str) -> str:
        """
        Create Stripe customer for organization.
        
        Returns customer ID.
        """
        customer = stripe.Customer.create(
            email=email,
            metadata={
                "org_id": org.id,
                "org_name": org.name
            }
        )
        
        # Save customer ID
        org.stripe_customer_id = customer.id
        await self.db.commit()
        
        return customer.id
    
    async def create_subscription(
        self,
        org: Organization,
        tier: SubscriptionTier,
        payment_method_id: Optional[str] = None
    ) -> dict:
        """
        Create subscription for organization.
        
        Args:
            org: Organization
            tier: Subscription tier
            payment_method_id: Stripe payment method ID (optional for trial)
        
        Returns:
            dict with subscription details and client_secret for payment confirmation
        """
        # Ensure customer exists
        if not org.stripe_customer_id:
            raise ValueError("Organization has no Stripe customer ID")
        
        # Get price ID for tier
        price_id = PRICE_IDS.get(tier)
        if not price_id:
            raise ValueError(f"No price ID configured for tier: {tier}")
        
        # Create subscription
        subscription_params = {
            "customer": org.stripe_customer_id,
            "items": [{"price": price_id}],
            "metadata": {
                "org_id": org.id,
                "tier": tier
            },
            "trial_period_days": 14 if tier == SubscriptionTier.STARTER else None,
        }
        
        if payment_method_id:
            subscription_params["default_payment_method"] = payment_method_id
        else:
            # Payment required mode (collect payment upfront)
            subscription_params["payment_behavior"] = "default_incomplete"
            subscription_params["payment_settings"] = {
                "payment_method_types": ["card"]
            }
        
        subscription = stripe.Subscription.create(**subscription_params)
        
        # Update organization
        org.stripe_subscription_id = subscription.id
        org.subscription_tier = tier
        org.subscription_status = subscription.status
        org.monthly_scan_limit = self._get_scan_limit(tier)
        
        if subscription.trial_end:
            org.trial_ends_at = datetime.fromtimestamp(subscription.trial_end)
        
        await self.db.commit()
        
        # Return client secret for payment confirmation
        latest_invoice = subscription.latest_invoice
        if isinstance(latest_invoice, str):
            invoice = stripe.Invoice.retrieve(latest_invoice)
            payment_intent = invoice.payment_intent
            if isinstance(payment_intent, str):
                pi = stripe.PaymentIntent.retrieve(payment_intent)
                return {
                    "subscription_id": subscription.id,
                    "client_secret": pi.client_secret,
                    "status": subscription.status
                }
        
        return {
            "subscription_id": subscription.id,
            "status": subscription.status
        }
    
    async def cancel_subscription(self, org: Organization) -> bool:
        """
        Cancel organization's subscription.
        
        Cancels at period end (not immediate).
        """
        if not org.stripe_subscription_id:
            return False
        
        subscription = stripe.Subscription.modify(
            org.stripe_subscription_id,
            cancel_at_period_end=True
        )
        
        org.subscription_status = "canceling"
        await self.db.commit()
        
        return True
    
    async def update_subscription(
        self,
        org: Organization,
        new_tier: SubscriptionTier
    ) -> dict:
        """
        Upgrade/downgrade subscription tier.
        
        Proration handled automatically by Stripe.
        """
        if not org.stripe_subscription_id:
            raise ValueError("No active subscription")
        
        # Get current subscription
        subscription = stripe.Subscription.retrieve(org.stripe_subscription_id)
        
        # Get new price ID
        new_price_id = PRICE_IDS.get(new_tier)
        if not new_price_id:
            raise ValueError(f"No price ID for tier: {new_tier}")
        
        # Update subscription
        updated = stripe.Subscription.modify(
            subscription.id,
            items=[{
                "id": subscription["items"]["data"][0].id,
                "price": new_price_id
            }],
            proration_behavior="always_invoice"
        )
        
        # Update organization
        org.subscription_tier = new_tier
        org.subscription_status = updated.status
        org.monthly_scan_limit = self._get_scan_limit(new_tier)
        await self.db.commit()
        
        return {
            "subscription_id": updated.id,
            "status": updated.status,
            "new_tier": new_tier
        }
    
    async def create_portal_session(
        self,
        org: Organization,
        return_url: str
    ) -> str:
        """
        Create Stripe Customer Portal session.
        
        Allows customer to manage billing, update payment methods, view invoices.
        
        Returns portal URL.
        """
        if not org.stripe_customer_id:
            raise ValueError("No Stripe customer")
        
        session = stripe.billing_portal.Session.create(
            customer=org.stripe_customer_id,
            return_url=return_url
        )
        
        return session.url
    
    async def handle_webhook(self, payload: bytes, signature: str) -> dict:
        """
        Handle Stripe webhook event.
        
        Important events:
        - customer.subscription.created
        - customer.subscription.updated
        - customer.subscription.deleted
        - invoice.payment_succeeded
        - invoice.payment_failed
        """
        try:
            event = stripe.Webhook.construct_event(
                payload, signature, STRIPE_WEBHOOK_SECRET
            )
        except ValueError:
            raise ValueError("Invalid payload")
        except stripe.error.SignatureVerificationError:
            raise ValueError("Invalid signature")
        
        event_type = event["type"]
        data = event["data"]["object"]
        
        # Handle different event types
        if event_type == "customer.subscription.updated":
            await self._handle_subscription_updated(data)
        
        elif event_type == "customer.subscription.deleted":
            await self._handle_subscription_deleted(data)
        
        elif event_type == "invoice.payment_succeeded":
            await self._handle_payment_succeeded(data)
        
        elif event_type == "invoice.payment_failed":
            await self._handle_payment_failed(data)
        
        return {"status": "success", "event_type": event_type}
    
    async def _handle_subscription_updated(self, subscription):
        """Handle subscription update webhook"""
        sub_id = subscription["id"]
        status = subscription["status"]
        
        # Find organization by subscription ID
        result = await self.db.execute(
            select(Organization).where(
                Organization.stripe_subscription_id == sub_id
            )
        )
        org = result.scalar_one_or_none()
        
        if org:
            org.subscription_status = status
            
            # Update trial end
            if subscription.get("trial_end"):
                org.trial_ends_at = datetime.fromtimestamp(subscription["trial_end"])
            
            await self.db.commit()
    
    async def _handle_subscription_deleted(self, subscription):
        """Handle subscription cancellation"""
        sub_id = subscription["id"]
        
        result = await self.db.execute(
            select(Organization).where(
                Organization.stripe_subscription_id == sub_id
            )
        )
        org = result.scalar_one_or_none()
        
        if org:
            org.subscription_status = "cancelled"
            org.subscription_tier = SubscriptionTier.STARTER  # Downgrade to free tier
            org.monthly_scan_limit = 10
            await self.db.commit()
    
    async def _handle_payment_succeeded(self, invoice):
        """Handle successful payment"""
        customer_id = invoice["customer"]
        
        result = await self.db.execute(
            select(Organization).where(
                Organization.stripe_customer_id == customer_id
            )
        )
        org = result.scalar_one_or_none()
        
        if org:
            # Reset monthly usage on successful payment (new billing period)
            org.subscription_status = "active"
            org.monthly_scans_used = 0
            await self.db.commit()
    
    async def _handle_payment_failed(self, invoice):
        """Handle failed payment"""
        customer_id = invoice["customer"]
        
        result = await self.db.execute(
            select(Organization).where(
                Organization.stripe_customer_id == customer_id
            )
        )
        org = result.scalar_one_or_none()
        
        if org:
            org.subscription_status = "past_due"
            await self.db.commit()
            
            # TODO: Send email notification to customer
    
    def _get_scan_limit(self, tier: SubscriptionTier) -> int:
        """Get monthly scan limit for tier"""
        limits = {
            SubscriptionTier.STARTER: 10,
            SubscriptionTier.PRO: 100,
            SubscriptionTier.ENTERPRISE: 999999,  # "unlimited"
            SubscriptionTier.APT: 999999
        }
        return limits.get(tier, 10)


# Helper functions

async def check_subscription_valid(org: Organization) -> bool:
    """Check if organization has valid subscription"""
    if org.subscription_status == "active":
        return True
    
    if org.subscription_status == "trialing" and org.trial_ends_at:
        return datetime.utcnow() < org.trial_ends_at
    
    return False


async def check_scan_limit(org: Organization) -> bool:
    """Check if organization has scans remaining"""
    return org.monthly_scans_used < org.monthly_scan_limit
