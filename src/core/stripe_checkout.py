# ── stripe_checkout.py ─────────────────────────────────────
import os
import stripe
from dotenv import load_dotenv

load_dotenv()
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")  # Put this in your .env

DOMAIN = "https://nichosec-v2.onrender.com"  # your deployed frontend

def create_checkout_session(user_email):
    try:
        checkout_session = stripe.checkout.Session.create(
            success_url=f"{DOMAIN}?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{DOMAIN}?cancelled=true",
            payment_method_types=["card"],
            mode="subscription",
            customer_email=user_email,
            line_items=[{
                "price": os.getenv("STRIPE_PRICE_ID"),  # From Stripe dashboard
                "quantity": 1
            }],
        )
        return checkout_session.url
    except Exception as e:
        return None
