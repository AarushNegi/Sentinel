"""Known-good fallback seeds. They pass the same validation as model output
and go through the same composer and engine as AI-generated scenarios."""

import copy
import random

from .scenario_schema import validate_seed
from .composer import compose_scenario

_TEMPLATE_SEEDS = {
    "no_compromise": {
        "title": "Overdue GST invoice email - no user interaction",
        "archetype": "no_compromise",
        "difficulty": "easy",
        "company": {"name": "Kaveri Textiles Pvt Ltd"},
        "victims": [{"first_name": "Ananya", "last_name": "Iyer",
                     "role": "Accounts Payable Executive", "department": "Finance"}],
        "impersonated_brand": "Sundaram Office Supplies",
        "sender_display_name": "Sundaram Office Supplies Billing",
        "email": {
            "subject": "GST invoice 40917 overdue - pay Rs 48,250 today",
            "paragraphs": [
                "Our records show GST invoice 40917 for Rs 48,250 is overdue and a late fee will be added.",
                "Please review the invoice and confirm your payment details on the vendor portal below.",
                "If you do not respond today, your vendor account may be put on hold.",
            ],
            "cta_label": "Review invoice",
            "signature": "Sundaram Office Supplies Accounts Team",
        },
        "attachment": None,
        "attacker_objective": "Harvest accounts-payable portal credentials to redirect vendor payments.",
    },
    "credential_compromise": {
        "title": "Fake salary portal email followed by a suspicious sign-in",
        "archetype": "credential_compromise",
        "difficulty": "medium",
        "company": {"name": "Lotus Health Care Pvt Ltd"},
        "victims": [{"first_name": "Rohan", "last_name": "Mehta",
                     "role": "Finance Manager", "department": "Finance"}],
        "impersonated_brand": "PayNest Payroll",
        "sender_display_name": "PayNest Payroll Service",
        "email": {
            "subject": "Action required: verify your salary account details",
            "paragraphs": [
                "We are updating our payroll system and need you to re-verify your salary account details.",
                "Accounts that are not verified within 24 hours may miss the next salary credit.",
            ],
            "cta_label": "Verify account",
            "signature": "PayNest Payroll Security",
        },
        "attachment": None,
        "attacker_objective": "Steal corporate credentials to access mailbox and finance systems.",
    },
    "multi_user_campaign": {
        "title": "Freight invoice campaign with an infected endpoint",
        "archetype": "multi_user_campaign",
        "difficulty": "hard",
        "company": {"name": "Shivalik Engineering Works"},
        "victims": [
            {"first_name": "Suresh", "last_name": "Nair",
             "role": "Procurement Lead", "department": "Procurement"},
            {"first_name": "Farhan", "last_name": "Qureshi",
             "role": "Project Accountant", "department": "Finance"},
            {"first_name": "Meera", "last_name": "Joshi",
             "role": "Operations Coordinator", "department": "Operations"},
        ],
        "impersonated_brand": "Vishwa Freight Services",
        "sender_display_name": "Vishwa Freight Billing",
        "email": {
            "subject": "Revised freight invoice and e-way bill details",
            "paragraphs": [
                "Please find the revised freight invoice attached together with the updated bank details for NEFT payment.",
                "Use the secure link below if you prefer to confirm the payment details online.",
                "Kindly action this before the end of the week.",
            ],
            "cta_label": "Confirm payment",
            "signature": "Vishwa Freight Billing Department",
        },
        "attachment": {"filename": "Freight_Invoice_70431.docm", "kind": "docm"},
        "attacker_objective": "Gain a foothold on finance workstations and harvest credentials for payment fraud.",
    },
    "blocked_campaign": {
        "title": "Parcel customs-fee campaign stopped before any user interacted",
        "archetype": "blocked_campaign",
        "difficulty": "medium",
        "company": {"name": "Deccan Auto Components"},
        "victims": [
            {"first_name": "Karthik", "last_name": "Subramanian",
             "role": "Plant Controller", "department": "Finance"},
            {"first_name": "Nisha", "last_name": "Banerjee",
             "role": "Supply Chain Planner", "department": "Logistics"},
            {"first_name": "Imran", "last_name": "Sheikh",
             "role": "Quality Engineer", "department": "Engineering"},
        ],
        "impersonated_brand": "Bharat Express Couriers",
        "sender_display_name": "Bharat Express Couriers Dispatch",
        "email": {
            "subject": "Parcel on hold: customs fee of Rs 1,250 pending",
            "paragraphs": [
                "Your parcel is on hold at the sorting centre because a customs fee of Rs 1,250 is unpaid.",
                "Confirm your delivery address and pay the fee through UPI on our payment page.",
            ],
            "cta_label": "Pay fee",
            "signature": "Bharat Express Couriers Customer Care",
        },
        "attachment": None,
        "attacker_objective": "Collect UPI and card details from employees through a fake delivery-fee page.",
    },
    "malicious_attachment": {
        "title": "Macro-enabled GST statement opened on a workstation",
        "archetype": "malicious_attachment",
        "difficulty": "medium",
        "company": {"name": "Sahyadri Analytics"},
        "victims": [{"first_name": "Kavya", "last_name": "Reddy",
                     "role": "Accounts Receivable Analyst", "department": "Finance"}],
        "impersonated_brand": "Gokul Logistics",
        "sender_display_name": "Gokul Logistics Billing",
        "email": {
            "subject": "Overdue GST statement attached - please review",
            "paragraphs": [
                "Please find the attached statement showing several overdue GST invoices.",
                "Open the document and click enable content to view the full account history.",
            ],
            "cta_label": "View statement",
            "signature": "Gokul Logistics Accounts",
        },
        "attachment": {"filename": "Statement_Q3_Overdue.docm", "kind": "docm"},
        "attacker_objective": "Run a macro downloader on a finance workstation to gain a foothold.",
    },
    "spoofed_internal": {
        "title": "Director impersonation asking for an urgent NEFT transfer",
        "archetype": "spoofed_internal",
        "difficulty": "hard",
        "company": {"name": "Konkan Capital Advisors"},
        "victims": [{"first_name": "Aditya", "last_name": "Kulkarni",
                     "role": "Treasury Analyst", "department": "Treasury"}],
        "impersonated_brand": "Mehra and Partners",
        "sender_display_name": "Vikram Malhotra Chief Financial Officer",
        "email": {
            "subject": "Confidential: urgent NEFT transfer needed today",
            "paragraphs": [
                "I need you to process a confidential NEFT payment of Rs 4,75,000 before the end of the day.",
                "Review the payment details using the secure link below and reply to me only; I am in meetings and cannot take calls.",
            ],
            "cta_label": "Open document",
            "signature": "Vikram Malhotra",
        },
        "attachment": None,
        "attacker_objective": "Pressure a treasury analyst into authorising a fraudulent NEFT transfer.",
    },
}


def template_archetypes():
    return tuple(_TEMPLATE_SEEDS)


def get_template_seed(archetype):
    return copy.deepcopy(_TEMPLATE_SEEDS[archetype])


def build_template_scenario(archetype=None, *, rng=None, now=None):
    """Return a validated scenario from a built-in template."""
    rng = rng or random.Random()
    archetype = archetype or rng.choice(template_archetypes())
    if archetype not in _TEMPLATE_SEEDS:
        raise ValueError(f"no template for archetype '{archetype}'")
    seed = validate_seed(get_template_seed(archetype))
    return compose_scenario(seed, source="template", now=now)
