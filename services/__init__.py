"""
Service layer exports. Import scanners from here for a clean API:
    from services import scan_website
"""

from services.website_scanner import scan_website, persist_scan as persist_website_scan
from services.email_scanner import scan_email, persist_scan as persist_email_scan
from services.job_scanner import scan_job, persist_scan as persist_job_scan
from services.whatsapp_scanner import scan_whatsapp_text, scan_whatsapp_image, persist_scan as persist_whatsapp_scan
from services.qr_scanner import scan_qr_image, persist_scan as persist_qr_scan
from services.payment_scanner import scan_payment_screenshot, persist_scan as persist_payment_scan
from services.product_scanner import scan_product, persist_scan as persist_product_scan
from services.claim_scanner import scan_claim, persist_scan as persist_claim_scan

__all__ = [
    "scan_website",
    "scan_email",
    "scan_job",
    "scan_whatsapp_text",
    "scan_whatsapp_image",
    "scan_qr_image",
    "scan_payment_screenshot",
    "scan_product",
    "scan_claim",
    "persist_website_scan",
    "persist_email_scan",
    "persist_job_scan",
    "persist_whatsapp_scan",
    "persist_qr_scan",
    "persist_payment_scan",
    "persist_product_scan",
    "persist_claim_scan",
]
