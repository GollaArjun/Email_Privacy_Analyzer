"""Pre-packaged synthetic test emails covering distinct cybersecurity scenarios."""

SAMPLE_EMAILS = {
    "phishing_credential_lure": {
        "title": "Phishing Attempt (Urgency, URL Spoofing, Reply-To Mismatch)",
        "description": "Deceptive alert claiming account suspension, with punycode domain, open redirect, and domain mismatch.",
        "content": """From: "Bank Security Operations" <alert-notice@secure-verify.xyz>
Reply-To: "Support Ticket Desk" <collector@attacker-portal.top>
To: account-holder@victim-company.com
Subject: URGENT: Unauthorized Access Attempt Detected - Immediate Action Required
Date: Sun, 15 Nov 2026 15:30:00 +0000
Message-ID: <phish-alert-99124@secure-verify.xyz>
Authentication-Results: mx.receiver.com; spf=fail; dkim=none; dmarc=fail

Dear Valued Customer,

We detected an unauthorized sign-in attempt from an unrecognized IP address (198.51.100.42).
Your online banking access has been temporarily suspended.

Immediate action required: You must confirm your identity within 24 hours to prevent permanent account closure.

Click here to restore access:
http://192.168.1.105/auth/login?redirect=http://secure-verify.xyz

Do not disregard this notice. Failure to authenticate immediately will result in forfeiture of privileges.

Fraud Prevention Center
"""
    },

    "pii_credential_leak": {
        "title": "Severe PII & API Key Leakage",
        "description": "Sensitive customer and employee records sent over unencrypted email, including Aadhaar, PAN, phone, and AWS key.",
        "content": """From: "Finance Desk" <finance-internal@acme-corp.com>
To: "External Auditor" <audit-partner@consulting-group.org>
Subject: CONFIDENTIAL: Onboarding KYC Dossier & Cloud Access Tokens
Date: Sat, 14 Nov 2026 10:15:00 +0000
Message-ID: <kyc-leak-8871@acme-corp.com>
Authentication-Results: mx.receiver.com; spf=pass; dkim=pass; dmarc=pass

Hi Sarah,

Please find the verified KYC credentials and cloud admin credentials for the new regional director:

Full Name: Rajesh Sharma
Aadhaar Number: 4582 9102 3847
Permanent Account Number (PAN): ABCDE1234F
Direct Phone: +91 9876543210
Personal IP: 103.21.244.15

Also, here are the staging AWS credentials we provisioned for their team:
AWS_ACCESS_KEY: AKIAIOSFODNN7EXAMPLE
Temporary Password: Password@2026!Secure

Please delete this message after verification.
"""
    },

    "tracking_pixels_marketing": {
        "title": "Covert Tracking Pixels & Telemetry",
        "description": "Newsletter containing zero-dimension 1x1 web beacon, ESP open tracker, and recipient telemetry queries.",
        "content": """From: "E-Commerce Specials" <newsletter@marketing-retailer.com>
To: "Subscriber" <target@domain.com>
Subject: Flash Sale: Save up to 50% on Cyber Defense Tools Today Only!
Date: Fri, 13 Nov 2026 12:00:00 +0000
Content-Type: text/html; charset=utf-8
Message-ID: <promo-pixel-5541@marketing-retailer.com>
Authentication-Results: mx.receiver.com; spf=pass; dkim=pass; dmarc=pass

<!DOCTYPE html>
<html>
<head><title>Flash Sale</title></head>
<body style="font-family: Arial, sans-serif;">
  <h2>Exclusive Weekend Flash Sale!</h2>
  <p>Discover our top-rated cybersecurity learning gear.</p>
  <a href="https://sendgrid.net/wf/click?upn=tracker99201&recipient_id=user_4821">Browse Deals Now</a>
  
  <!-- Zero-dimension invisible tracking pixel -->
  <img src="https://sendgrid.net/wf/open?upn=pixel_track_4821" width="1" height="1" style="display:none;" alt="" />
  <!-- Additional third-party telemetry beacon -->
  <img src="https://hs-analytics.net/track/open.gif?eid=sub_9921" width="0" height="0" alt="" />
</body>
</html>
"""
    },

    "malicious_attachment": {
        "title": "Dangerous Attachment (Double Extension & Macro)",
        "description": "Simulated spear-phishing email with deceptive invoice containing double-extension executable.",
        "content": """From: "Accounts Payable" <billing-dept@freight-invoices.com>
To: "Accounting Staff" <ap@target-company.com>
Subject: Overdue Invoice Remittance: INV-98402 (Payment Confirmation Needed)
Date: Thu, 12 Nov 2026 08:30:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_9912_10829182.1700000000"
Message-ID: <invoice-threat-3310@freight-invoices.com>
Authentication-Results: mx.receiver.com; spf=softfail; dkim=none; dmarc=none

------=_Part_9912_10829182.1700000000
Content-Type: text/plain; charset=utf-8

Please find attached the past due invoice statement for review. Immediate remittance required.

Attached: Invoice_Statement_Nov2026.pdf.exe

Regards,
Accounts Department
------=_Part_9912_10829182.1700000000
Content-Type: application/octet-stream; name="Invoice_Statement_Nov2026.pdf.exe"
Content-Disposition: attachment; filename="Invoice_Statement_Nov2026.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAA2AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1v
ZGUuDQ0KJAAAAAAAAABQRQAATAEDAAAAAAAAAAAAAAAAAAAAAAAA
------=_Part_9912_10829182.1700000000--
"""
    },

    "clean_benign_email": {
        "title": "Clean, Authenticated Business Communication",
        "description": "Legitimate business email with SPF, DKIM, and DMARC passing, zero tracking pixels, and no PII leaks.",
        "content": """From: "Alice Mitchell" <alice.mitchell@engineering-partner.org>
To: "Bob Vance" <bob.vance@tech-solutions.com>
Subject: Project Sprint 4 Architecture Review Meeting Notes
Date: Wed, 11 Nov 2026 14:00:00 +0000
Message-ID: <sprint4-notes-20261111@engineering-partner.org>
Authentication-Results: mx.google.com; spf=pass (google.com: domain of alice.mitchell@engineering-partner.org designates 192.0.2.1 as permitted sender); dkim=pass header.i=@engineering-partner.org; dmarc=pass

Hi Bob,

Thanks for the productive engineering review earlier today. 
The team has agreed on the microservices decoupling schedule. We will proceed with Phase 1 deployment next Tuesday morning during the standard maintenance window.

Please review the architecture diagram in our shared intranet wiki when you have a moment.

Best regards,
Alice Mitchell
Lead Software Architect
Engineering Partner Org
"""
    }
}
