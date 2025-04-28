import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from django.conf import settings
import logging
from datetime import datetime

# Logger for error reporting
logger = logging.getLogger(__name__)

# Brevo configuration
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = settings.BREVO_API_KEY

def send_brevo_email(to_email, subject, html_content, text_content=None):
    try:
        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

        # Prepare the email object
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            sender={'email': settings.DEFAULT_FROM_EMAIL},
            to=[{'email': to_email}],
            subject=subject,
            html_content=html_content,
            text_content=text_content,  # <-- added plain text fallback
        )

        # Send the email using Brevo's API
        api_instance.send_transac_email(send_smtp_email)
        logger.info(f"Verification email sent to {to_email} via Brevo")
        return True
    except ApiException as e:
        logger.error(f"Brevo API exception: {e}")
        return False


def send_verification_email(user, verification_code):
    subject = "Verify Your Email Address"
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user.email]

    current_year = datetime.now().year

    # Plain text fallback
    text_content = f"""
Hi {user.first_name},

Thank you for registering with us!

To complete your registration, please verify your email address using the following code:

{verification_code}

This code will expire in 24 hours. If you did not request this, you can safely ignore this email.

Need help? Contact our support team at support@yourcompany.com.

© {current_year} Your Company Name. All rights reserved.
[Company Address Line 1], [Company Address Line 2]

Privacy Policy | Terms of Service
    """

    # HTML Content
    html_content = f"""
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: 'Helvetica Neue', Arial, sans-serif; background-color: #f8f9fa; margin: 0; padding: 0;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff;">
        <div style="background-color: #ffffff; padding: 24px 30px; border-bottom: 1px solid #eaeaea;">
            <table width="100%">
                <tr>
                    <td>
                        <img src="cid:logo_image" alt="Company Logo" style="height: 32px; max-height: 32px;">
                    </td>
                    <td style="text-align: right; color: #6c757d; font-size: 14px;">
                        Email Verification
                    </td>
                </tr>
            </table>
        </div>
        <div style="padding: 40px 30px;">
            <h1 style="margin-top: 0; margin-bottom: 24px; font-size: 24px; font-weight: 600; color: #212529;">
                Verify your email address
            </h1>
            <p style="margin-bottom: 24px; font-size: 16px; line-height: 1.5; color: #495057;">
                Hello {user.first_name}, thank you for registering with us. To complete your registration, please verify your email address by entering the following verification code:
            </p>
            <div style="background-color: #f8f9fa; border-radius: 6px; padding: 16px; text-align: center; margin: 32px 0;">
                <span style="font-size: 32px; letter-spacing: 2px; color: #2c3e50; font-weight: 600; font-family: monospace;">
                    {verification_code}
                </span>
            </div>
            <p style="margin-bottom: 24px; font-size: 16px; line-height: 1.5; color: #495057;">
                This code will expire in <strong>24 hours</strong>. If you didn't request this code, you can safely ignore this email.
            </p>
            <div style="margin-top: 32px; padding-top: 16px; border-top: 1px solid #eaeaea;">
                <p style="margin-bottom: 8px; font-size: 14px; color: #6c757d;">
                    Need help? <a href="mailto:support@yourcompany.com" style="color: #4a6ee0; text-decoration: none;">Contact our support team</a>
                </p>
            </div>
        </div>
        <div style="background-color: #f8f9fa; padding: 24px 30px; text-align: center; font-size: 12px; color: #6c757d;">
            <p style="margin: 0 0 8px 0;">
                © {current_year} Your Company Name. All rights reserved.
            </p>
            <p style="margin: 0 0 8px 0;">
                [Company Address Line 1], [Company Address Line 2]
            </p>
            <p style="margin: 0;">
                <a href="#" style="color: #6c757d; text-decoration: none; margin: 0 8px;">Privacy Policy</a>
                <a href="#" style="color: #6c757d; text-decoration: none; margin: 0 8px;">Terms of Service</a>
            </p>
        </div>
    </div>
</body>
</html>
    """

    # Send email using Brevo with both HTML and plain text
    return send_brevo_email(user.email, subject, html_content, text_content)
