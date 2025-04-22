import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from django.conf import settings
import logging

# Logger for error reporting
logger = logging.getLogger(__name__)

# Brevo configuration
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = settings.BREVO_API_KEY

def send_brevo_email(to_email, subject, html_content):
    try:
        api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

        # Prepare the email object
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
            sender={'email': settings.DEFAULT_FROM_EMAIL},
            to=[{'email': to_email}],
            subject=subject,
            html_content=html_content,
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

    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
        <div style="max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 10px; text-align: center;">
            <img src="cid:logo_image" alt="Your App Logo" style="max-width: 150px; margin-bottom: 20px;" />
            <h2>Hello {user.first_name},</h2>
            <p>Please verify your email by entering this code:</p>
            <div style="margin: 20px 0;">
                <span style="font-size: 28px; color: #4CAF50;">{verification_code}</span>
            </div>
            <p>This code expires in 24 hours.</p>
            <p>— Your App Team</p>
        </div>
    </body>
    </html>
    """

    # Send email using Brevo
    return send_brevo_email(user.email, subject, html_content)



# from django.core.mail import EmailMessage
# from django.conf import settings
# import logging

# logger = logging.getLogger(__name__)

# def send_verification_email(user, verification_code):
#     subject = "Verify Your Email Address"
#     from_email = settings.DEFAULT_FROM_EMAIL
#     to_email = [user.email]

#     html_content = f"""
#     <html>
#     <body>
#         <h2>Hello {user.first_name},</h2>
#         <p>Your verification code is:</p>
#         <h3>{verification_code}</h3>
#     </body>
#     </html>
#     """

#     try:
#         email = EmailMessage(subject, html_content, from_email, to_email)
#         email.content_subtype = "html"
#         email.send()
#         logger.info(f"Sent verification email to {user.email} via console backend")
#         return True
#     except Exception as e:
#         logger.error(f"Error sending email: {e}")
#         return False
