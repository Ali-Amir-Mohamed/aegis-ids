import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

EMAIL_FROM = "alimohamedamir66@gmail.com"
EMAIL_TO   = "alimohamedamir66@gmail.com"
EMAIL_PASS = "kcgv vqyx ixxc rtrj"

def send_alert_email(src_ip, attack_type, confidence, port):
    try:
        msg = MIMEMultipart()
        msg["Subject"] = "AEGIS ALERT: " + str(attack_type) + " Detected!"
        msg["From"]    = EMAIL_FROM
        msg["To"]      = EMAIL_TO
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = (
            "AEGIS AI Intrusion Detection System\n"
            "=====================================\n"
            "ATTACK DETECTED!\n\n"
            "Time        : " + now + "\n"
            "Attack Type : " + str(attack_type) + "\n"
            "Source IP   : " + str(src_ip) + "\n"
            "Port        : " + str(port) + "\n"
            "Confidence  : " + str(confidence) + "%\n"
            "Action      : IP blocked via iptables\n\n"
            "Check your dashboard: http://localhost:5000\n\n"
            "=====================================\n"
            "AEGIS v1.0 - University Research Project\n"
        )
        msg.attach(MIMEText(body, "plain"))
        password = EMAIL_PASS.replace(" ", "")
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_FROM, password)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        print("  [EMAIL] Alert sent to " + EMAIL_TO)
        return True
    except Exception as e:
        print("  [EMAIL ERROR] " + str(e))
        return False

if __name__ == "__main__":
    print("Testing email alert...")
    result = send_alert_email("127.0.0.1", "SSH Brute Force (port 22)", 90, 22)
    if result:
        print("Email sent successfully! Check your Gmail inbox.")
    else:
        print("Email failed.")
