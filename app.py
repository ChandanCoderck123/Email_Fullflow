import re
import dns.resolver
import smtplib
import mysql.connector

# MySQL config
MYSQL_CONFIG = {
    'host': 'holistique-middleware.c9wdjmzy25ra.ap-south-1.rds.amazonaws.com',
    'user': 'Chandan',
    'password': 'Chandan@#4321',
    'database': 'email_validator_app'
}

# Heuristic Datasets
DISPOSABLE_DOMAINS = {
    "10minutemail.com", "tempmail.com", "mailinator.com", "guerrillamail.com",
    "yopmail.com", "trashmail.com", "temp-mail.org", "maildrop.cc"
}
ROLE_ACCOUNTS = {
    "admin", "support", "info", "sales", "contact", "help", "webmaster", "office"
}
BLOCKLISTED_EMAILS = {"baduser@scam.com"}
BLOCKLISTED_DOMAINS = {"spammydomain.com"}
HISTORICAL_BOUNCES = {"bounce@oldcompany.com", "test@companybounced.com"}

def is_valid_syntax(email):
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(regex, email) is not None

def get_domain(email):
    return email.split('@')[-1].lower()

def is_disposable(email):
    return get_domain(email) in DISPOSABLE_DOMAINS

def is_role_account(email):
    local = email.split('@')[0].lower()
    prefix = local.split('+')[0].split('.')[0].split('_')[0]
    return prefix in ROLE_ACCOUNTS

def is_blocklisted(email):
    domain = get_domain(email)
    return email in BLOCKLISTED_EMAILS or domain in BLOCKLISTED_DOMAINS

def has_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return len(answers) > 0
    except Exception:
        return False

def smtp_check(email, from_address="test@example.com"):
    domain = get_domain(email)
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange)
    except Exception:
        return False
    server = None
    try:
        server = smtplib.SMTP(timeout=10)
        server.connect(mx_host)
        server.helo(server.local_hostname)
        server.mail(from_address)
        code, resp = server.rcpt(email)
        server.quit()
        if code in [250, 251]:
            return True
        elif code == 550:
            return False
        else:
            return False
    except Exception:
        return False
    finally:
        if server:
            try:
                server.close()
            except Exception:
                pass

def historical_bounce_check(email):
    return email in HISTORICAL_BOUNCES

def ml_heuristic_check(email):
    weird_patterns = ['test', 'fake', 'random', 'xxxx', '123', 'qwerty']
    email_lower = email.lower()
    for pattern in weird_patterns:
        if pattern in email_lower:
            return True
    return False

def validate_email(email):
    if not is_valid_syntax(email):
        return 'invalid'
    if is_blocklisted(email):
        return 'invalid'
    if is_disposable(email):
        return 'invalid'
    if is_role_account(email):
        return 'invalid'
    if historical_bounce_check(email):
        return 'invalid'
    if ml_heuristic_check(email):
        return 'invalid'
    domain = get_domain(email)
    if not has_mx_record(domain):
        return 'invalid'
    if not smtp_check(email):
        return 'invalid'
    return 'valid'

def main():
    # Connect to MySQL
    conn = mysql.connector.connect(**MYSQL_CONFIG)
    cursor = conn.cursor(dictionary=True)

    # 1. Try up to 45 'pending' first
    cursor.execute("""
        SELECT * FROM email_data
        WHERE process_status = 'pending'
        LIMIT 45
    """)
    rows = cursor.fetchall()

    # 2. If no pending, process up to 45 'error' emails
    if not rows:
        cursor.execute("""
            SELECT * FROM email_data
            WHERE process_status = 'error'
            LIMIT 45
        """)
        rows = cursor.fetchall()

    if not rows:
        print("No pending or error emails to process.")
        cursor.close()
        conn.close()
        return

    print(f"Processing {len(rows)} emails...")

    for row in rows:
        email = row['email']
        print(f"Validating: {email}")
        try:
            result = validate_email(email)
            process_status = 'successful' if result in ['valid', 'invalid'] else 'error'
            final_status = result if result in ['valid', 'invalid'] else 'not_processed'
            update_cursor = conn.cursor()
            update_cursor.execute("""
                UPDATE email_data
                SET final_status=%s, process_status=%s, updated_at=NOW()
                WHERE email=%s
            """, (final_status, process_status, email))
            conn.commit()
            update_cursor.close()
            print(f"-> {email}: {final_status} ({process_status})")
        except Exception as e:
            update_cursor = conn.cursor()
            update_cursor.execute("""
                UPDATE email_data
                SET process_status='error', final_status='not_processed', updated_at=NOW()
                WHERE email=%s
            """, (email,))
            conn.commit()
            update_cursor.close()
            print(f"-> {email}: ERROR ({e})")

    cursor.close()
    conn.close()
    print("Batch processing complete.")

if __name__ == '__main__':
    main()
