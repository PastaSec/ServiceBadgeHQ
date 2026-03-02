import re

def format_us_phone_display(phone_e164: str) -> str:
    """
    ELI5: Takes +15551234567 and shows (555) 123-4567.
    US-only for MVP.
    """
    if not phone_e164:
        return ""
    digits = re.sub(r"\D", "", phone_e164)
    # handle +1XXXXXXXXXX or just XXXXXXXXXX
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        return phone_e164  # fallback: show what we have
    return f"({digits[0:3]}) {digits[3:6]}-{digits[6:10]}"
