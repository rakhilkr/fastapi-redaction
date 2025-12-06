import os
import logging
from fastapi_redaction.redaction import Redaction, RedactingFilter

# Set up environment secret for test
os.environ["PASSWORD"] = "my_db_pass_1234"

# Create Redaction instance
r = Redaction()

# Attach filter manually
log_filter = RedactingFilter(r._secrets_substrings)

# Set up logger
logger = logging.getLogger("test")
logger.setLevel(logging.INFO)
logger.addFilter(log_filter)

# Add a console handler so we see output
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
logger.addHandler(console_handler)

# Test logging with secret
logger.info(f"password: {os.environ['PASSWORD']}")

# Test direct text redaction
print("Original:", f"My password is {os.environ['PASSWORD']}")
print("Redacted:", r.redact_text(f"My password is {os.environ['PASSWORD']}"))
