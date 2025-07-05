
from django.core.validators import RegexValidator


validate_name = RegexValidator(
    regex=r'^[A-Za-z\s]+$',
    message='Only alphabetic characters are allowed.'
)


# print(bool(re.match(r'^[A-Za-z]$', 'G')))   # ✅ True — G is a letter
