ALL_RULES = []

from .injection import rules as injection_rules
from .auth import rules as auth_rules
from .xss import rules as xss_rules
from .csrf import rules as csrf_rules
from .upload import rules as upload_rules
from .misconfig import rules as misconfig_rules
from .deserialization import rules as deserialization_rules

ALL_RULES += injection_rules
ALL_RULES += auth_rules
ALL_RULES += xss_rules
ALL_RULES += csrf_rules
ALL_RULES += upload_rules
ALL_RULES += misconfig_rules
ALL_RULES += deserialization_rules