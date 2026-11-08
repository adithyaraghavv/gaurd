from . import (ai, cookies, cors, db_rules, exposed, headers, injection, jwt,
               mass_assignment, ratelimit, tenant, upload)

ALL_CHECKS = {
    "headers": headers.run,
    "cors": cors.run,
    "cookies": cookies.run,
    "exposed": exposed.run,
    "tenant": tenant.run,
    "jwt": jwt.run,
    "injection": injection.run,
    "mass_assignment": mass_assignment.run,
    "upload": upload.run,
    "ratelimit": ratelimit.run,
    "db_rules": db_rules.run,
    "ai": ai.run,
}

# These run without network (http=None); their live parts are skipped then.
OFFLINE_OK = {"db_rules", "ai", "jwt"}
