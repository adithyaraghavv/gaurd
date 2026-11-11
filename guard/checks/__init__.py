from . import (access, ai, cookies, cors, db_access, db_rules, exposed, headers, injection, jwt,
               mass_assignment, ratelimit, tenant, upload)

ALL_CHECKS = {
    "headers": headers.run,
    "cors": cors.run,
    "cookies": cookies.run,
    "exposed": exposed.run,
    "tenant": tenant.run,
    "access": access.run,
    "jwt": jwt.run,
    "injection": injection.run,
    "mass_assignment": mass_assignment.run,
    "upload": upload.run,
    "ratelimit": ratelimit.run,
    "db_rules": db_rules.run,
    "db_access": db_access.run,
    "ai": ai.run,
}

# These run without network (http=None); their live parts are skipped then.
OFFLINE_OK = {"db_rules", "db_access", "ai", "jwt"}

# Checks that look at cfg.probe_paths (only the first cfg.max_probe_paths are used).
PROBE_PATH_CHECKS = {"headers", "cors", "cookies", "injection"}
