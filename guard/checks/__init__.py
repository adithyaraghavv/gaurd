from . import (access, ai, cookies, cors, db_access, db_rules, exposed, headers, injection, jwt,
               mass_assignment, prod_config, ratelimit, supabase_audit, tenant, tenant_routes, upload)

ALL_CHECKS = {
    "headers": headers.run,
    "cors": cors.run,
    "cookies": cookies.run,
    "exposed": exposed.run,
    "tenant": tenant.run,
    "tenant_routes": tenant_routes.run,
    "access": access.run,
    "jwt": jwt.run,
    "injection": injection.run,
    "mass_assignment": mass_assignment.run,
    "upload": upload.run,
    "ratelimit": ratelimit.run,
    "db_rules": db_rules.run,
    "db_access": db_access.run,
    "supabase_audit": supabase_audit.run,
    "prod_config": prod_config.run,
    "ai": ai.run,
}

# These run without network (http=None); their live parts are skipped then.
OFFLINE_OK = {"db_rules", "db_access", "supabase_audit", "prod_config", "ai", "jwt"}

# Checks that look at cfg.probe_paths (only the first cfg.max_probe_paths are used).
PROBE_PATH_CHECKS = {"headers", "cors", "cookies", "injection"}
