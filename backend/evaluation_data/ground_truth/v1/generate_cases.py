"""Generate curated benchmark cases for RepoLens Ground-Truth Evaluation Benchmark."""

import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent / "cases"

cases = []

# =========================================================================
# 1. SECURITY FAMILIES
# =========================================================================

# Family 1: SEC-AUTH-01 (FastAPI tenant header client-controlled boundary) - DEV
cases.append({
    "case_id": "SEC-AUTH-01A",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-AUTH-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/routes/orders.py": (
                "from fastapi import APIRouter, Header\n"
                "router = APIRouter()\n\n"
                "@router.post('/orders')\n"
                "def create_order(x_tenant_id: str = Header(..., alias='X-Tenant-Id')):\n"
                "    tenant_id_context = x_tenant_id\n"
                "    db_session.where(tenant_id=tenant_id_context)\n"
                "    return {'status': 'created'}\n"
            )
        },
        "description": "FastAPI endpoint using unverified X-Tenant-Id header directly in tenant isolation boundary"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["CLIENT_CONTROLLED_AUTH_HEADER"],
        "claims": [{
            "rule_id": "CLIENT_CONTROLLED_AUTH_HEADER",
            "permitted_files": ["app/routes/orders.py"],
            "permitted_symbols": ["create_order"],
            "permitted_spans": [[5, 9]],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "CRITICAL"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_fastapi_tenant_pattern",
        "human_authored_explanation": "Direct client assertion via X-Tenant-Id header without cryptographic token verification."
    },
    "tags": ["auth", "tenant-isolation", "fastapi"]
})

cases.append({
    "case_id": "SEC-AUTH-01B",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-AUTH-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/routes/orders.py": (
                "from fastapi import APIRouter, Depends\n"
                "router = APIRouter()\n\n"
                "@router.post('/orders')\n"
                "def create_order(token: str = Depends(oauth2_scheme)):\n"
                "    payload = verify_token(token)\n"
                "    tenant_id_context = payload['tenant_id']\n"
                "    db_session.where(tenant_id=tenant_id_context)\n"
                "    return {'status': 'created'}\n"
            )
        },
        "description": "FastAPI endpoint extracting tenant identity from cryptographically verified token"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["CLIENT_CONTROLLED_AUTH_HEADER"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_fastapi_verified_token",
        "human_authored_explanation": "Tenant context is derived from verify_token cryptographic verification, which is safe."
    },
    "tags": ["auth", "tenant-isolation", "clean"]
})

cases.append({
    "case_id": "SEC-AUTH-01C",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-AUTH-01",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/routes/orders.py": (
                "from fastapi import APIRouter, Header\n"
                "router = APIRouter()\n\n"
                "@router.post('/orders')\n"
                "def create_order(x_tenant_id: str = Header(..., alias='X-Tenant-Id')):\n"
                "    # Log request tenant for diagnostic tracing only\n"
                "    logger.info(f'Diagnostic tenant trace: {x_tenant_id}')\n"
                "    return {'status': 'created'}\n"
            )
        },
        "description": "FastAPI endpoint using header only for logging, not in isolation or query filters"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["CLIENT_CONTROLLED_AUTH_HEADER"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_fastapi_trace_header",
        "human_authored_explanation": "X-Tenant-Id is read only for logger message, not used as database filter or authorization predicate."
    },
    "tags": ["auth", "logging", "clean"]
})

cases.append({
    "case_id": "SEC-AUTH-01D",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-AUTH-01",
    "category": "SECURITY",
    "difficulty": "HARD",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/routes/orders.py": (
                "from fastapi import APIRouter, Request\n"
                "router = APIRouter()\n\n"
                "@router.post('/orders')\n"
                "def create_order(request: Request):\n"
                "    # Tenant context resolved by external dynamic provider\n"
                "    ctx = resolve_opaque_context(request)\n"
                "    return {'status': 'created'}\n"
            )
        },
        "description": "FastAPI endpoint with unresolved external context provider; evidence is ambiguous"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["CLIENT_CONTROLLED_AUTH_HEADER"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "synthetic_ambiguous_context_provider",
        "human_authored_explanation": "Dynamic context resolver hides header reads; cannot establish vulnerability or safety with static evidence."
    },
    "tags": ["auth", "ambiguous", "unknown"]
})

# Family 2: SEC-AUTH-02 (FastAPI role/authorization header client-controlled) - DEV
cases.append({
    "case_id": "SEC-AUTH-02A",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-AUTH-02",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/routes/admin.py": (
                "from fastapi import APIRouter, Request\n"
                "router = APIRouter()\n\n"
                "@router.delete('/admin/users/{user_id}')\n"
                "def delete_user(user_id: str, request: Request):\n"
                "    role = request.headers.get('X-User-Role')\n"
                "    if 'admin' in role.split(','):\n"
                "        execute_delete(user_id)\n"
                "    return {'deleted': user_id}\n"
            )
        },
        "description": "FastAPI endpoint using client request header to enforce authorization"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["CLIENT_CONTROLLED_AUTH_HEADER"],
        "claims": [{
            "rule_id": "CLIENT_CONTROLLED_AUTH_HEADER",
            "permitted_files": ["app/routes/admin.py"],
            "permitted_symbols": ["delete_user"],
            "permitted_spans": [[5, 9]],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "CRITICAL"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_fastapi_role_header",
        "human_authored_explanation": "X-User-Role header read directly from request and used in authorization check without cryptographic signature."
    },
    "tags": ["auth", "authorization", "fastapi"]
})

cases.append({
    "case_id": "SEC-AUTH-02B",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-AUTH-02",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/routes/admin.py": (
                "from fastapi import APIRouter, Depends\n"
                "router = APIRouter()\n\n"
                "@router.delete('/admin/users/{user_id}')\n"
                "def delete_user(user_id: str, user = Depends(get_current_user)):\n"
                "    if 'admin' in user.roles:\n"
                "        execute_delete(user_id)\n"
                "    return {'deleted': user_id}\n"
            )
        },
        "description": "FastAPI admin endpoint deriving roles from verified get_current_user dependency"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["CLIENT_CONTROLLED_AUTH_HEADER"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_fastapi_verified_user",
        "human_authored_explanation": "Authorization relies on get_current_user dependency, which is safe."
    },
    "tags": ["auth", "authorization", "clean"]
})

cases.append({
    "case_id": "SEC-AUTH-02C",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-AUTH-02",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/routes/admin.py": (
                "from fastapi import APIRouter, Request\n"
                "router = APIRouter()\n\n"
                "@router.get('/health/role')\n"
                "def get_role_probe(request: Request):\n"
                "    # Echo header purely for frontend diagnostic badge\n"
                "    raw_val = request.headers.get('X-User-Role')\n"
                "    return {'echo': raw_val}\n"
            )
        },
        "description": "FastAPI endpoint echoing header with zero authorization logic"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["CLIENT_CONTROLLED_AUTH_HEADER"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_fastapi_echo_header",
        "human_authored_explanation": "Echoing header does not gate access to resources or operations."
    },
    "tags": ["auth", "clean"]
})

cases.append({
    "case_id": "SEC-AUTH-02D",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-AUTH-02",
    "category": "SECURITY",
    "difficulty": "HARD",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/routes/admin.py": (
                "from fastapi import APIRouter, Request\n"
                "router = APIRouter()\n\n"
                "@router.post('/admin/action')\n"
                "def execute_action(request: Request):\n"
                "    # Role verification delegated to upstream middleware\n"
                "    check_permission_header(request.headers)\n"
                "    return {'status': 'ok'}\n"
            )
        },
        "description": "FastAPI endpoint delegating check to helper whose implementation is not visible"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["CLIENT_CONTROLLED_AUTH_HEADER"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "synthetic_ambiguous_helper",
        "human_authored_explanation": "Cannot determine whether check_permission_header validates tokens or merely passes unverified header."
    },
    "tags": ["auth", "ambiguous", "unknown"]
})

# Family 3: SEC-CRED-01 (IaC YAML hardcoded secret API key) - DEV
cases.append({
    "case_id": "SEC-CRED-01A",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CRED-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["yaml"],
    "fixture": {
        "files": {
            "deploy/config.yaml": (
                "# Deployment configuration\n"
                "app:\n"
                "  name: payment-service\n"
                "  api_key: \"live_sk_94827104928174918237\"\n"
            )
        },
        "description": "YAML configuration containing literal secret API key"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HARDCODED_CREDENTIAL"],
        "claims": [{
            "rule_id": "HARDCODED_CREDENTIAL",
            "permitted_files": ["deploy/config.yaml"],
            "permitted_spans": [[4, 4]],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_yaml_secret",
        "human_authored_explanation": "Fixed literal credential assigned to sensitive key api_key in yaml configuration."
    },
    "tags": ["secret", "config", "yaml"]
})

cases.append({
    "case_id": "SEC-CRED-01B",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CRED-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["yaml"],
    "fixture": {
        "files": {
            "deploy/config.yaml": (
                "# Deployment configuration\n"
                "app:\n"
                "  name: payment-service\n"
                "  api_key: \"${PAYMENT_API_KEY}\"\n"
            )
        },
        "description": "YAML configuration referencing environment variable placeholder"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HARDCODED_CREDENTIAL"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_yaml_env_ref",
        "human_authored_explanation": "${PAYMENT_API_KEY} is an environment variable reference, not a hardcoded secret."
    },
    "tags": ["secret", "config", "clean"]
})

cases.append({
    "case_id": "SEC-CRED-01C",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CRED-01",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["yaml"],
    "fixture": {
        "files": {
            "deploy/config.yaml": (
                "# Deployment configuration\n"
                "app:\n"
                "  name: payment-service\n"
                "  api_key: \"changeme_dummy_key\"\n"
            )
        },
        "description": "YAML configuration using dummy changeme placeholder"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HARDCODED_CREDENTIAL"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_yaml_placeholder",
        "human_authored_explanation": "changeme_dummy_key is an obvious template placeholder recognized by secret filters."
    },
    "tags": ["secret", "config", "clean"]
})

cases.append({
    "case_id": "SEC-CRED-01D",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CRED-01",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["yaml"],
    "fixture": {
        "files": {
            "deploy/config.yaml": (
                "# Deployment configuration\n"
                "app:\n"
                "  name: payment-service\n"
                "  # api_key: \"live_sk_94827104928174918237\"\n"
                "  api_key_ref: secretmanager.v1\n"
            )
        },
        "description": "YAML configuration with commented out secret key and secret manager reference"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HARDCODED_CREDENTIAL"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_yaml_commented_secret",
        "human_authored_explanation": "Commented line does not constitute active configuration."
    },
    "tags": ["secret", "config", "clean"]
})

# Family 4: SEC-CRED-02 (Terraform .tf hardcoded database password) - DEV
cases.append({
    "case_id": "SEC-CRED-02A",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CRED-02",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["tf"],
    "fixture": {
        "files": {
            "terraform/db.tf": (
                "resource \"aws_db_instance\" \"default\" {\n"
                "  allocated_storage = 20\n"
                "  engine            = \"postgres\"\n"
                "  username          = \"dbadmin\"\n"
                "  password          = \"SuperSecretMasterPassword123!\"\n"
                "}\n"
            )
        },
        "description": "Terraform resource with hardcoded plaintext database password"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HARDCODED_CREDENTIAL"],
        "claims": [{
            "rule_id": "HARDCODED_CREDENTIAL",
            "permitted_files": ["terraform/db.tf"],
            "permitted_spans": [[5, 5]],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_terraform_secret",
        "human_authored_explanation": "Literal plaintext password in terraform resource."
    },
    "tags": ["secret", "terraform", "iac"]
})

cases.append({
    "case_id": "SEC-CRED-02B",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CRED-02",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["tf"],
    "fixture": {
        "files": {
            "terraform/db.tf": (
                "resource \"aws_db_instance\" \"default\" {\n"
                "  allocated_storage = 20\n"
                "  engine            = \"postgres\"\n"
                "  username          = \"dbadmin\"\n"
                "  password          = var.db_master_password\n"
                "}\n"
            )
        },
        "description": "Terraform resource referencing input variable for password"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HARDCODED_CREDENTIAL"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_terraform_var_ref",
        "human_authored_explanation": "var.db_master_password is an input variable reference, not a hardcoded secret."
    },
    "tags": ["secret", "terraform", "clean"]
})

cases.append({
    "case_id": "SEC-CRED-02C",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CRED-02",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "STATIC_FINDING",
    "benchmark_languages": ["tf"],
    "fixture": {
        "files": {
            "terraform/db.tf": (
                "resource \"aws_db_instance\" \"default\" {\n"
                "  allocated_storage = 20\n"
                "  engine            = \"postgres\"\n"
                "  username          = \"dbadmin\"\n"
                "  password          = data.aws_secretsmanager_secret_version.db_pwd.secret_string\n"
                "}\n"
            )
        },
        "description": "Terraform resource referencing secret manager data source"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HARDCODED_CREDENTIAL"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_terraform_secretsmanager",
        "human_authored_explanation": "data source reference from secretsmanager is secure."
    },
    "tags": ["secret", "terraform", "clean"]
})

# Family 5: SEC-SQLI-01 (Python SQLite f-string query formatting) - DEV
cases.append({
    "case_id": "SEC-SQLI-01A",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-SQLI-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/db/query.py": (
                "import sqlite3\n\n"
                "def search_accounts(user_input: str):\n"
                "    conn = sqlite3.connect('app.db')\n"
                "    cursor = conn.cursor()\n"
                "    query = f\"SELECT * FROM accounts WHERE name = '{user_input}'\"\n"
                "    cursor.execute(query)\n"
                "    return cursor.fetchall()\n"
            )
        },
        "description": "Direct string interpolation into SQL query string passed to execute"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_SQLI"],
        "claims": [{
            "rule_id": "INTERPROCEDURAL_FLOW_SQLI",
            "permitted_files": ["app/db/query.py"],
            "permitted_symbols": ["search_accounts"],
            "permitted_spans": [[3, 8]],
            "required_structural_facts": {
                "sink_kind": "INPUT_TO_DATABASE",
                "flow_required": True
            },
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_sqli_sqlite",
        "human_authored_explanation": "User input interpolated into SQL query string and passed to cursor.execute sink without parameterization."
    },
    "tags": ["sqli", "database", "python"]
})

cases.append({
    "case_id": "SEC-SQLI-01B",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-SQLI-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/db/query.py": (
                "import sqlite3\n\n"
                "def search_accounts(user_input: str):\n"
                "    conn = sqlite3.connect('app.db')\n"
                "    cursor = conn.cursor()\n"
                "    query = \"SELECT * FROM accounts WHERE name = ?\"\n"
                "    cursor.execute(query, (user_input,))\n"
                "    return cursor.fetchall()\n"
            )
        },
        "description": "Safe parameterized SQLite query using placeholder tuple"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_SQLI"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_sqli_parameterized",
        "human_authored_explanation": "Parameterized query eliminates SQL injection risk."
    },
    "tags": ["sqli", "database", "clean"]
})

cases.append({
    "case_id": "SEC-SQLI-01C",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-SQLI-01",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/db/query.py": (
                "import sqlite3\n\n"
                "def search_accounts(user_input: str):\n"
                "    # Static constant query with zero input formatting\n"
                "    conn = sqlite3.connect('app.db')\n"
                "    cursor = conn.cursor()\n"
                "    cursor.execute('SELECT id, name FROM accounts ORDER BY name')\n"
                "    return cursor.fetchall()\n"
            )
        },
        "description": "Static SQL query without formatting or user input concatenation"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_SQLI"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_sqli_constant_query",
        "human_authored_explanation": "Literal constant query without parameters."
    },
    "tags": ["sqli", "database", "clean"]
})

cases.append({
    "case_id": "SEC-SQLI-01D",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-SQLI-01",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/db/query.py": (
                "import sqlite3\n\n"
                "def search_accounts(user_input: str):\n"
                "    # Misleading comment: SQL injection vulnerability test\n"
                "    conn = sqlite3.connect('app.db')\n"
                "    cursor = conn.cursor()\n"
                "    query = \"SELECT * FROM accounts WHERE id = ?\"\n"
                "    cursor.execute(query, (int(user_input),))\n"
                "    return cursor.fetchall()\n"
            )
        },
        "description": "Safe parameterized query with misleading vulnerability comment"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_SQLI"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_sqli_comment_adversarial",
        "human_authored_explanation": "Comment says vulnerability but implementation is safely parameterized."
    },
    "tags": ["sqli", "adversarial", "clean"]
})

# Family 6: SEC-CMDI-01 (Python subprocess command injection) - DEV
cases.append({
    "case_id": "SEC-CMDI-01A",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CMDI-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/utils/network.py": (
                "import subprocess\n\n"
                "def ping_host(host_address: str):\n"
                "    cmd = f'ping -c 1 {host_address}'\n"
                "    return subprocess.run(cmd, shell=True, check=False)\n"
            )
        },
        "description": "Command string formatted with user parameter and executed via shell=True"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_CMDI"],
        "claims": [{
            "rule_id": "INTERPROCEDURAL_FLOW_CMDI",
            "permitted_files": ["app/utils/network.py"],
            "permitted_symbols": ["ping_host"],
            "permitted_spans": [[3, 5]],
            "required_structural_facts": {
                "sink_kind": "INPUT_TO_COMMAND",
                "flow_required": True
            },
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_cmdi_subprocess",
        "human_authored_explanation": "Arbitrary command injection via shell=True and untrusted argument concatenation."
    },
    "tags": ["cmdi", "command-injection", "python"]
})

cases.append({
    "case_id": "SEC-CMDI-01B",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CMDI-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/utils/network.py": (
                "import subprocess\n\n"
                "def ping_host(host_address: str):\n"
                "    # Safe argument array without shell execution\n"
                "    return subprocess.run(['ping', '-c', '1', host_address], check=False)\n"
            )
        },
        "description": "Safe subprocess invocation using explicit argument list without shell"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_CMDI"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_cmdi_safe_array",
        "human_authored_explanation": "Passing command as argument list prevents shell command interpretation."
    },
    "tags": ["cmdi", "clean"]
})

cases.append({
    "case_id": "SEC-CMDI-01C",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CMDI-01",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/utils/network.py": (
                "import subprocess\n\n"
                "def get_system_uptime():\n"
                "    # Literal constant command\n"
                "    return subprocess.run(['uptime'], capture_output=True, check=False)\n"
            )
        },
        "description": "Safe constant command invocation"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_CMDI"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_cmdi_constant",
        "human_authored_explanation": "Constant command with zero variable inputs."
    },
    "tags": ["cmdi", "clean"]
})

cases.append({
    "case_id": "SEC-CMDI-01D",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-CMDI-01",
    "category": "SECURITY",
    "difficulty": "HARD",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/utils/network.py": (
                "import subprocess\n\n"
                "def execute_task(task_spec):\n"
                "    # External sanitizer cleans command string\n"
                "    clean = sanitize_external_command(task_spec)\n"
                "    return subprocess.run(clean, shell=True)\n"
            )
        },
        "description": "Subprocess call with unknown external sanitizer function"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_CMDI"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "synthetic_cmdi_ambiguous_sanitizer",
        "human_authored_explanation": "Unresolved external sanitizer cannot be verified statically."
    },
    "tags": ["cmdi", "ambiguous", "unknown"]
})

# Family 7: SEC-SQLI-02 (PostgreSQL cursor raw query flow) - FROZEN_PUBLIC_EVAL
cases.append({
    "case_id": "SEC-SQLI-02A",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-SQLI-02",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "services/customer_db.py": (
                "def find_customers_by_domain(domain_str: str, cursor):\n"
                "    sql = \"SELECT id, email FROM customers WHERE email LIKE '%\" + domain_str + \"%'\"\n"
                "    cursor.execute(sql)\n"
                "    return cursor.fetchall()\n"
            )
        },
        "description": "String concatenation inside helper function passed to database execute"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_SQLI"],
        "claims": [{
            "rule_id": "INTERPROCEDURAL_FLOW_SQLI",
            "permitted_files": ["services/customer_db.py"],
            "permitted_symbols": ["find_customers_by_domain"],
            "permitted_spans": [[1, 4]],
            "required_structural_facts": {
                "sink_kind": "INPUT_TO_DATABASE",
                "flow_required": True
            },
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_sqli_pg",
        "human_authored_explanation": "SQL query built via string concatenation and executed on cursor without parameterization."
    },
    "tags": ["sqli", "frozen-eval", "python"]
})

cases.append({
    "case_id": "SEC-SQLI-02B",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-SQLI-02",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "services/customer_db.py": (
                "def find_customers_by_domain(domain_str: str, cursor):\n"
                "    sql = \"SELECT id, email FROM customers WHERE email LIKE %s\"\n"
                "    cursor.execute(sql, (f'%{domain_str}%',))\n"
                "    return cursor.fetchall()\n"
            )
        },
        "description": "Safe PostgreSQL parameterized query with %s placeholder"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_SQLI"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_sqli_pg_param",
        "human_authored_explanation": "Query uses %s placeholder and parameter tuple."
    },
    "tags": ["sqli", "frozen-eval", "clean"]
})

cases.append({
    "case_id": "SEC-SQLI-02C",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-SQLI-02",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "services/customer_db.py": (
                "def log_and_fetch_stats(domain_str: str, cursor):\n"
                "    # Formats message for audit logger, does not execute formatted string on DB\n"
                "    audit_log = f'Auditing query for {domain_str}'\n"
                "    cursor.execute('SELECT COUNT(*) FROM customers')\n"
                "    return cursor.fetchone()\n"
            )
        },
        "description": "String formatting used for audit log while database runs constant query"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_SQLI"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_sqli_audit_log",
        "human_authored_explanation": "The formatted string flows to a log variable, not the database execute sink."
    },
    "tags": ["sqli", "frozen-eval", "clean"]
})

cases.append({
    "case_id": "SEC-SQLI-02D",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-SQLI-02",
    "category": "SECURITY",
    "difficulty": "HARD",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "services/customer_db.py": (
                "def dispatch_query(table_name: str, cursor):\n"
                "    # Dynamic query builder imported from external package\n"
                "    sql = external_query_builder(table_name)\n"
                "    cursor.execute(sql)\n"
                "    return cursor.fetchall()\n"
            )
        },
        "description": "Query string created by external builder whose implementation is unavailable"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_SQLI"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "novel_frozen_sqli_external_builder",
        "human_authored_explanation": "External query builder cannot be evaluated statically."
    },
    "tags": ["sqli", "frozen-eval", "unknown"]
})

# Family 8: SEC-PATH-01 (Python open() path traversal) - FROZEN_PUBLIC_EVAL
cases.append({
    "case_id": "SEC-PATH-01A",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-PATH-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/storage/reader.py": (
                "import os\n\n"
                "def read_user_asset(filename: str):\n"
                "    target_path = os.path.join('/var/app/uploads', filename)\n"
                "    with open(target_path, 'r') as f:\n"
                "        return f.read()\n"
            )
        },
        "description": "User controlled filename joined with upload path and passed directly to open()"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_PATH_TRAVERSAL"],
        "claims": [{
            "rule_id": "INTERPROCEDURAL_FLOW_PATH_TRAVERSAL",
            "permitted_files": ["app/storage/reader.py"],
            "permitted_symbols": ["read_user_asset"],
            "permitted_spans": [[3, 6]],
            "required_structural_facts": {
                "sink_kind": "INPUT_TO_FILESYSTEM",
                "flow_required": True
            },
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_path_traversal",
        "human_authored_explanation": "Unsanitized file path reaches filesystem sink open() allowing directory traversal."
    },
    "tags": ["path-traversal", "filesystem", "frozen-eval"]
})

cases.append({
    "case_id": "SEC-PATH-01B",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-PATH-01",
    "category": "SECURITY",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/storage/reader.py": (
                "from app.core.path_confinement import resolve_safe_path\n\n"
                "def read_user_asset(filename: str):\n"
                "    safe_path = resolve_safe_path('/var/app/uploads', filename)\n"
                "    with open(safe_path, 'r') as f:\n"
                "        return f.read()\n"
            )
        },
        "description": "Path confined using resolve_safe_path sanitizer before filesystem open"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_PATH_TRAVERSAL"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_path_safe_sanitizer",
        "human_authored_explanation": "resolve_safe_path confines the target path to the root directory."
    },
    "tags": ["path-traversal", "clean", "frozen-eval"]
})

cases.append({
    "case_id": "SEC-PATH-01C",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-PATH-01",
    "category": "SECURITY",
    "difficulty": "MEDIUM",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/storage/reader.py": (
                "def read_system_manifest():\n"
                "    # Static file read with fixed constant path\n"
                "    with open('/var/app/config/manifest.json', 'r') as f:\n"
                "        return f.read()\n"
            )
        },
        "description": "Filesystem read of constant path without parameters"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_PATH_TRAVERSAL"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_path_constant",
        "human_authored_explanation": "Fixed constant path cannot be manipulated by untrusted input."
    },
    "tags": ["path-traversal", "clean", "frozen-eval"]
})

cases.append({
    "case_id": "SEC-PATH-01D",
    "benchmark_version": "1.0.0",
    "case_family": "SEC-PATH-01",
    "category": "SECURITY",
    "difficulty": "HARD",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/storage/reader.py": (
                "def read_storage_entry(opaque_id: str):\n"
                "    # Sanitization happens in external C extension or opaque provider\n"
                "    resolved = c_ext_resolve_path(opaque_id)\n"
                "    with open(resolved, 'r') as f:\n"
                "        return f.read()\n"
            )
        },
        "description": "Path resolution delegated to opaque C extension"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["INTERPROCEDURAL_FLOW_PATH_TRAVERSAL"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "novel_frozen_path_opaque_ext",
        "human_authored_explanation": "Opaque C extension behavior cannot be determined statically."
    },
    "tags": ["path-traversal", "unknown", "frozen-eval"]
})

# =========================================================================
# 2. CORRECTNESS FAMILIES
# =========================================================================

# Family 9: BUG-EXCEPT-01 (Broad exception swallowing in Python transaction) - DEV
cases.append({
    "case_id": "BUG-EXCEPT-01A",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-EXCEPT-01",
    "category": "CORRECTNESS",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/services/payment.py": (
                "def process_transaction(account_id: str, amount: float):\n"
                "    try:\n"
                "        ledger.charge(account_id, amount)\n"
                "    except Exception:\n"
                "        pass\n"
            )
        },
        "description": "Broad exception handler with bare pass statement swallowing failure"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BROAD_EXCEPTION_SWALLOW"],
        "claims": [{
            "rule_id": "BROAD_EXCEPTION_SWALLOW",
            "permitted_files": ["app/services/payment.py"],
            "permitted_symbols": ["process_transaction"],
            "permitted_spans": [[4, 5]],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "MEDIUM"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_broad_except_pass",
        "human_authored_explanation": "except Exception with pass body completely suppresses payment errors without recovery."
    },
    "tags": ["correctness", "exceptions", "python"]
})

cases.append({
    "case_id": "BUG-EXCEPT-01B",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-EXCEPT-01",
    "category": "CORRECTNESS",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/services/payment.py": (
                "def process_transaction(account_id: str, amount: float):\n"
                "    try:\n"
                "        ledger.charge(account_id, amount)\n"
                "    except PaymentGatewayTimeout as exc:\n"
                "        logger.error(f'Gateway timeout for {account_id}: {exc}')\n"
                "        raise\n"
            )
        },
        "description": "Targeted exception handler logging error and re-raising"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BROAD_EXCEPTION_SWALLOW"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_targeted_except_reraise",
        "human_authored_explanation": "Targeted exception type logged and re-raised."
    },
    "tags": ["correctness", "clean"]
})

cases.append({
    "case_id": "BUG-EXCEPT-01C",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-EXCEPT-01",
    "category": "CORRECTNESS",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/services/payment.py": (
                "def clean_temporary_cache(cache_path: str):\n"
                "    # Safe suppression of non-existent file on cleanup\n"
                "    try:\n"
                "        os.remove(cache_path)\n"
                "    except FileNotFoundError:\n"
                "        pass\n"
            )
        },
        "description": "Safe suppression of specific FileNotFoundError on optional cache"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BROAD_EXCEPTION_SWALLOW"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_specific_file_not_found",
        "human_authored_explanation": "Specific exception type FileNotFoundError is legitimately ignorable."
    },
    "tags": ["correctness", "clean"]
})

cases.append({
    "case_id": "BUG-EXCEPT-01D",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-EXCEPT-01",
    "category": "CORRECTNESS",
    "difficulty": "HARD",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/services/payment.py": (
                "def execute_with_fallback(action_spec):\n"
                "    try:\n"
                "        return perform_action(action_spec)\n"
                "    except:\n"
                "        return dynamic_fallback_handler(action_spec)\n"
            )
        },
        "description": "Bare except delegating to opaque fallback handler function"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BROAD_EXCEPTION_SWALLOW"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "synthetic_ambiguous_fallback_except",
        "human_authored_explanation": "Cannot determine statically if dynamic_fallback_handler properly records or recovers."
    },
    "tags": ["correctness", "unknown"]
})

# Family 10: BUG-ASYNC-BLOCK-01 (Blocking calls in async function) - DEV
cases.append({
    "case_id": "BUG-ASYNC-BLOCK-01A",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-ASYNC-BLOCK-01",
    "category": "CORRECTNESS",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/workers/event_consumer.py": (
                "import time\n\n"
                "async def handle_incoming_message(message_data: dict):\n"
                "    # Blocking call inside event loop\n"
                "    time.sleep(2.0)\n"
                "    return {'processed': True}\n"
            )
        },
        "description": "time.sleep() blocking the asyncio event loop inside async def"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLOCKING_API_IN_ASYNC"],
        "claims": [{
            "rule_id": "BLOCKING_API_IN_ASYNC",
            "permitted_files": ["app/workers/event_consumer.py"],
            "permitted_symbols": ["handle_incoming_message"],
            "permitted_spans": [[3, 6]],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "MEDIUM"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_async_blocking_sleep",
        "human_authored_explanation": "time.sleep blocks the single-threaded asyncio event loop preventing concurrent request processing."
    },
    "tags": ["correctness", "async", "python"]
})

cases.append({
    "case_id": "BUG-ASYNC-BLOCK-01B",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-ASYNC-BLOCK-01",
    "category": "CORRECTNESS",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/workers/event_consumer.py": (
                "import asyncio\n\n"
                "async def handle_incoming_message(message_data: dict):\n"
                "    # Non-blocking async sleep\n"
                "    await asyncio.sleep(2.0)\n"
                "    return {'processed': True}\n"
            )
        },
        "description": "Proper non-blocking await asyncio.sleep()"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLOCKING_API_IN_ASYNC"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_async_safe_sleep",
        "human_authored_explanation": "await asyncio.sleep yields control back to event loop safely."
    },
    "tags": ["correctness", "async", "clean"]
})

cases.append({
    "case_id": "BUG-ASYNC-BLOCK-01C",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-ASYNC-BLOCK-01",
    "category": "CORRECTNESS",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/workers/event_consumer.py": (
                "import time\n\n"
                "def synchronous_worker_routine(item_id: str):\n"
                "    # Blocking call is safe in dedicated synchronous worker process\n"
                "    time.sleep(2.0)\n"
                "    return {'done': item_id}\n"
            )
        },
        "description": "time.sleep() in standard synchronous function"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLOCKING_API_IN_ASYNC"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_sync_time_sleep",
        "human_authored_explanation": "time.sleep is completely valid in synchronous routines."
    },
    "tags": ["correctness", "clean"]
})

cases.append({
    "case_id": "BUG-ASYNC-BLOCK-01D",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-ASYNC-BLOCK-01",
    "category": "CORRECTNESS",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/workers/event_consumer.py": (
                "async def handle_incoming_message(message_data: dict):\n"
                "    # Non-blocking async calculation\n"
                "    total = sum(message_data.get('items', []))\n"
                "    return {'total': total}\n"
            )
        },
        "description": "Pure in-memory computation in async function"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLOCKING_API_IN_ASYNC"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_async_cpu_pure",
        "human_authored_explanation": "In-memory list comprehension is safe in async function."
    },
    "tags": ["correctness", "clean"]
})

# Family 11: BUG-UNAWAITED-01 (Unawaited async call in same file) - DEV
cases.append({
    "case_id": "BUG-UNAWAITED-01A",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-UNAWAITED-01",
    "category": "CORRECTNESS",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/services/audit.py": (
                "async def log_audit_event(event_name: str):\n"
                "    pass\n\n"
                "async def record_user_login(user_id: str):\n"
                "    # Bug: called without await\n"
                "    log_audit_event('USER_LOGGED_IN')\n"
                "    return {'status': 'ok'}\n"
            )
        },
        "description": "Async function called without await expression"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["UNAWAITED_ASYNC_CALL"],
        "claims": [{
            "rule_id": "UNAWAITED_ASYNC_CALL",
            "permitted_files": ["app/services/audit.py"],
            "permitted_symbols": ["record_user_login"],
            "permitted_spans": [[4, 7]],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "MEDIUM"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_unawaited_async_call",
        "human_authored_explanation": "Calling async function without await creates a coroutine object that is never executed."
    },
    "tags": ["correctness", "async", "python"]
})

cases.append({
    "case_id": "BUG-UNAWAITED-01B",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-UNAWAITED-01",
    "category": "CORRECTNESS",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/services/audit.py": (
                "async def log_audit_event(event_name: str):\n"
                "    pass\n\n"
                "async def record_user_login(user_id: str):\n"
                "    # Correctly awaited\n"
                "    await log_audit_event('USER_LOGGED_IN')\n"
                "    return {'status': 'ok'}\n"
            )
        },
        "description": "Async function properly called with await keyword"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["UNAWAITED_ASYNC_CALL"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_awaited_async_call",
        "human_authored_explanation": "await keyword properly executes the coroutine."
    },
    "tags": ["correctness", "async", "clean"]
})

cases.append({
    "case_id": "BUG-UNAWAITED-01C",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-UNAWAITED-01",
    "category": "CORRECTNESS",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/services/audit.py": (
                "def sync_log_audit_event(event_name: str):\n"
                "    pass\n\n"
                "def record_user_login(user_id: str):\n"
                "    sync_log_audit_event('USER_LOGGED_IN')\n"
                "    return {'status': 'ok'}\n"
            )
        },
        "description": "Synchronous functions called synchronously"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["UNAWAITED_ASYNC_CALL"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "synthetic_sync_calls",
        "human_authored_explanation": "Neither function is async."
    },
    "tags": ["correctness", "clean"]
})

cases.append({
    "case_id": "BUG-UNAWAITED-01D",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-UNAWAITED-01",
    "category": "CORRECTNESS",
    "difficulty": "HARD",
    "split": "DEV",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "app/services/audit.py": (
                "import asyncio\n\n"
                "async def log_audit_event(event_name: str):\n"
                "    pass\n\n"
                "def record_user_login(user_id: str):\n"
                "    # Coroutine passed to external scheduler; static status is ambiguous\n"
                "    coro = log_audit_event('USER_LOGGED_IN')\n"
                "    custom_external_scheduler.schedule(coro)\n"
                "    return {'status': 'scheduled'}\n"
            )
        },
        "description": "Coroutine passed to opaque external scheduler"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["UNAWAITED_ASYNC_CALL"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "synthetic_opaque_scheduler",
        "human_authored_explanation": "Cannot determine statically if custom_external_scheduler awaits the coroutine or drops it."
    },
    "tags": ["correctness", "unknown"]
})

# Family 12: BUG-EXCEPT-02 (Bare except: pass in cache) - FROZEN_PUBLIC_EVAL
cases.append({
    "case_id": "BUG-EXCEPT-02A",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-EXCEPT-02",
    "category": "CORRECTNESS",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "core/caching/memcache.py": (
                "def invalidate_user_session(session_id: str):\n"
                "    try:\n"
                "        cache_client.delete(session_id)\n"
                "    except:\n"
                "        pass\n"
            )
        },
        "description": "Bare except: pass swallowing all exceptions during session cache invalidation"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BROAD_EXCEPTION_SWALLOW"],
        "claims": [{
            "rule_id": "BROAD_EXCEPTION_SWALLOW",
            "permitted_files": ["core/caching/memcache.py"],
            "permitted_symbols": ["invalidate_user_session"],
            "permitted_spans": [[4, 5]],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "MEDIUM"
        }],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_bare_except",
        "human_authored_explanation": "Bare except with pass statement completely swallows unexpected errors."
    },
    "tags": ["correctness", "frozen-eval", "python"]
})

cases.append({
    "case_id": "BUG-EXCEPT-02B",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-EXCEPT-02",
    "category": "CORRECTNESS",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "core/caching/memcache.py": (
                "def invalidate_user_session(session_id: str):\n"
                "    try:\n"
                "        cache_client.delete(session_id)\n"
                "    except CacheConnectionError as err:\n"
                "        logger.warning(f'Cache unavailable during invalidation: {err}')\n"
            )
        },
        "description": "Specific CacheConnectionError caught and logged"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BROAD_EXCEPTION_SWALLOW"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_targeted_cache_error",
        "human_authored_explanation": "Targeted exception handled with logging."
    },
    "tags": ["correctness", "frozen-eval", "clean"]
})

cases.append({
    "case_id": "BUG-EXCEPT-02C",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-EXCEPT-02",
    "category": "CORRECTNESS",
    "difficulty": "MEDIUM",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "core/caching/memcache.py": (
                "def invalidate_user_session(session_id: str):\n"
                "    # Direct call without try/except\n"
                "    cache_client.delete(session_id)\n"
            )
        },
        "description": "Standard call letting exceptions propagate up the stack"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BROAD_EXCEPTION_SWALLOW"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_no_except",
        "human_authored_explanation": "No exception handling block."
    },
    "tags": ["correctness", "frozen-eval", "clean"]
})

cases.append({
    "case_id": "BUG-EXCEPT-02D",
    "benchmark_version": "1.0.0",
    "case_family": "BUG-EXCEPT-02",
    "category": "CORRECTNESS",
    "difficulty": "MEDIUM",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "REPOSITORY_SCAN",
    "evaluation_stage": "ANALYSIS_CANDIDATE",
    "benchmark_languages": ["python"],
    "fixture": {
        "files": {
            "core/caching/memcache.py": (
                "def invalidate_user_session(session_id: str):\n"
                "    try:\n"
                "        cache_client.delete(session_id)\n"
                "    except Exception as e:\n"
                "        # Comments only in safe logging handler\n"
                "        metrics.increment('cache_invalidation_failures')\n"
                "        raise e\n"
            )
        },
        "description": "Broad exception caught, metric incremented, and re-raised"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BROAD_EXCEPTION_SWALLOW"],
        "claims": [],
        "how_established": "source_code_audit",
        "fixture_source": "novel_frozen_metric_reraise",
        "human_authored_explanation": "Re-raise preserves exception propagation."
    },
    "tags": ["correctness", "frozen-eval", "clean"]
})

# =========================================================================
# 3. CROSS-LAYER CONTRACT FAMILIES
# =========================================================================

# Family 13: CONTRACT-ROUTE-PATH-01 (Route path changed) - DEV
cases.append({
    "case_id": "CONTRACT-ROUTE-PATH-01A",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-ROUTE-PATH-01",
    "category": "CONTRACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/users.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v1/users')\ndef get_users():\n    return []\n"
        },
        "head_files": {
            "app/api/users.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v2/users')\ndef get_users():\n    return []\n"
        },
        "description": "Backend FastAPI route path changed from /api/v1/users to /api/v2/users"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["ROUTE_PATH_MISMATCH"],
        "claims": [{
            "rule_id": "ROUTE_PATH_MISMATCH",
            "permitted_files": ["app/api/users.py"],
            "permitted_symbols": ["get_users"],
            "required_structural_facts": {"change_type": "PATH_CHANGED"},
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_route_path_change",
        "human_authored_explanation": "Breaking route path change emitted by ChangeDiffEngine as PATH_CHANGED delta."
    },
    "tags": ["contract", "route", "diff"]
})

cases.append({
    "case_id": "CONTRACT-ROUTE-PATH-01B",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-ROUTE-PATH-01",
    "category": "CONTRACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/users.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v1/users')\ndef get_users():\n    return []\n"
        },
        "head_files": {
            "app/api/users.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v1/users')\ndef get_users():\n    # Unchanged route definition\n    return [{'id': 1}]\n"
        },
        "description": "Internal handler body changed with zero route path modification"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["ROUTE_PATH_MISMATCH"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_route_path_unchanged",
        "human_authored_explanation": "Route path is unchanged."
    },
    "tags": ["contract", "route", "clean"]
})

cases.append({
    "case_id": "CONTRACT-ROUTE-PATH-01C",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-ROUTE-PATH-01",
    "category": "CONTRACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/users.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v1/users')\ndef get_users():\n    return []\n"
        },
        "head_files": {
            "app/api/users.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v1/users')\ndef get_users():\n    # Formatting update only\n    return []\n"
        },
        "description": "Formatting change in route file"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["ROUTE_PATH_MISMATCH"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_route_formatting",
        "human_authored_explanation": "No route contract delta."
    },
    "tags": ["contract", "route", "clean"]
})

cases.append({
    "case_id": "CONTRACT-ROUTE-PATH-01D",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-ROUTE-PATH-01",
    "category": "CONTRACT",
    "difficulty": "HARD",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/users.py": "from fastapi import APIRouter\nrouter = APIRouter()\nrouter.add_api_route(build_dynamic_path('users'), handler)\n"
        },
        "head_files": {
            "app/api/users.py": "from fastapi import APIRouter\nrouter = APIRouter()\nrouter.add_api_route(build_dynamic_path('users_v2'), handler)\n"
        },
        "description": "Dynamic route path registration using runtime helper"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["ROUTE_PATH_MISMATCH"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "synthetic_dynamic_route_registration",
        "human_authored_explanation": "Dynamic route helper build_dynamic_path cannot be resolved by static AST parser."
    },
    "tags": ["contract", "route", "unknown"]
})

# Family 14: CONTRACT-METHOD-01 (HTTP method changed) - DEV
cases.append({
    "case_id": "CONTRACT-METHOD-01A",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-METHOD-01",
    "category": "CONTRACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/items')\ndef list_items():\n    return []\n"
        },
        "head_files": {
            "app/api/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/api/items')\ndef list_items():\n    return []\n"
        },
        "description": "Endpoint HTTP method changed from GET to POST"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HTTP_METHOD_MISMATCH"],
        "claims": [{
            "rule_id": "HTTP_METHOD_MISMATCH",
            "permitted_files": ["app/api/items.py"],
            "permitted_symbols": ["list_items"],
            "required_structural_facts": {"change_type": "METHOD_CHANGED"},
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_method_change",
        "human_authored_explanation": "Incompatible HTTP method alteration emitted as METHOD_CHANGED."
    },
    "tags": ["contract", "http-method", "diff"]
})

cases.append({
    "case_id": "CONTRACT-METHOD-01B",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-METHOD-01",
    "category": "CONTRACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/api/items')\ndef list_items():\n    return []\n"
        },
        "head_files": {
            "app/api/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/api/items')\ndef list_items():\n    return [{'ok': True}]\n"
        },
        "description": "HTTP method remains POST; only internal logic modified"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HTTP_METHOD_MISMATCH"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_method_unchanged",
        "human_authored_explanation": "No HTTP method delta."
    },
    "tags": ["contract", "http-method", "clean"]
})

cases.append({
    "case_id": "CONTRACT-METHOD-01C",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-METHOD-01",
    "category": "CONTRACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.delete('/api/items/{id}')\ndef delete_item(id: str):\n    pass\n"
        },
        "head_files": {
            "app/api/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.delete('/api/items/{id}')\ndef delete_item(id: str):\n    # docstring added\n    pass\n"
        },
        "description": "Docstring added to unchanged DELETE endpoint"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HTTP_METHOD_MISMATCH"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_method_docstring",
        "human_authored_explanation": "DELETE method unchanged."
    },
    "tags": ["contract", "http-method", "clean"]
})

cases.append({
    "case_id": "CONTRACT-METHOD-01D",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-METHOD-01",
    "category": "CONTRACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/items')\ndef list_items():\n    return []\n"
        },
        "head_files": {
            "app/api/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/items')\ndef list_items():\n    return []\n"
        },
        "description": "Identical base and head files"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["HTTP_METHOD_MISMATCH"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_method_identity",
        "human_authored_explanation": "Zero changes."
    },
    "tags": ["contract", "clean"]
})

# Family 15: CONTRACT-METHOD-PATH-01 (Both method and path changed) - DEV
cases.append({
    "case_id": "CONTRACT-METHOD-PATH-01A",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-METHOD-PATH-01",
    "category": "CONTRACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/orders.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/api/v1/orders')\ndef get_orders():\n    return []\n"
        },
        "head_files": {
            "app/api/orders.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/api/v2/orders')\ndef get_orders():\n    return []\n"
        },
        "description": "Route modified with both method change (GET -> POST) and path change (/v1 -> /v2)"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["ROUTE_METHOD_AND_PATH_CHANGED"],
        "claims": [{
            "rule_id": "ROUTE_METHOD_AND_PATH_CHANGED",
            "permitted_files": ["app/api/orders.py"],
            "permitted_symbols": ["get_orders"],
            "required_structural_facts": {"change_type": "METHOD_AND_PATH_CHANGED"},
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_method_and_path_change",
        "human_authored_explanation": "Simultaneous method and path change emitted as METHOD_AND_PATH_CHANGED delta."
    },
    "tags": ["contract", "route", "diff"]
})

cases.append({
    "case_id": "CONTRACT-METHOD-PATH-01B",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-METHOD-PATH-01",
    "category": "CONTRACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/orders.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/api/v2/orders')\ndef get_orders():\n    return []\n"
        },
        "head_files": {
            "app/api/orders.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/api/v2/orders')\ndef get_orders():\n    return []\n"
        },
        "description": "Route unchanged across base and head"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["ROUTE_METHOD_AND_PATH_CHANGED"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_route_clean",
        "human_authored_explanation": "No change."
    },
    "tags": ["contract", "clean"]
})

cases.append({
    "case_id": "CONTRACT-METHOD-PATH-01C",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-METHOD-PATH-01",
    "category": "CONTRACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/api/orders.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/api/v2/orders')\ndef get_orders():\n    return []\n"
        },
        "head_files": {
            "app/api/orders.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/api/v2/orders')\ndef get_orders():\n    # Response item added\n    return [{'status': 'confirmed'}]\n"
        },
        "description": "Internal implementation updated without route signature break"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["ROUTE_METHOD_AND_PATH_CHANGED"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_route_safe_impl",
        "human_authored_explanation": "Route definition preserved."
    },
    "tags": ["contract", "clean"]
})

# Family 16: CONTRACT-SCHEMA-ADD-01 (Field added to schema) - DEV
cases.append({
    "case_id": "CONTRACT-SCHEMA-ADD-01A",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-SCHEMA-ADD-01",
    "category": "CONTRACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/schemas/user.py": "from pydantic import BaseModel\n\nclass UserCreate(BaseModel):\n    username: str\n"
        },
        "head_files": {
            "app/schemas/user.py": "from pydantic import BaseModel\n\nclass UserCreate(BaseModel):\n    username: str\n    email: str\n"
        },
        "description": "Field email added to UserCreate Pydantic model"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SCHEMA_FIELD_ADDED"],
        "claims": [{
            "rule_id": "SCHEMA_FIELD_ADDED",
            "permitted_files": ["app/schemas/user.py"],
            "permitted_symbols": ["UserCreate"],
            "required_structural_facts": {"change_type": "ADDED_FIELD"},
            "forbidden_structural_facts": {},
            "expected_severity": "LOW"
        }],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_schema_add_field",
        "human_authored_explanation": "Structural schema delta emitted as ADDED_FIELD."
    },
    "tags": ["contract", "schema", "diff"]
})

cases.append({
    "case_id": "CONTRACT-SCHEMA-ADD-01B",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-SCHEMA-ADD-01",
    "category": "CONTRACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/schemas/user.py": "from pydantic import BaseModel\n\nclass UserCreate(BaseModel):\n    username: str\n"
        },
        "head_files": {
            "app/schemas/user.py": "from pydantic import BaseModel\n\nclass UserCreate(BaseModel):\n    username: str\n"
        },
        "description": "Pydantic model unchanged across revisions"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SCHEMA_FIELD_ADDED"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_schema_clean",
        "human_authored_explanation": "Zero schema deltas."
    },
    "tags": ["contract", "schema", "clean"]
})

cases.append({
    "case_id": "CONTRACT-SCHEMA-ADD-01C",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-SCHEMA-ADD-01",
    "category": "CONTRACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/schemas/user.py": "from pydantic import BaseModel\n\nclass UserCreate(BaseModel):\n    username: str\n"
        },
        "head_files": {
            "app/schemas/user.py": "from pydantic import BaseModel\n\nclass UserCreate(BaseModel):\n    # docstring added\n    \"\"\"Model for user creation.\"\"\"\n    username: str\n"
        },
        "description": "Docstring added to Pydantic model with no field modifications"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SCHEMA_FIELD_ADDED"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "phase6_schema_docstring",
        "human_authored_explanation": "Model fields unchanged."
    },
    "tags": ["contract", "schema", "clean"]
})

cases.append({
    "case_id": "CONTRACT-SCHEMA-ADD-01D",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-SCHEMA-ADD-01",
    "category": "CONTRACT",
    "difficulty": "HARD",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/schemas/user.py": "class UserData(dict):\n    pass\n"
        },
        "head_files": {
            "app/schemas/user.py": "class UserData(dict):\n    def __init__(self):\n        self['extra'] = True\n"
        },
        "description": "Plain Python dict subclass modified dynamically rather than declared as Pydantic model"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SCHEMA_FIELD_ADDED"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "synthetic_dynamic_dict_subclass",
        "human_authored_explanation": "Arbitrary dict subclasses without type annotations cannot be resolved as structured Pydantic schema deltas."
    },
    "tags": ["contract", "schema", "unknown"]
})

# Family 17: CONTRACT-SCHEMA-TYPE-01 (Field type modified) - FROZEN_PUBLIC_EVAL
cases.append({
    "case_id": "CONTRACT-SCHEMA-TYPE-01A",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-SCHEMA-TYPE-01",
    "category": "CONTRACT",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "models/billing.py": "from pydantic import BaseModel\n\nclass InvoiceOut(BaseModel):\n    invoice_id: int\n"
        },
        "head_files": {
            "models/billing.py": "from pydantic import BaseModel\n\nclass InvoiceOut(BaseModel):\n    invoice_id: str\n"
        },
        "description": "Field invoice_id type modified from int to str"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SCHEMA_FIELD_TYPE_CHANGED"],
        "claims": [{
            "rule_id": "SCHEMA_FIELD_TYPE_CHANGED",
            "permitted_files": ["models/billing.py"],
            "permitted_symbols": ["InvoiceOut"],
            "required_structural_facts": {"change_type": "MODIFIED_TYPE"},
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "novel_frozen_schema_type_change",
        "human_authored_explanation": "Incompatible schema type modification emitted as MODIFIED_TYPE."
    },
    "tags": ["contract", "schema", "frozen-eval"]
})

cases.append({
    "case_id": "CONTRACT-SCHEMA-TYPE-01B",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-SCHEMA-TYPE-01",
    "category": "CONTRACT",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "models/billing.py": "from pydantic import BaseModel\n\nclass InvoiceOut(BaseModel):\n    invoice_id: str\n"
        },
        "head_files": {
            "models/billing.py": "from pydantic import BaseModel\n\nclass InvoiceOut(BaseModel):\n    invoice_id: str\n"
        },
        "description": "Pydantic model field type unchanged"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SCHEMA_FIELD_TYPE_CHANGED"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "novel_frozen_schema_clean",
        "human_authored_explanation": "Type preserved."
    },
    "tags": ["contract", "clean", "frozen-eval"]
})

cases.append({
    "case_id": "CONTRACT-SCHEMA-TYPE-01C",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-SCHEMA-TYPE-01",
    "category": "CONTRACT",
    "difficulty": "MEDIUM",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "models/billing.py": "from pydantic import BaseModel\n\nclass InvoiceOut(BaseModel):\n    invoice_id: str\n"
        },
        "head_files": {
            "models/billing.py": "from pydantic import BaseModel\n\nclass InvoiceOut(BaseModel):\n    # Formatting only\n    invoice_id: str\n"
        },
        "description": "Whitespace update in model"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SCHEMA_FIELD_TYPE_CHANGED"],
        "claims": [],
        "how_established": "diff_engine_ground_truth",
        "fixture_source": "novel_frozen_schema_ws",
        "human_authored_explanation": "No type modification."
    },
    "tags": ["contract", "clean", "frozen-eval"]
})

cases.append({
    "case_id": "CONTRACT-SCHEMA-TYPE-01D",
    "benchmark_version": "1.0.0",
    "case_family": "CONTRACT-SCHEMA-TYPE-01",
    "category": "CONTRACT",
    "difficulty": "HARD",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "CHANGE_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "models/billing.py": "class CustomModel:\n    raw_type = int\n"
        },
        "head_files": {
            "models/billing.py": "class CustomModel:\n    raw_type = str\n"
        },
        "description": "Custom class variable assignment not using Pydantic or dataclass annotations"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SCHEMA_FIELD_TYPE_CHANGED"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "novel_frozen_schema_custom_class",
        "human_authored_explanation": "Cannot determine if custom raw_type class variable represents a formal schema contract."
    },
    "tags": ["contract", "unknown", "frozen-eval"]
})

# =========================================================================
# 4. CHANGE IMPACT & BLAST RADIUS FAMILIES
# =========================================================================

# Family 18: IMPACT-ISOLATED-01 (Change with 0 external callers) - DEV
cases.append({
    "case_id": "IMPACT-ISOLATED-01A",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-ISOLATED-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/utils/math_helper.py": "def _private_calculate(a: int, b: int) -> int:\n    return a + b\n"
        },
        "head_files": {
            "app/utils/math_helper.py": "def _private_calculate(a: int, b: int) -> int:\n    # Refactored implementation with no external callers\n    val = a + b\n    return val\n"
        },
        "description": "Private helper modified with zero callers anywhere in repository"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "ALL_SUPPORTED",
        "target_rule_ids": [],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_isolated_helper",
        "human_authored_explanation": "Function has 0 callers, blast radius impact count is 0."
    },
    "tags": ["impact", "isolated", "clean"]
})

cases.append({
    "case_id": "IMPACT-ISOLATED-01B",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-ISOLATED-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/utils/math_helper.py": "def _private_calculate(a: int, b: int) -> int:\n    return a + b\n"
        },
        "head_files": {
            "app/utils/math_helper.py": "def _private_calculate(a: int, b: int) -> int:\n    return a + b\n"
        },
        "description": "Zero change across files"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "ALL_SUPPORTED",
        "target_rule_ids": [],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_isolated_clean",
        "human_authored_explanation": "Zero impact facts."
    },
    "tags": ["impact", "clean"]
})

cases.append({
    "case_id": "IMPACT-ISOLATED-01C",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-ISOLATED-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/utils/math_helper.py": "def _private_calculate(a: int, b: int) -> int:\n    return a + b\n"
        },
        "head_files": {
            "app/utils/math_helper.py": "# Docstring added\n\"\"\"Helper module.\"\"\"\ndef _private_calculate(a: int, b: int) -> int:\n    return a + b\n"
        },
        "description": "Module docstring added with zero caller impacts"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "ALL_SUPPORTED",
        "target_rule_ids": [],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_isolated_docstring",
        "human_authored_explanation": "Zero blast radius."
    },
    "tags": ["impact", "clean"]
})

# Family 19: IMPACT-DIRECT-01 (Modified function with exactly 1 direct caller) - DEV
cases.append({
    "case_id": "IMPACT-DIRECT-01A",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DIRECT-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/auth/verifier.py": "def verify_credentials(user_id: str) -> bool:\n    return True\n",
            "app/api/login.py": "from app.auth.verifier import verify_credentials\ndef login_endpoint(user_id: str):\n    if verify_credentials(user_id):\n        return 'ok'\n"
        },
        "head_files": {
            "app/auth/verifier.py": "def verify_credentials(user_id: str) -> bool:\n    # Modified verification logic\n    return len(user_id) > 3\n",
            "app/api/login.py": "from app.auth.verifier import verify_credentials\ndef login_endpoint(user_id: str):\n    if verify_credentials(user_id):\n        return 'ok'\n"
        },
        "description": "verify_credentials modified with exactly one downstream caller in login.py"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_DIRECT_CALLER"],
        "claims": [{
            "rule_id": "BLAST_RADIUS_DIRECT_CALLER",
            "permitted_files": ["app/api/login.py"],
            "permitted_symbols": ["login_endpoint"],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "LOW"
        }],
        "expected_impact_count": 1,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_direct_caller",
        "human_authored_explanation": "ChangeImpactEngine identifies login_endpoint as directly impacted caller."
    },
    "tags": ["impact", "direct-caller", "diff"]
})

cases.append({
    "case_id": "IMPACT-DIRECT-01B",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DIRECT-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/auth/verifier.py": "def verify_credentials(user_id: str) -> bool:\n    return True\n",
            "app/api/login.py": "from app.auth.verifier import verify_credentials\ndef login_endpoint(user_id: str):\n    if verify_credentials(user_id):\n        return 'ok'\n"
        },
        "head_files": {
            "app/auth/verifier.py": "def verify_credentials(user_id: str) -> bool:\n    return True\n",
            "app/api/login.py": "from app.auth.verifier import verify_credentials\ndef login_endpoint(user_id: str):\n    if verify_credentials(user_id):\n        return 'ok'\n"
        },
        "description": "Unchanged caller and callee"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_DIRECT_CALLER"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_direct_caller_clean",
        "human_authored_explanation": "Zero impact facts."
    },
    "tags": ["impact", "clean"]
})

cases.append({
    "case_id": "IMPACT-DIRECT-01C",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DIRECT-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/auth/verifier.py": "def verify_credentials(user_id: str) -> bool:\n    return True\n",
            "app/api/login.py": "from app.auth.verifier import verify_credentials\ndef login_endpoint(user_id: str):\n    if verify_credentials(user_id):\n        return 'ok'\n"
        },
        "head_files": {
            "app/auth/verifier.py": "def verify_credentials(user_id: str) -> bool:\n    return True\n",
            "app/api/login.py": "from app.auth.verifier import verify_credentials\ndef login_endpoint(user_id: str):\n    # doc comment in caller only\n    if verify_credentials(user_id):\n        return 'ok'\n"
        },
        "description": "Callee untouched; comment added to caller only"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_DIRECT_CALLER"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_caller_comment_only",
        "human_authored_explanation": "Callee function verify_credentials did not change."
    },
    "tags": ["impact", "clean"]
})

cases.append({
    "case_id": "IMPACT-DIRECT-01D",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DIRECT-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "HARD",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/auth/verifier.py": "def verify_credentials(user_id: str) -> bool:\n    return True\n",
            "app/api/login.py": "def login_endpoint(user_id: str):\n    # Dynamic getattr call\n    fn = getattr(importlib.import_module('app.auth.verifier'), 'verify_credentials')\n    return fn(user_id)\n"
        },
        "head_files": {
            "app/auth/verifier.py": "def verify_credentials(user_id: str) -> bool:\n    return len(user_id) > 0\n",
            "app/api/login.py": "def login_endpoint(user_id: str):\n    fn = getattr(importlib.import_module('app.auth.verifier'), 'verify_credentials')\n    return fn(user_id)\n"
        },
        "description": "Callee called dynamically via getattr; call edge cannot be resolved statically"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_DIRECT_CALLER"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "synthetic_dynamic_getattr_call",
        "human_authored_explanation": "Static AST parser cannot resolve dynamic getattr import into a repository graph edge."
    },
    "tags": ["impact", "dynamic", "unknown"]
})

# Family 20: IMPACT-MULTI-01 (Shared utility affecting multiple callers) - DEV
cases.append({
    "case_id": "IMPACT-MULTI-01A",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-MULTI-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/common/format.py": "def format_name(first: str, last: str) -> str:\n    return f'{first} {last}'\n",
            "app/services/email.py": "from app.common.format import format_name\ndef send_email(f: str, l: str):\n    return format_name(f, l)\n",
            "app/services/pdf.py": "from app.common.format import format_name\ndef make_pdf(f: str, l: str):\n    return format_name(f, l)\n"
        },
        "head_files": {
            "app/common/format.py": "def format_name(first: str, last: str) -> str:\n    # Uppercased format\n    return f'{last.upper()}, {first}'\n",
            "app/services/email.py": "from app.common.format import format_name\ndef send_email(f: str, l: str):\n    return format_name(f, l)\n",
            "app/services/pdf.py": "from app.common.format import format_name\ndef make_pdf(f: str, l: str):\n    return format_name(f, l)\n"
        },
        "description": "Shared format_name modified affecting two downstream callers (email and pdf)"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_MULTI_CONSUMER"],
        "claims": [{
            "rule_id": "BLAST_RADIUS_MULTI_CONSUMER",
            "permitted_files": ["app/services/email.py", "app/services/pdf.py"],
            "permitted_symbols": ["send_email", "make_pdf"],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "MEDIUM"
        }],
        "expected_impact_count": 2,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_multi_caller",
        "human_authored_explanation": "ChangeImpactEngine computes blast radius reachability affecting multiple downstream callers."
    },
    "tags": ["impact", "multi-caller", "diff"]
})

cases.append({
    "case_id": "IMPACT-MULTI-01B",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-MULTI-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/common/format.py": "def format_name(first: str, last: str) -> str:\n    return f'{first} {last}'\n",
            "app/services/email.py": "from app.common.format import format_name\ndef send_email(f: str, l: str):\n    return format_name(f, l)\n",
            "app/services/pdf.py": "from app.common.format import format_name\ndef make_pdf(f: str, l: str):\n    return format_name(f, l)\n"
        },
        "head_files": {
            "app/common/format.py": "def format_name(first: str, last: str) -> str:\n    return f'{first} {last}'\n",
            "app/services/email.py": "from app.common.format import format_name\ndef send_email(f: str, l: str):\n    return format_name(f, l)\n",
            "app/services/pdf.py": "from app.common.format import format_name\ndef make_pdf(f: str, l: str):\n    return format_name(f, l)\n"
        },
        "description": "Shared helper unchanged across base and head"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_MULTI_CONSUMER"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_multi_caller_clean",
        "human_authored_explanation": "Zero impact facts."
    },
    "tags": ["impact", "clean"]
})

cases.append({
    "case_id": "IMPACT-MULTI-01C",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-MULTI-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/common/format.py": "def format_name(first: str, last: str) -> str:\n    return f'{first} {last}'\n",
            "app/services/email.py": "from app.common.format import format_name\ndef send_email(f: str, l: str):\n    return format_name(f, l)\n",
            "app/services/pdf.py": "from app.common.format import format_name\ndef make_pdf(f: str, l: str):\n    return format_name(f, l)\n"
        },
        "head_files": {
            "app/common/format.py": "def format_name(first: str, last: str) -> str:\n    return f'{first} {last}'\n",
            "app/services/email.py": "from app.common.format import format_name\ndef send_email(f: str, l: str):\n    # docstring in single caller\n    return format_name(f, l)\n",
            "app/services/pdf.py": "from app.common.format import format_name\ndef make_pdf(f: str, l: str):\n    return format_name(f, l)\n"
        },
        "description": "Callee untouched; comment added in single caller only"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_MULTI_CONSUMER"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_multi_caller_comment",
        "human_authored_explanation": "format_name is not modified."
    },
    "tags": ["impact", "clean"]
})

cases.append({
    "case_id": "IMPACT-MULTI-01D",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-MULTI-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/common/format.py": "def format_name(first: str, last: str) -> str:\n    return f'{first} {last}'\n"
        },
        "head_files": {
            "app/common/format.py": "# comments only\ndef format_name(first: str, last: str) -> str:\n    return f'{first} {last}'\n"
        },
        "description": "Comment added to format_name with zero implementation changes"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_MULTI_CONSUMER"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_format_comment",
        "human_authored_explanation": "Symbol implementation unchanged."
    },
    "tags": ["impact", "clean"]
})

# Family 21: IMPACT-DELETED-CALLER-01 (Deleted function with active callers) - DEV
cases.append({
    "case_id": "IMPACT-DELETED-CALLER-01A",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DELETED-CALLER-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/auth.py": "def verify_user(token: str) -> bool:\n    return bool(token)\n",
            "app/api.py": "from app.auth import verify_user\ndef login_endpoint(token: str):\n    if verify_user(token):\n        return True\n"
        },
        "head_files": {
            "app/auth.py": "# verify_user function deleted\ndef helper():\n    pass\n",
            "app/api.py": "from app.auth import verify_user\ndef login_endpoint(token: str):\n    if verify_user(token):\n        return True\n"
        },
        "description": "Function verify_user deleted in auth.py while api.py still imports and calls it"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["DELETED_SYMBOL_WITH_CALLERS"],
        "claims": [{
            "rule_id": "DELETED_SYMBOL_WITH_CALLERS",
            "permitted_files": ["app/api.py"],
            "permitted_symbols": ["login_endpoint"],
            "required_structural_facts": {"impact_type": "CALLER_BROKEN_BY_DELETION"},
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "expected_impact_count": 1,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_deleted_caller",
        "human_authored_explanation": "ChangeImpactEngine detects CALLER_BROKEN_BY_DELETION for login_endpoint."
    },
    "tags": ["impact", "deletion", "diff"]
})

cases.append({
    "case_id": "IMPACT-DELETED-CALLER-01B",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DELETED-CALLER-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/auth.py": "def verify_user(token: str) -> bool:\n    return bool(token)\n",
            "app/api.py": "from app.auth import verify_user\ndef login_endpoint(token: str):\n    if verify_user(token):\n        return True\n"
        },
        "head_files": {
            "app/auth.py": "# verify_user replaced by new_verify\ndef new_verify(token: str) -> bool:\n    return bool(token)\n",
            "app/api.py": "from app.auth import new_verify\ndef login_endpoint(token: str):\n    if new_verify(token):\n        return True\n"
        },
        "description": "Deleted function refactored synchronously across callee and caller"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["DELETED_SYMBOL_WITH_CALLERS"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_deleted_caller_safe_refactor",
        "human_authored_explanation": "Caller in head branch calls new_verify, so no active caller is broken."
    },
    "tags": ["impact", "clean"]
})

cases.append({
    "case_id": "IMPACT-DELETED-CALLER-01C",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DELETED-CALLER-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/auth.py": "def verify_user(token: str) -> bool:\n    return bool(token)\n"
        },
        "head_files": {
            "app/auth.py": "def helper():\n    pass\n"
        },
        "description": "Deleted function that had zero callers in the repository"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["DELETED_SYMBOL_WITH_CALLERS"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_deleted_unused_function",
        "human_authored_explanation": "Function had 0 callers, so deletion breaks no active consumers."
    },
    "tags": ["impact", "clean"]
})

cases.append({
    "case_id": "IMPACT-DELETED-CALLER-01D",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DELETED-CALLER-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "HARD",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/auth.py": "def verify_user(token: str) -> bool:\n    return bool(token)\n",
            "app/api.py": "def login_endpoint(token: str):\n    # Conditional string import\n    mod = __import__('app.auth')\n    return getattr(mod, 'verify_user')(token)\n"
        },
        "head_files": {
            "app/auth.py": "def helper():\n    pass\n",
            "app/api.py": "def login_endpoint(token: str):\n    mod = __import__('app.auth')\n    return getattr(mod, 'verify_user')(token)\n"
        },
        "description": "Caller imports deleted function via __import__ string call"
    },
    "annotation": {
        "expected_verdict": "UNKNOWN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["DELETED_SYMBOL_WITH_CALLERS"],
        "claims": [],
        "how_established": "expert_review",
        "fixture_source": "synthetic_dunder_import_caller",
        "human_authored_explanation": "Static AST builder cannot track dynamic __import__ call."
    },
    "tags": ["impact", "unknown"]
})

# Family 22: IMPACT-SIGNATURE-01 (Required argument added breaking callers) - DEV
cases.append({
    "case_id": "IMPACT-SIGNATURE-01A",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-SIGNATURE-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/billing.py": "def calculate_fee(amount: float) -> float:\n    return amount * 0.05\n",
            "app/checkout.py": "from app.billing import calculate_fee\ndef checkout(amt: float):\n    return calculate_fee(amt)\n"
        },
        "head_files": {
            "app/billing.py": "def calculate_fee(amount: float, tier: str, country: str) -> float:\n    return amount * 0.05\n",
            "app/checkout.py": "from app.billing import calculate_fee\ndef checkout(amt: float):\n    return calculate_fee(amt)\n"
        },
        "description": "calculate_fee adds required arguments tier and country breaking existing caller"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SIGNATURE_BREAK_CALLERS"],
        "claims": [{
            "rule_id": "SIGNATURE_BREAK_CALLERS",
            "permitted_files": ["app/checkout.py"],
            "permitted_symbols": ["checkout"],
            "required_structural_facts": {"impact_type": "SIGNATURE_MISMATCH"},
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "expected_impact_count": 1,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_signature_break",
        "human_authored_explanation": "ChangeImpactEngine detects SIGNATURE_MISMATCH for checkout."
    },
    "tags": ["impact", "signature", "diff"]
})

cases.append({
    "case_id": "IMPACT-SIGNATURE-01B",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-SIGNATURE-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/billing.py": "def calculate_fee(amount: float) -> float:\n    return amount * 0.05\n",
            "app/checkout.py": "from app.billing import calculate_fee\ndef checkout(amt: float):\n    return calculate_fee(amt)\n"
        },
        "head_files": {
            "app/billing.py": "def calculate_fee(amount: float, tier: str = 'standard', country: str = 'US') -> float:\n    return amount * 0.05\n",
            "app/checkout.py": "from app.billing import calculate_fee\ndef checkout(amt: float):\n    return calculate_fee(amt)\n"
        },
        "description": "Optional arguments with default values added, preserving backwards compatibility"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SIGNATURE_BREAK_CALLERS"],
        "claims": [],
        "expected_impact_count": 1,  # caller is affected but signature matches defaults
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_signature_default_safe",
        "human_authored_explanation": "Default values prevent SIGNATURE_MISMATCH."
    },
    "tags": ["impact", "signature", "clean"]
})

cases.append({
    "case_id": "IMPACT-SIGNATURE-01C",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-SIGNATURE-01",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "DEV",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "app/billing.py": "def calculate_fee(amount: float) -> float:\n    return amount * 0.05\n",
            "app/checkout.py": "from app.billing import calculate_fee\ndef checkout(amt: float):\n    return calculate_fee(amt)\n"
        },
        "head_files": {
            "app/billing.py": "def calculate_fee(amount: float) -> float:\n    # Refactored body with unchanged signature\n    rate = 0.05\n    return amount * rate\n",
            "app/checkout.py": "from app.billing import calculate_fee\ndef checkout(amt: float):\n    return calculate_fee(amt)\n"
        },
        "description": "Internal implementation change with zero signature delta"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["SIGNATURE_BREAK_CALLERS"],
        "claims": [],
        "expected_impact_count": 1,  # direct caller impact without signature break
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "phase6_signature_unchanged",
        "human_authored_explanation": "Signature preserved exactly."
    },
    "tags": ["impact", "clean"]
})

# Family 23: IMPACT-DELETED-CALLER-02 (Novel cross-package deleted function) - FROZEN_PUBLIC_EVAL
cases.append({
    "case_id": "IMPACT-DELETED-CALLER-02A",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DELETED-CALLER-02",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "pkg/crypto/hasher.py": "def compute_sha256(data: str) -> str:\n    return 'hash'\n",
            "pkg/audit/logger.py": "from pkg.crypto.hasher import compute_sha256\ndef write_audit_log(entry: str):\n    h = compute_sha256(entry)\n    return h\n"
        },
        "head_files": {
            "pkg/crypto/hasher.py": "# compute_sha256 removed\ndef get_salt():\n    return 'salt'\n",
            "pkg/audit/logger.py": "from pkg.crypto.hasher import compute_sha256\ndef write_audit_log(entry: str):\n    h = compute_sha256(entry)\n    return h\n"
        },
        "description": "Public function compute_sha256 deleted while audit logger calls it"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["DELETED_SYMBOL_WITH_CALLERS"],
        "claims": [{
            "rule_id": "DELETED_SYMBOL_WITH_CALLERS",
            "permitted_files": ["pkg/audit/logger.py"],
            "permitted_symbols": ["write_audit_log"],
            "required_structural_facts": {"impact_type": "CALLER_BROKEN_BY_DELETION"},
            "forbidden_structural_facts": {},
            "expected_severity": "HIGH"
        }],
        "expected_impact_count": 1,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "novel_frozen_deleted_crypto",
        "human_authored_explanation": "ChangeImpactEngine detects CALLER_BROKEN_BY_DELETION in write_audit_log."
    },
    "tags": ["impact", "deletion", "frozen-eval"]
})

cases.append({
    "case_id": "IMPACT-DELETED-CALLER-02B",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DELETED-CALLER-02",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "pkg/crypto/hasher.py": "def compute_sha256(data: str) -> str:\n    return 'hash'\n",
            "pkg/audit/logger.py": "from pkg.crypto.hasher import compute_sha256\ndef write_audit_log(entry: str):\n    h = compute_sha256(entry)\n    return h\n"
        },
        "head_files": {
            "pkg/crypto/hasher.py": "def compute_sha256(data: str) -> str:\n    return 'hash'\n",
            "pkg/audit/logger.py": "from pkg.crypto.hasher import compute_sha256\ndef write_audit_log(entry: str):\n    h = compute_sha256(entry)\n    return h\n"
        },
        "description": "Unchanged crypto hasher and logger"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["DELETED_SYMBOL_WITH_CALLERS"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "novel_frozen_deleted_clean",
        "human_authored_explanation": "No deletion."
    },
    "tags": ["impact", "clean", "frozen-eval"]
})

cases.append({
    "case_id": "IMPACT-DELETED-CALLER-02C",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-DELETED-CALLER-02",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "pkg/crypto/hasher.py": "def compute_sha256(data: str) -> str:\n    return 'hash'\n",
            "pkg/audit/logger.py": "from pkg.crypto.hasher import compute_sha256\ndef write_audit_log(entry: str):\n    h = compute_sha256(entry)\n    return h\n"
        },
        "head_files": {
            "pkg/crypto/hasher.py": "def compute_sha256(data: str) -> str:\n    # implementation optimized\n    return 'hash_v2'\n",
            "pkg/audit/logger.py": "from pkg.crypto.hasher import compute_sha256\ndef write_audit_log(entry: str):\n    h = compute_sha256(entry)\n    return h\n"
        },
        "description": "Function updated without deletion"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["DELETED_SYMBOL_WITH_CALLERS"],
        "claims": [],
        "expected_impact_count": 1,  # direct caller, not broken by deletion
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "novel_frozen_deleted_safe_update",
        "human_authored_explanation": "Symbol modified but not deleted."
    },
    "tags": ["impact", "clean", "frozen-eval"]
})

# Family 24: IMPACT-MULTI-02 (Novel shared auth service helper modified) - FROZEN_PUBLIC_EVAL
cases.append({
    "case_id": "IMPACT-MULTI-02A",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-MULTI-02",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "core/auth/token_util.py": "def decode_token_claims(t: str) -> dict:\n    return {'user': t}\n",
            "services/api/gateway.py": "from core.auth.token_util import decode_token_claims\ndef route_gateway(t: str):\n    return decode_token_claims(t)\n",
            "services/jobs/worker.py": "from core.auth.token_util import decode_token_claims\ndef process_job(t: str):\n    return decode_token_claims(t)\n"
        },
        "head_files": {
            "core/auth/token_util.py": "def decode_token_claims(t: str) -> dict:\n    # Modified parsing algorithm\n    return {'user': t, 'v': 2}\n",
            "services/api/gateway.py": "from core.auth.token_util import decode_token_claims\ndef route_gateway(t: str):\n    return decode_token_claims(t)\n",
            "services/jobs/worker.py": "from core.auth.token_util import decode_token_claims\ndef process_job(t: str):\n    return decode_token_claims(t)\n"
        },
        "description": "Shared token_util modified affecting gateway and worker consumers"
    },
    "annotation": {
        "expected_verdict": "ISSUE",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_MULTI_CONSUMER"],
        "claims": [{
            "rule_id": "BLAST_RADIUS_MULTI_CONSUMER",
            "permitted_files": ["services/api/gateway.py", "services/jobs/worker.py"],
            "permitted_symbols": ["route_gateway", "process_job"],
            "required_structural_facts": {},
            "forbidden_structural_facts": {},
            "expected_severity": "MEDIUM"
        }],
        "expected_impact_count": 2,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "novel_frozen_multi_caller",
        "human_authored_explanation": "Reachability affects multiple consumer modules."
    },
    "tags": ["impact", "multi-caller", "frozen-eval"]
})

cases.append({
    "case_id": "IMPACT-MULTI-02B",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-MULTI-02",
    "category": "CHANGE_IMPACT",
    "difficulty": "EASY",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "core/auth/token_util.py": "def decode_token_claims(t: str) -> dict:\n    return {'user': t}\n",
            "services/api/gateway.py": "from core.auth.token_util import decode_token_claims\ndef route_gateway(t: str):\n    return decode_token_claims(t)\n",
            "services/jobs/worker.py": "from core.auth.token_util import decode_token_claims\ndef process_job(t: str):\n    return decode_token_claims(t)\n"
        },
        "head_files": {
            "core/auth/token_util.py": "def decode_token_claims(t: str) -> dict:\n    return {'user': t}\n",
            "services/api/gateway.py": "from core.auth.token_util import decode_token_claims\ndef route_gateway(t: str):\n    return decode_token_claims(t)\n",
            "services/jobs/worker.py": "from core.auth.token_util import decode_token_claims\ndef process_job(t: str):\n    return decode_token_claims(t)\n"
        },
        "description": "Zero change across files"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_MULTI_CONSUMER"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "novel_frozen_multi_clean",
        "human_authored_explanation": "Zero impact facts."
    },
    "tags": ["impact", "clean", "frozen-eval"]
})

cases.append({
    "case_id": "IMPACT-MULTI-02C",
    "benchmark_version": "1.0.0",
    "case_family": "IMPACT-MULTI-02",
    "category": "CHANGE_IMPACT",
    "difficulty": "MEDIUM",
    "split": "FROZEN_PUBLIC_EVAL",
    "target_pipeline": "CHANGE_ANALYSIS",
    "evaluation_stage": "IMPACT_FACT",
    "benchmark_languages": ["python"],
    "fixture": {
        "base_files": {
            "core/auth/token_util.py": "def decode_token_claims(t: str) -> dict:\n    return {'user': t}\n",
            "services/api/gateway.py": "from core.auth.token_util import decode_token_claims\ndef route_gateway(t: str):\n    return decode_token_claims(t)\n",
            "services/jobs/worker.py": "from core.auth.token_util import decode_token_claims\ndef process_job(t: str):\n    return decode_token_claims(t)\n"
        },
        "head_files": {
            "core/auth/token_util.py": "def decode_token_claims(t: str) -> dict:\n    return {'user': t}\n",
            "services/api/gateway.py": "from core.auth.token_util import decode_token_claims\ndef route_gateway(t: str):\n    # caller comment only\n    return decode_token_claims(t)\n",
            "services/jobs/worker.py": "from core.auth.token_util import decode_token_claims\ndef process_job(t: str):\n    return decode_token_claims(t)\n"
        },
        "description": "Callee untouched; comment added in single caller only"
    },
    "annotation": {
        "expected_verdict": "CLEAN",
        "evaluation_scope": "RULE_SCOPED",
        "target_rule_ids": ["BLAST_RADIUS_MULTI_CONSUMER"],
        "claims": [],
        "expected_impact_count": 0,
        "how_established": "impact_engine_ground_truth",
        "fixture_source": "novel_frozen_multi_caller_comment",
        "human_authored_explanation": "Callee decode_token_claims is untouched."
    },
    "tags": ["impact", "clean", "frozen-eval"]
})


def write_all_cases():
    cat_dirs = {
        "SECURITY": BASE_DIR / "security",
        "CORRECTNESS": BASE_DIR / "correctness",
        "CONTRACT": BASE_DIR / "contract",
        "CHANGE_IMPACT": BASE_DIR / "impact",
    }
    for d in cat_dirs.values():
        d.mkdir(parents=True, exist_ok=True)

    for case in cases:
        category = case["category"]
        dest_dir = cat_dirs[category]
        file_path = dest_dir / f"{case['case_id']}.json"
        with open(file_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(case, f, indent=2, ensure_ascii=False)
        print(f"Wrote {file_path.name}")

    print(f"\nTotal cases generated: {len(cases)}")


if __name__ == "__main__":
    write_all_cases()
