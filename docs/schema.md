# Database Schema

_Generated from `server/app/models.py` by `scripts/generate_schema_docs.py`._

## `audit_log`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| timestamp | DATETIME | indexed, not null |
| actor | VARCHAR(32) | not null |
| action | VARCHAR(64) | not null |
| target | VARCHAR(255) | not null |
| details | JSON | not null |

## `blocklist`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| kind | VARCHAR(16) | not null |
| value | VARCHAR(255) | not null |
| added_at | DATETIME | not null |

## `detections`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| device_id | VARCHAR(36) | FK→devices.id, indexed, not null |
| event_id | INTEGER | FK→threat_events.id |
| rule_id | VARCHAR(64) | indexed, not null |
| name | VARCHAR(255) | not null |
| severity | VARCHAR(16) | not null |
| risk_score | INTEGER | not null |
| technique_id | VARCHAR(16) | not null |
| technique_name | VARCHAR(128) | not null |
| status | VARCHAR(16) | indexed, not null |
| details | JSON | not null |
| created_at | DATETIME | indexed, not null |

## `device_groups`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| name | VARCHAR(128) | not null |
| description | TEXT | not null |
| created_at | DATETIME | not null |

## `device_inventory`

| Column | Type | Attributes |
|---|---|---|
| device_id | VARCHAR(36) | PK, FK→devices.id, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| os_version | VARCHAR(255) | not null |
| kernel | VARCHAR(255) | not null |
| cpu_model | VARCHAR(255) | not null |
| cpu_count | INTEGER | not null |
| ram_total_mb | INTEGER | not null |
| disk_total_gb | INTEGER | not null |
| disk_free_gb | INTEGER | not null |
| installed_software | JSON | not null |
| running_services | JSON | not null |
| logged_in_users | JSON | not null |
| health | VARCHAR(16) | not null |
| posture | JSON | not null |
| updated_at | DATETIME | not null |

## `devices`

| Column | Type | Attributes |
|---|---|---|
| id | VARCHAR(36) | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| group_id | INTEGER | FK→device_groups.id, indexed |
| hostname | VARCHAR(255) | not null |
| platform | VARCHAR(64) | not null |
| agent_version | VARCHAR(32) | not null |
| api_key | VARCHAR(64) | unique, not null |
| enrolled_at | DATETIME | not null |
| last_seen | DATETIME | not null |
| isolated | BOOLEAN | not null |
| pending_commands | JSON | not null |
| stopped | BOOLEAN | not null |
| unresponsive_alerted | BOOLEAN | not null |

## `integrations`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| name | VARCHAR(128) | not null |
| kind | VARCHAR(24) | not null |
| config | JSON | not null |
| min_severity | VARCHAR(16) | not null |
| enabled | BOOLEAN | not null |
| created_at | DATETIME | not null |

## `intel_rules`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| kind | VARCHAR(8) | not null |
| name | VARCHAR(255) | not null |
| content | TEXT | not null |
| enabled | BOOLEAN | not null |
| created_at | DATETIME | not null |

## `iocs`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| ioc_type | VARCHAR(16) | indexed, not null |
| value | VARCHAR(512) | indexed, not null |
| confidence | INTEGER | not null |
| source | VARCHAR(128) | not null |
| description | TEXT | not null |
| expires_at | DATETIME |  |
| created_at | DATETIME | not null |

## `organizations`

| Column | Type | Attributes |
|---|---|---|
| id | VARCHAR(36) | PK, not null |
| name | VARCHAR(255) | not null |
| slug | VARCHAR(64) | unique, indexed, not null |
| is_active | BOOLEAN | not null |
| license_tier | VARCHAR(32) | not null |
| max_devices | INTEGER | not null |
| created_at | DATETIME | not null |

## `policies`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| group_id | INTEGER | FK→device_groups.id, indexed |
| name | VARCHAR(128) | not null |
| settings | JSON | not null |
| enabled | BOOLEAN | not null |
| created_at | DATETIME | not null |

## `quarantine_items`

| Column | Type | Attributes |
|---|---|---|
| id | VARCHAR(64) | PK, not null |
| device_id | VARCHAR(36) | FK→devices.id, indexed, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| original_path | TEXT | not null |
| sha256 | VARCHAR(64) | not null |
| reason | TEXT | not null |
| verdict | VARCHAR(16) | not null |
| status | VARCHAR(24) | not null |
| quarantined_at | DATETIME | not null |
| restored_at | DATETIME |  |

## `refresh_tokens`

| Column | Type | Attributes |
|---|---|---|
| jti | VARCHAR(32) | PK, not null |
| user_id | VARCHAR(36) | FK→users.id, indexed, not null |
| expires_at | DATETIME | not null |
| revoked | BOOLEAN | not null |
| created_at | DATETIME | not null |

## `response_actions`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| device_id | VARCHAR(36) | FK→devices.id, indexed |
| action_type | VARCHAR(32) | indexed, not null |
| params | JSON | not null |
| status | VARCHAR(16) | indexed, not null |
| actor | VARCHAR(64) | not null |
| result | JSON | not null |
| created_at | DATETIME | indexed, not null |
| completed_at | DATETIME |  |

## `threat_events`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| device_id | VARCHAR(36) | FK→devices.id, indexed, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| timestamp | DATETIME | indexed, not null |
| source | VARCHAR(32) | not null |
| severity | VARCHAR(16) | not null |
| action | VARCHAR(64) | not null |
| summary | TEXT | not null |
| details | JSON | not null |

## `user_tokens`

| Column | Type | Attributes |
|---|---|---|
| id | INTEGER | PK, not null |
| user_id | VARCHAR(36) | FK→users.id, indexed, not null |
| purpose | VARCHAR(24) | indexed, not null |
| token_hash | VARCHAR(64) | indexed, not null |
| expires_at | DATETIME | not null |
| used_at | DATETIME |  |
| created_at | DATETIME | not null |

## `users`

| Column | Type | Attributes |
|---|---|---|
| id | VARCHAR(36) | PK, not null |
| org_id | VARCHAR(36) | FK→organizations.id, indexed |
| email | VARCHAR(255) | unique, indexed, not null |
| hashed_password | VARCHAR(255) | not null |
| role | VARCHAR(32) | not null |
| is_active | BOOLEAN | not null |
| email_verified | BOOLEAN | not null |
| failed_login_count | INTEGER | not null |
| locked_until | DATETIME |  |
| last_login_at | DATETIME |  |
| created_at | DATETIME | not null |
