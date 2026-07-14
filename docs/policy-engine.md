# Policy Engine, Device Groups & Licensing (Module M16)

Lets admins group devices and target them with policies that resolve to an
effective configuration delivered to each agent at check-in. Includes licensing
placeholders with an enrollment device cap.

## Device groups

`device_groups` (org-scoped, unique name per org). A device has an optional
`group_id`. Assign via `POST /api/admin/devices/{id}/group`.

## Policies

`policies` table. A policy with `group_id` NULL is the **org default**; a
group-scoped policy overrides it for that group's devices. `settings` is a free
JSON blob understood by the agent:

| Key | Effect |
|---|---|
| `suspicious_ports` | ports the port-watchdog treats as malicious |
| `blocked_processes` | process names to kill on sight |
| `blocked_domains` | domains to sinkhole |
| `file_drop_dirs` | extra directories the file-drop monitor watches |
| `block_usb_storage` | block newly inserted USB storage |
| `detection_auto_isolate` | (server-side) auto-isolate on critical detections |

### Resolution precedence

`resolve_effective_policy` merges, later overriding earlier:
built-in defaults → org-default policy → device's group policy.

## Delivery

The resolved policy is included in the agent **check-in** response
(`CheckinResponse.policy`, additive). The agent's `apply_policy` merges it into
its running config each cycle. Preview it via
`GET /api/admin/devices/{id}/policy`.

## API & permissions

Group/policy CRUD and device assignment require `manage:policy` (super-admin,
SOC manager); reads and the effective-policy preview require `read:fleet`. All
mutations are audit-logged and org-scoped.

## Licensing

`organizations` gains `license_tier` and `max_devices` (0 = unlimited).
Enrollment returns **402** when the org's device cap is reached — a placeholder
for real license enforcement.
