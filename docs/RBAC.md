# Resource RBAC

Permissions are protocol-independent and default-deny. Roles receive explicit entries in `role_permissions`; authorization never derives from connection-profile credentials.

- Administrators manage resources/profiles and have all session/recording permissions.
- Operators can test resources, approve access, view group sessions, terminate sessions and review/export recordings.
- Users can view resources, request access, launch their own grants and view their own session metadata.

The permission catalog is: `resources.view`, `resources.create`, `resources.update`, `resources.delete`, `resources.test_connection`, `access.request`, `access.approve`, `sessions.launch`, `sessions.view_own`, `sessions.view_group`, `sessions.terminate`, `recordings.view`, `recordings.download`, and `session_events.export`.

Access profiles add resource type/group/environment/criticality constraints, maximum duration, approval, MFA, recording, schedule, upload, download and clipboard policy. These policy fields are evaluated before grants or sessions are created. Recording playback/download also requires MFA step-up for privileged reviewers and creates an audit entry.
