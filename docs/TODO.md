# Mission: Security & Correctness Remediation

- [x] Task 1: Admin token remediation <!-- id: 1 -->
- [x] Task 2: CSRF remediation (settings.go, logout, forensic, intelligence) <!-- id: 2 --><!-- resolved: v1.1.1 — H-1, M-3 fixed; tests in settings_test.go, server_test.go -->
- [x] Task 3: SQLite hardening <!-- id: 3 --><!-- resolved: v1.1.1 — M-1 fixed; WALCheckpoint/ExportHotSnapshot/requireColumn input validation; tests in db_test.go -->
- [x] Task 4: CrowdSec validation hardening <!-- id: 4 --><!-- resolved: v1.1.1 — M-2 fixed; AllowlistEntry.Comment validated before cscli exec; tests in client_validation_test.go -->
- [x] Task 5: Rollback planner correctness (requires ROLLBACK_ANALYSIS.md) <!-- id: 5 --><!-- resolved: v1.1.1 — L-2 fixed; OpUpdate now returns explicit error; tests in planner_test.go -->
- [x] Task 6: Low findings (SameSite=Strict, audit redaction, backup rotation, etc.) <!-- id: 6 --><!-- resolved: v1.1.1 — L-1 (SameSite=Strict), L-4 (bearer audit redaction), L-5 (RotateBackups error visibility) all fixed -->
