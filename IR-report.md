# IR report — suspected precursor activity before ransomware

**Disposition:** High-priority investigation in a synthetic exercise. The records support suspicious ticket activity, issuance from a risky certificate template, and attempts to impair recovery. Whether an intruder gained access, used the certificate, destroyed backups, or encrypted files remains undetermined.

**Scope:** The fictional DC, issuing CA, and workstation appear below. Evidence consists of 13 projected Windows records and a template snapshot in the exercise bundle. The live UTM workstation check is a separate validation of endpoint visibility. All timeline entries are in UTC on November 24, 2026.

| Time | Host and record IDs | Observation and assessment |
| --- | --- | --- |
| 09:00:00–09:00:01 | dc01, 101–102 | Ordinary inventory account requests to one service form the ticket control. |
| 09:00:03–09:00:26 | dc01, 103–106 | alex from 192.0.2.40 requested RC4 tickets for four distinct services in 23 seconds. Consistent with Kerberoasting. Password recovery and subsequent service-account use are unverified. |
| 09:01:00–09:01:04 | ca01, 200–201 | StandardUser issuance to the requesting identity provides an enrollment control. |
| 09:03:00–09:03:04 | ca01, 202–203 | Request 18 by alex resulted in a LegacyAuth certificate identifying lab-admin. The exercise inventory shows broad enrollment, requester-supplied subject, authentication use, and no approval/signature gate. High-confidence ESC1-like exposure in the replay. |
| 09:04:00 | ws01, 301 | A read-only VSS writer query produced no recovery-impairment finding. |
| 09:05:00–09:05:21 | ws01, 302–303 | Process records indicate shadow-copy and backup-catalog deletion attempts. Exit status, resulting backup inventory, and the responsible account are absent. |

**Indicators and pivots:** 192.0.2.40 is a documentation-range fixture IP. Pivot on alex, lab-admin, the four service names, CA request 18, template LegacyAuth, and workstation process records 302–303. These values apply to this exercise only. No external infrastructure, payload hashes, or ransomware family were identified.

**Root cause and confidence:** The modeled template configuration allowed an identity mismatch to pass issuance controls. The ticket burst and certificate request share a requester. The workspace lacks an initial-access record, a certificate-authentication event, and a logon or process identifier joining alex to ws01. The common actor across all stages is therefore a hypothesis. An administrative maintenance window could independently explain the workstation activity.

**Containment decisions (tabletop):** Preserve DC/CA Security logs, the issued certificate, template permissions, workstation process ancestry, logon records, and backup-console audit history. Contact the backup owner immediately to verify recoverability from an independent console. If unauthorized activity is corroborated, isolate ws01, restrict the affected principal, suspend new enrollment on the risky template under change control, and revoke the affected certificate with the PKI owner. Check revocation publication and enforcement. No containment action was executed on a real identity or production host.

**Recovery and closure:** Validate an isolated restore from an immutable recovery point, verify restored data integrity, correct enrollment permissions and issuance settings, and inventory other certificates issued from the template. Close only after the affected scope is reconciled and monitoring covers repeat authentication and recovery changes.

**Lessons learned:** A ticket request has low specificity without a service baseline. CA issuance becomes actionable when joined to effective template permissions and the actual issued identity. An endpoint process start establishes intent more reliably than impact. Backup-system audit records and a restore test are needed to quantify loss. Preserve host, record ID, and time independently at each stage.

**Live validation:** The existing UTM agent was active in Wazuh. A read-only VSS writer check completed successfully and Sysmon recorded event 1. The live record and UTC timestamp are stored in [live-control.json](evidence/live-control.json). It is excluded from the fictional incident timeline.
