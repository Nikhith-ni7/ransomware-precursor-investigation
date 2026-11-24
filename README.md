# Ransomware precursor investigation in Active Directory

Investigate a fictional service-ticket burst, certificate issuance, and two attempts to impair recovery. A separate live Windows endpoint check supplies a benign comparison. The project runs locally with Python 3.10+ and uses the existing UTM Windows, Sysmon, and Wazuh lab. Azure resources and a live AD forest are outside this edition.

## Reproduce the findings

From this folder run:

```sh
python3 investigate.py
python3 -m unittest discover -v
```

The first command reads 13 projected records and a mock certificate-template inventory and prints four findings. Compare the UTC times and record IDs with [saved findings](evidence/findings.json) and the [incident report](IR-report.md). The second command checks detections and negative controls.

## Evidence model

- The replay uses normalized exercise fields. A production adapter would extract requester, service, encryption type, and source address from DC Security event 4769. The service-ticket alert requires successful RC4 requests for four distinct services within five minutes from one requester and address observed on the same DC. Splitting traffic across DCs or using AES can defeat this particular heuristic.
- Certificate correlation joins 4886 and 4887 by issuing CA and request ID, then checks the template inventory and identity mismatch. The exercise supplies the issued identity as an enriched field. A real investigation must obtain the certificate or CA database record, validate SAN/UPN identities and aliases, inspect effective enrollment rights and issuance controls, and establish the template settings at issuance time. [Microsoft CA auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority)
- The endpoint replay uses Sysmon process creation with normalized operation labels. The Python rules distinguish two deletion attempts from a read-only writer query. These are offline detections over projected records. Deployment into the Wazuh rules engine and coverage of alternate utilities require separate validation.
- [Live control](evidence/live-control.json) contains redacted endpoint metadata. The Windows agent was active on the local Wazuh manager. A bounded search of the latest 1,800 manager alerts found no matching alert for the control record. The original Windows event was verified directly in Sysmon.
