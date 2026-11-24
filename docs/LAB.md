# Validate the local investigation lab

Run `python3 -m unittest -v` and `python3 investigate.py` from the repository root. Use the recorded Windows and Wazuh examples in `evidence/exercise.jsonl` to validate detection of recovery inhibition. Compare them with the benign VSS writer query captured from the UTM guest in `evidence/live-control.json`.

For Wazuh validation, load `wazuh/local_rules.xml` as a separate rules file on a test manager and submit Windows eventchannel JSON to `/var/ossec/bin/wazuh-logtest`. Check the matched rule IDs and confirm that the read-only control does not match the recovery rules. Treat process starts as evidence of attempted activity. Verify impact separately using backup audit logs and restore checks.

When using outside event exports, pass the matching inventory via `--templates` and decoded certificate identities via `--issued`. Use empty inventory files when those sources are unavailable. Record the dataset provenance and report coverage gaps.
