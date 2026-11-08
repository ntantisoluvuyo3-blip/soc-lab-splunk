SOC Lab: Cowrie Honeypot Detection Pipeline (Splunk)

A second detection engineering exercise built on the same Cowrie honeypot dataset used in
my Sentinel pipeline (https://github.com/ntantisoluvuyo3-blip/soc-lab-sentinel), this time
implemented in Splunk Enterprise. The goal: reproduce the same three detections across a
different SIEM platform, to validate the underlying analysis logic independent of any one
vendor's query language.

Architecture
Cowrie honeypot logs (cowrie.json) -> Splunk Add Data (file upload) -> custom index (cowrie)
-> Search & Reporting (SPL) -> Scheduled Alerts -> Triggered Alerts

What was built
- Self-hosted Splunk Enterprise (free trial), installed directly on the lab's existing Kali
  VM.
- A custom index (cowrie) holding the honeypot's JSON logs, with a manually configured
  timestamp extraction (Splunk's auto-detection defaulted to file upload time rather than
  the log's own timestamp field).
- Three scheduled SPL alerts, each reproducing a finding from the original honeypot
  analysis and its Sentinel KQL equivalent, each verified against the ingested data.

Alerts
- Brute Force Login Attempts (T1110.001) - flags source IPs with 5+ login attempts.
- Post-Login Reconnaissance Commands (T1078) - flags commands run within 2 minutes of a
  successful login.
- Anomalous Password Attempt Truncation - flags username/source pairs where attempts
  stopped after exactly 4 distinct passwords, the same anomaly found through manual log
  analysis in the original honeypot project and reproduced in the Sentinel pipeline.

Analysis
- Architecture and pipeline details
- Rule 1: Brute force detection
- Rule 2: Post-login reconnaissance
- Rule 3: Password attempt truncation
- Limitations

Related projects
- Cowrie SSH Honeypot Lab: https://github.com/ntantisoluvuyo3-blip/SOC-Lab-Honeypot
- Microsoft Sentinel pipeline: https://github.com/ntantisoluvuyo3-blip/soc-lab-sentinel

Notes
All data in this repo was generated in a personal lab. No external or real-world incident
data is included.
