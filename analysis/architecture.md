Architecture and Pipeline

Source data
Same cowrie.json dataset used in the original honeypot analysis and the Sentinel pipeline.

Platform
Splunk Enterprise (60-day free trial), self-hosted on the lab's Kali VM.

Ingestion
Data was ingested via Splunk's built-in "Add Data" upload workflow rather than a custom
script, since Splunk's native JSON handling parsed the file's structure automatically with
no manual schema definition required (a notable contrast to the Sentinel pipeline's custom
table and transformation setup).

Timestamp handling
Splunk's automatic timestamp detection initially failed, defaulting every event to the file
upload time rather than the log's actual event time. This was corrected by manually
configuring the sourcetype's timestamp extraction: timestamp format
%Y-%m-%dT%H:%M:%S.%6N%Z, timestamp field "timestamp", matching the log's ISO 8601 format
with microseconds.

Index
A dedicated index, cowrie, was created to keep lab data separate from Splunk's default
index.

Detection
Three SPL searches, saved as scheduled alerts (hourly), query the index and trigger when
their conditions are met, logged as Triggered Alerts within Splunk.
