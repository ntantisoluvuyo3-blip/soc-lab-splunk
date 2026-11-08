Limitations

1. Static, historical data: same dataset as the Sentinel pipeline, bulk-uploaded rather than
   ingested live.
2. Small dataset: 132 log lines, same caveats on threshold tuning as the Sentinel version.
3. Single-instance Splunk: this is a 60-day free trial on a single host, not a distributed
   or production-representative Splunk deployment.
4. Join behavior difference: the post-login reconnaissance query required restructuring
   compared to its Sentinel/KQL equivalent due to how Splunk's join command handled
   multiple matches per key; documented in rule2-recon.md.
5. Single attacker source: as with the Sentinel version, all detections were tested against
   one attacking IP from one lab session.
