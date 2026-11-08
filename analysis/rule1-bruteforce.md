Rule 1: Brute Force Login Attempts (T1110.001)

Purpose
Detect source IPs making multiple SSH login attempts in a short window.

Query
index=cowrie (eventid="cowrie.login.failed" OR eventid="cowrie.login.success")
| stats count(eval(eventid="cowrie.login.failed")) AS FailedCount,
        count(eval(eventid="cowrie.login.success")) AS SuccessCount,
        count AS TotalAttempts,
        values(username) AS Usernames,
        earliest(_time) AS FirstAttempt,
        latest(_time) AS LastAttempt
        by src_ip
| where TotalAttempts >= 5
| sort -TotalAttempts

Result
Correctly identified 192.168.56.20 with 2 failed, 15 successful, 17 total attempts across
4 usernames, matching the original manual analysis and the Sentinel version of this rule
exactly.
