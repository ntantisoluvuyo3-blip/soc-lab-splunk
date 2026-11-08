Rule 3: Anomalous Password Attempt Truncation

Purpose
Reproduce, in Splunk, a finding originally made through manual log analysis and later
automated in Sentinel: Hydra's per-user password attempts stopped after exactly 4
passwords, not the full 6-password wordlist, for every targeted user.

Query
index=cowrie (eventid="cowrie.login.failed" OR eventid="cowrie.login.success")
| stats count AS AttemptsPerUser,
        values(password) AS PasswordsTried,
        earliest(_time) AS FirstAttempt,
        latest(_time) AS LastAttempt
        by src_ip, username
| eval PasswordCount=mvcount(PasswordsTried)
| where PasswordCount=4
| sort username

Result
Confirmed exactly 4 distinct passwords tried for admin, test, ubuntu, and root (root shows
5 total attempts due to a duplicate login event, but still only 4 distinct passwords).
Matches both the original manual finding and the Sentinel version exactly.
