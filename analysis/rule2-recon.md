Rule 2: Post-Login Reconnaissance Commands (T1078)

Purpose
Detect commands run within 2 minutes of a successful login, consistent with post-access
reconnaissance.

Query
index=cowrie eventid="cowrie.command.input"
| eval CommandTime=_time
| join type=left session
    [ search index=cowrie eventid="cowrie.login.success"
      | eval LoginTime=_time
      | table LoginTime, session, src_ip, username, password ]
| eval TimeDiff=CommandTime-LoginTime
| where TimeDiff>=0 AND TimeDiff<=120
| search input="*passwd*" OR input="*whoami*" OR input="*id*" OR input="*uname*" OR
  input="*shadow*" OR input="*ls -la*"
| table LoginTime, CommandTime, session, src_ip, username, password, input
| sort CommandTime

Result
Correctly matched all 5 commands from the manual root session (c3466e00ce2b) to their login
event: whoami, id, ls -la, uname -a, cat /etc/passwd.

Implementation note
An earlier version of this query used commands as the join subsearch rather than the base
search, which silently returned only 1 of the 5 expected matches. Switching so that
commands are the primary search, with login details joined in via a left join, resolved
this. This is a meaningful difference from the Sentinel version, where a standard inner
join on session worked correctly in either direction - worth flagging as a platform-specific
quirk rather than a logic error in the original query design.
