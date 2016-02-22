# PrivilegeEscalationTestExtender

How this tool works   (works only with pro version)
------------------------------
If an administrator role User's URL can be accessible by a Normal role user then it is privilege escalated

What are the ways to identify the privilege escalations: 

1. based on response text

         a. if contains "ABC" text then the URL is Privilege Escalated.
         b. if contains "PQR" text then the URL is NOT Privilege Escalated.

2. based on Content-Length

         a. if response content length is 20 then the URL is Privilege Escalated.
         b. if response content length is 23 then the URL is NOT Privilege Escalated.

3. based on Response Status Codes

         a. if baseResponse Status Code is not Equals to CurrentResponse Status Code then it is NOT Privilege Escalated
         [base Request/Response means Administrator Role user session request/response current Request/Response means Normal Role user            session request/response]

Similarly we can add multiple conditions to identify the Privileges Escalation Requests.

Also this Extender identifies 
         Direct Page Access vulnerability by setting the cookie with null
         Authorization Bypass in some cases
