services:
  - type: web
    name: ai-shield-api
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: uvicorn main:app --host 0.0.0.0 --port $PORT
    envVars:
      - key: ADMIN_MASTER_KEY
        generateValue: true
      - key: DATABASE_PATH
        value: /var/data/ai_security_audit.db
    disk:
      name: aishield-db-volume
      mountPath: /var/data
      sizeGB: 10