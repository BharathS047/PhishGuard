# PhishGuard - Azure Deployment Guide

## Architecture

```
[Azure Static Web Apps]  -->  [Azure App Service (B1)]  -->  [Azure PostgreSQL Flexible Server]
      (React frontend)          (Django backend)                  (Database)
                                      |
                              [Azure Communication Services]
                                    (Email OTP)
```

## Step 1: Create Azure Resources

### 1.1 Resource Group (if not already created)

```bash
az group create --name phishguard-rg-westus --location westus2
```

### 1.2 PostgreSQL Flexible Server

```bash
az postgres flexible-server create \
  --resource-group phishguard-rg-westus \
  --name phishguard-db \
  --location westus2 \
  --sku-name Standard_B1ms \
  --tier Burstable \
  --admin-user phishguardadmin \
  --admin-password '<STRONG_PASSWORD>' \
  --storage-size 32 \
  --version 16

# Create the database
az postgres flexible-server db create \
  --resource-group phishguard-rg-westus \
  --server-name phishguard-db \
  --database-name phishguard

# Allow Azure services to connect
az postgres flexible-server firewall-rule create \
  --resource-group phishguard-rg-westus \
  --name phishguard-db \
  --rule-name AllowAzureServices \
  --start-ip-address 0.0.0.0 \
  --end-ip-address 0.0.0.0
```

### 1.3 App Service (Backend)

```bash
az appservice plan create \
  --name phishguard-plan \
  --resource-group phishguard-rg-westus \
  --sku B1 \
  --is-linux

az webapp create \
  --name phishguard-backend \
  --resource-group phishguard-rg-westus \
  --plan phishguard-plan \
  --runtime "PYTHON:3.12"

# Set startup command
az webapp config set \
  --name phishguard-backend \
  --resource-group phishguard-rg-westus \
  --startup-file "startup.sh"
```

### 1.4 Static Web App (Frontend)

Create via Azure Portal or CLI:

```bash
az staticwebapp create \
  --name phishguard-frontend \
  --resource-group phishguard-rg-westus \
  --location westus2
```

## Step 2: Configure Environment Variables

Set these in Azure App Service > Configuration > Application Settings:

```bash
az webapp config appsettings set \
  --name phishguard-backend \
  --resource-group phishguard-rg-westus \
  --settings \
    DJANGO_SECRET_KEY='<generate-a-random-50-char-string>' \
    DEBUG='False' \
    ALLOWED_HOSTS='phishguard-backend.azurewebsites.net' \
    CORS_ALLOWED_ORIGINS='https://<your-static-web-app>.azurestaticapps.net' \
    CSRF_TRUSTED_ORIGINS='https://<your-static-web-app>.azurestaticapps.net' \
    FRONTEND_URL='https://<your-static-web-app>.azurestaticapps.net' \
    DB_HOST='phishguard-db.postgres.database.azure.com' \
    DB_NAME='phishguard' \
    DB_USER='phishguardadmin' \
    DB_PASSWORD='<your-db-password>' \
    DB_PORT='5432' \
    GOOGLE_SAFEBROWSING_API_KEY='<your-key>' \
    VIRUSTOTAL_API_KEY='<your-key>' \
    AZURE_COMMUNICATION_CONNECTION_STRING='<your-connection-string>' \
    AZURE_EMAIL_SENDER_ADDRESS='<your-sender-address>'
```

To generate a secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

## Step 3: Set Up GitHub Secrets

In your GitHub repo (BharathS047/PhishGuard), go to **Settings > Secrets and variables > Actions** and add:

| Secret Name | How to Get It |
|---|---|
| `AZURE_BACKEND_PUBLISH_PROFILE` | Azure Portal > App Service > Download publish profile |
| `AZURE_STATIC_WEB_APPS_API_TOKEN` | Azure Portal > Static Web App > Manage deployment token |
| `REACT_APP_API_URL` | `https://phishguard-backend.azurewebsites.net` |

### Download Publish Profile

```bash
az webapp deployment list-publishing-profiles \
  --name phishguard-backend \
  --resource-group phishguard-rg-westus \
  --xml
```

Copy the entire XML output as the `AZURE_BACKEND_PUBLISH_PROFILE` secret.

### Get Static Web App Token

```bash
az staticwebapp secrets list \
  --name phishguard-frontend \
  --resource-group phishguard-rg-westus
```

## Step 4: Deploy

### Option A: GitHub Actions (automated)

Push to `main` branch. The workflows will automatically deploy:
- Backend changes trigger `deploy-backend.yml`
- Frontend changes trigger `deploy-frontend.yml`

### Option B: Manual deploy (one-time)

**Backend:**
```bash
cd backend
az webapp up --name phishguard-backend --resource-group phishguard-rg-westus --runtime "PYTHON:3.12"
```

**Frontend:**
```bash
cd frontend
REACT_APP_API_URL=https://phishguard-backend.azurewebsites.net npm run build
# Then deploy the build/ folder via Azure Portal or SWA CLI
npx @azure/static-web-apps-cli deploy ./build
```

## Step 5: Verify

1. Check backend health: `https://phishguard-backend.azurewebsites.net/admin/`
2. Check frontend: `https://<your-static-web-app>.azurestaticapps.net`
3. Check logs if something is wrong:

```bash
az webapp log tail --name phishguard-backend --resource-group phishguard-rg-westus
```

## Rotate Compromised API Keys

Your previous API keys were exposed in git history. Rotate them:

1. **Google Safe Browsing**: https://console.cloud.google.com/apis/credentials - delete old key, create new
2. **VirusTotal**: https://www.virustotal.com/gui/my-apikey - regenerate key
3. **Azure Communication Services**: Azure Portal > Communication Services > Keys > Regenerate

## Cost Estimate (Monthly)

| Resource | SKU | ~Cost |
|---|---|---|
| App Service | B1 | ~$13 |
| PostgreSQL Flexible | B1ms | ~$12 |
| Static Web Apps | Free tier | $0 |
| Communication Services | Pay-as-you-go | ~$0.25/1000 emails |
| **Total** | | **~$25/month** |
