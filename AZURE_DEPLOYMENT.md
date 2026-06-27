# PhishGuard - Azure Deployment Guide

> **Current deployment (as of 2026-06-27)** — provisioned in subscription
> `Azure subscription 1` (account `karans9954@outlook.com`). Resource names use
> the suffix `35ohcu`. Replace the suffix/names if you re-provision in a new
> subscription (App Service, PostgreSQL, and ACS names are globally unique).

## Architecture

```
[Azure Static Web Apps]  -->  [Azure App Service (B1, Linux)]  -->  [Azure PostgreSQL Flexible Server]
      (React frontend)              (Django backend)                       (Database)
   westus2                          westus2                                centralus
                                        |
                                [Azure Communication Services]
                                      (Email OTP)
```

## Live URLs

| Component | URL |
|---|---|
| Frontend (Static Web App) | https://brave-sky-03c9cf41e.7.azurestaticapps.net |
| Backend (App Service) | https://phishguard-backend-35ohcu.azurewebsites.net |
| Backend health check | https://phishguard-backend-35ohcu.azurewebsites.net/health/ |

## Resource Inventory

| Resource | Type / SKU | Name | Region |
|---|---|---|---|
| Resource group | — | `phishguard-rg` | westus2 |
| App Service plan | Linux, B1 | `phishguard-plan` | westus2 |
| Backend web app | App Service, Python 3.12 | `phishguard-backend-35ohcu` | westus2 |
| Frontend | Static Web App, Free | `phishguard-frontend` | westus2 |
| Database | PostgreSQL Flexible, B1ms (Burstable) | `phishguard-db-35ohcu` | **centralus** |
| Email | Communication Services | `phishguard-comm-35ohcu` | global |
| Email service | Email Communication Service | `phishguard-email-35ohcu` | global |

> **Why the DB is in a different region:** this subscription is **restricted
> from creating PostgreSQL Flexible Server in `westus2` and `eastus2`**
> ("The location is restricted from performing this operation"). `centralus`
> works. App Service (paid B1) is fine in `westus2`. Cross-region DB access
> works because the server allows all Azure services (firewall `0.0.0.0`) and
> Django connects over SSL.

---

## Step 1: Create Azure Resources

Set shared variables (bash):

```bash
RG=phishguard-rg
SUFFIX=35ohcu                 # change if re-provisioning
LOC=westus2                   # compute region
DB_LOC=centralus             # PostgreSQL region (see note above)
```

### 1.1 Resource Group

```bash
az group create --name $RG --location $LOC
```

### 1.2 PostgreSQL Flexible Server

```bash
az postgres flexible-server create \
  --resource-group $RG \
  --name phishguard-db-$SUFFIX \
  --location $DB_LOC \
  --tier Burstable \
  --sku-name Standard_B1ms \
  --storage-size 32 \
  --version 16 \
  --admin-user phishguardadmin \
  --admin-password '<STRONG_PASSWORD>' \
  --public-access 0.0.0.0 \
  --yes

# Create the database
az postgres flexible-server db create \
  --resource-group $RG \
  --server-name phishguard-db-$SUFFIX \
  --database-name phishguard
```

`--public-access 0.0.0.0` adds the "Allow all Azure services" firewall rule so
the App Service can reach the DB. Django enforces `sslmode=require`.

### 1.3 App Service (Backend)

```bash
az appservice plan create \
  --name phishguard-plan \
  --resource-group $RG \
  --sku B1 \
  --is-linux

az webapp create \
  --name phishguard-backend-$SUFFIX \
  --resource-group $RG \
  --plan phishguard-plan \
  --runtime "PYTHON:3.12"

# Startup command (NOT set via the deploy workflow — see Step 3 note)
az webapp config set \
  --name phishguard-backend-$SUFFIX \
  --resource-group $RG \
  --startup-file "startup.sh"

# Keep the app warm — avoids 30-60s cold starts that reload the ML model
az webapp config set \
  --name phishguard-backend-$SUFFIX \
  --resource-group $RG \
  --always-on true

# Allow publish-profile (basic-auth) deployments used by the GitHub workflow
az resource update \
  --resource-group $RG \
  --namespace Microsoft.Web \
  --resource-type basicPublishingCredentialsPolicies \
  --name scm \
  --parent "sites/phishguard-backend-$SUFFIX" \
  --set properties.allow=true
```

### 1.4 Static Web App (Frontend)

```bash
az staticwebapp create \
  --name phishguard-frontend \
  --resource-group $RG \
  --location $LOC \
  --sku Free
```

### 1.5 Communication Services (Email OTP)

```bash
# Communication Services resource
az extension add --name communication
az communication create \
  --name phishguard-comm-$SUFFIX \
  --resource-group $RG \
  --location global \
  --data-location UnitedStates

# Email service + Azure-managed domain
az communication email create \
  --name phishguard-email-$SUFFIX \
  --resource-group $RG \
  --location global \
  --data-location UnitedStates

az communication email domain create \
  --domain-name AzureManagedDomain \
  --email-service-name phishguard-email-$SUFFIX \
  --resource-group $RG \
  --location global \
  --domain-management AzureManaged

# Link the domain to the Communication Services resource
DOMAIN_ID=$(az communication email domain show \
  --domain-name AzureManagedDomain \
  --email-service-name phishguard-email-$SUFFIX \
  --resource-group $RG --query id -o tsv)

az communication update \
  --name phishguard-comm-$SUFFIX \
  --resource-group $RG \
  --linked-domains $DOMAIN_ID

# Connection string for app settings
az communication list-key --name phishguard-comm-$SUFFIX --resource-group $RG \
  --query primaryConnectionString -o tsv
```

The Azure-managed sender address is `DoNotReply@<from-sender-domain>.azurecomm.net`.
For the current deployment it is:
`DoNotReply@d59bf631-a472-4514-a1e1-23f8827210ec.azurecomm.net`.

> **Deliverability:** the `*.azurecomm.net` managed domain works but emails
> often land in spam. For production, verify a **custom domain** in ACS
> (add DNS verification + SPF/DKIM records, then relink).

---

## Step 2: Configure Backend Application Settings

```bash
SWA=https://brave-sky-03c9cf41e.7.azurestaticapps.net
BE=phishguard-backend-35ohcu.azurewebsites.net

az webapp config appsettings set \
  --name phishguard-backend-35ohcu \
  --resource-group phishguard-rg \
  --settings \
    DJANGO_SECRET_KEY='<random-50+ char string>' \
    DEBUG='False' \
    ALLOWED_HOSTS="$BE" \
    CORS_ALLOWED_ORIGINS="$SWA" \
    CSRF_TRUSTED_ORIGINS="$SWA" \
    FRONTEND_URL="$SWA" \
    DB_HOST='phishguard-db-35ohcu.postgres.database.azure.com' \
    DB_NAME='phishguard' \
    DB_USER='phishguardadmin' \
    DB_PASSWORD='<your-db-password>' \
    DB_PORT='5432' \
    GOOGLE_SAFEBROWSING_API_KEY='<your-key>' \
    VIRUSTOTAL_API_KEY='<your-key>' \
    AZURE_COMMUNICATION_CONNECTION_STRING='<acs-connection-string>' \
    AZURE_EMAIL_SENDER_ADDRESS='DoNotReply@d59bf631-a472-4514-a1e1-23f8827210ec.azurecomm.net' \
    SCM_DO_BUILD_DURING_DEPLOYMENT='true'
```

`SCM_DO_BUILD_DURING_DEPLOYMENT=true` makes Oryx install `requirements.txt`
during deploy. Setting `DB_HOST` switches Django from SQLite to PostgreSQL
(see `settings.py`).

Generate a secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

---

## Step 3: CI/CD via GitHub Actions

Repo: **BharathS047/PhishGuard**, branch **main**. Two workflows:

- `.github/workflows/deploy-backend.yml` — triggers on `backend/**` changes;
  deploys via **publish-profile auth** (`azure/webapps-deploy@v3`).
- `.github/workflows/deploy-frontend.yml` — triggers on `frontend/**` changes;
  builds + deploys to the Static Web App.

### Required GitHub Secrets

| Secret | How to get it |
|---|---|
| `AZURE_BACKEND_PUBLISH_PROFILE` | `az webapp deployment list-publishing-profiles --name phishguard-backend-35ohcu --resource-group phishguard-rg --xml` |
| `AZURE_STATIC_WEB_APPS_API_TOKEN` | `az staticwebapp secrets list --name phishguard-frontend --resource-group phishguard-rg --query properties.apiKey -o tsv` |
| `REACT_APP_API_URL` | `https://phishguard-backend-35ohcu.azurewebsites.net` |

Set them with `--body` (see warning below):

```bash
az webapp deployment list-publishing-profiles --name phishguard-backend-35ohcu \
  --resource-group phishguard-rg --xml | gh secret set AZURE_BACKEND_PUBLISH_PROFILE --repo BharathS047/PhishGuard
gh secret set REACT_APP_API_URL --repo BharathS047/PhishGuard \
  --body "https://phishguard-backend-35ohcu.azurewebsites.net"
```

> ⚠️ **Do NOT pipe a string into `gh secret set` from Windows PowerShell** — it
> prepends a UTF-8 BOM (`﻿`) to the value. A BOM on `REACT_APP_API_URL`
> made the React bundle bake `"﻿https://..."`, an invalid URL that the
> browser treated as relative, so login/register POSTs hit the static host and
> returned **405**. Always use `gh secret set NAME --repo R --body "value"`.

> **Note:** the backend workflow does **not** set `startup-command` — that input
> is rejected when using publish-profile auth. The startup file is configured on
> the web app instead (Step 1.3, `az webapp config set --startup-file`).

> The stale `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_CREDENTIALS`,
> `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID` secrets are from the previous
> service-principal-based deploy and are no longer used; they can be deleted.

---

## Step 4: Deploy

### Option A: GitHub Actions (automated)

Push to `main`. Backend changes trigger `deploy-backend.yml`; frontend changes
trigger `deploy-frontend.yml`. To deploy without a matching change, dispatch
manually:

```bash
gh workflow run deploy-frontend.yml --repo BharathS047/PhishGuard --ref main
gh workflow run deploy-backend.yml  --repo BharathS047/PhishGuard --ref main
```

### Option B: Manual (one-time)

```bash
# Backend
cd backend
az webapp up --name phishguard-backend-35ohcu --resource-group phishguard-rg --runtime "PYTHON:3.12"

# Frontend
cd frontend
REACT_APP_API_URL=https://phishguard-backend-35ohcu.azurewebsites.net npm run build
npx @azure/static-web-apps-cli deploy ./build
```

---

## Step 5: Verify

```bash
# Backend health (expects {"status":"healthy", services: {database:"ok", ml_model:"ok"}})
curl https://phishguard-backend-35ohcu.azurewebsites.net/health/

# Frontend
curl -I https://brave-sky-03c9cf41e.7.azurestaticapps.net

# Logs
az webapp log tail --name phishguard-backend-35ohcu --resource-group phishguard-rg
```

---

## Operational Notes / Gotchas

- **Cold starts:** keep `alwaysOn=true`. Without it, App Service unloads after
  ~20 min idle and the next request takes 30–60s to re-import the ML stack and
  reload the model — surfaced in the UI as "Error connecting to the server".
- **First scan of an unknown domain** is slow (live WHOIS + page fetch +
  VirusTotal + Safe Browsing). The frontend uses a 180s client timeout.
- **gh secret BOM** issue — see the warning in Step 3.
- **publish-profile vs startup-command** incompatibility — see the note in Step 3.
- **PostgreSQL region restriction** on this subscription — see the note up top.
- **Running one-off Django commands** (e.g. deleting a user): the app runs from
  a packed Oryx tarball, so Kudu `/api/command` has no venv. Easiest path is to
  add a temporary DB firewall rule for your IP, run the project's local venv
  against the prod DB by exporting `DB_HOST/DB_NAME/DB_USER/DB_PASSWORD/DB_PORT/
  DJANGO_SECRET_KEY` and `python manage.py shell -c "..."`, then remove the rule.

---

## Rotate Compromised API Keys

Previous API keys were exposed in git history. Rotate them:

1. **Google Safe Browsing**: https://console.cloud.google.com/apis/credentials
2. **VirusTotal**: https://www.virustotal.com/gui/my-apikey
3. **Azure Communication Services**: Azure Portal > Communication Services > Keys > Regenerate

After rotating, update the corresponding app settings (Step 2).

---

## Cost Estimate (Monthly)

| Resource | SKU | ~Cost |
|---|---|---|
| App Service | B1 | ~$13 |
| PostgreSQL Flexible | B1ms | ~$12 |
| Static Web Apps | Free tier | $0 |
| Communication Services | Pay-as-you-go | ~$0.25/1000 emails |
| **Total** | | **~$25/month** |
