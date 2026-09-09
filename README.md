# AdFlow AI — Final Launch Candidate

A deployable SaaS foundation for usage-based ad creative generation.

## Included
- Express production server
- SQLite persistence with WAL
- API keys
- Credits and usage metering
- Generation endpoint
- Plans endpoint
- Usage endpoint
- Dockerfile
- Environment template
- Minimal browser client

## Run locally
```bash
npm install
npm start
```
Open http://localhost:3000

## API
`POST /api/signup` → create/retrieve account and API key
`GET /api/me` with `x-api-key`
`POST /api/generate` with `x-api-key` and `{ "product": "..." }`
`GET /api/usage` with `x-api-key`
`GET /api/plans`

## Production blockers
Live payments and a paid AI provider require provider accounts/credentials and webhook configuration. They cannot be truthfully activated without those external credentials. The billing endpoint intentionally returns 501 until configured.
