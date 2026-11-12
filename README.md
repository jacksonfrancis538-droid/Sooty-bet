# SOOTY BET

Responsive sports-betting interface preview.

## Current status

This is a **frontend preview**, not a production sportsbook. Fixtures and odds are illustrative sample data. Live event feeds are not connected. Bet placement, deposits, and withdrawals are disabled.

## Deploy on Render

Create a Render Static Site connected to this repository:

- Branch: `main`
- Build command: leave empty
- Publish directory: `.`

Render will serve `index.html` over a public `onrender.com` URL.

## Backend status

The frontend contains API calls intended for a separately deployed backend. No backend service is currently deployed, so login, wallet history, bet history, and admin data will not function until a compatible API is deployed and the frontend API base URL is configured.

## Safety and compliance

Do not accept customer funds or wagers using this preview. Before any real-money operation, obtain applicable Nigerian legal and regulatory approvals and implement age verification, KYC/AML, responsible-gambling controls, licensed odds/data feeds, payment-provider integration, secure ledgering, server-side bet validation and settlement, audit logging, fraud controls, and independent security testing.
