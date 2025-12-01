# n8n-nodes-reftab

This is an n8n community node for [Reftab](https://reftab.com) - Asset Management Software.

[n8n](https://n8n.io/) is a [fair-code licensed](https://docs.n8n.io/reference/license/) workflow automation platform.

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation.

### npm Installation

```bash
npm install n8n-nodes-reftab
```

### Manual Installation

1. Navigate to your n8n nodes directory:
   ```bash
   cd ~/.n8n/nodes
   ```

2. Install the package:
   ```bash
   npm install n8n-nodes-reftab
   ```

3. Restart n8n

## Credentials

To use this node, you need a Reftab API key pair:

1. Log into your Reftab account
2. Go to **Settings** > **API Keys**
3. Click **Create API Key**
4. Copy both the **Public Key** and **Secret Key**

In n8n, create new Reftab API credentials and enter both keys.

## Resources

This node supports the following Reftab resources:

### Asset
- **Get** - Get a single asset by ID
- **Get Many** - Get multiple assets with filtering options
- **Create** - Create a new asset
- **Update** - Update an existing asset
- **Delete** - Delete an asset

### Asset Maintenance
- **Get** - Get a maintenance record by ID
- **Get Many** - Get multiple maintenance records with filtering
- **Create** - Create a new maintenance record for an asset

### Loan
- **Get** - Get a loan by ID
- **Get Many** - Get multiple loans with filtering
- **Create** - Create a new loan (check out items)
- **Update** - Update a loan
- **Check In** - Return loaned items

### Reservation
- **Get** - Get a reservation by ID
- **Get Many** - Get multiple reservations with filtering
- **Create** - Create a new reservation
- **Update** - Update a reservation
- **Delete** - Delete a reservation
- **Fulfill** - Convert a reservation to a loan

### Custom API Call
- Make custom API calls to any Reftab endpoint

## Features

- **HMAC Authentication** - Proper signature generation for Reftab API
- **Email Lookups** - Enter email addresses for loanees/users and the node automatically looks up the ID
- **Dynamic Dropdowns** - Locations, categories, and statuses are loaded dynamically
- **Remote Signature** - Option to bypass signature requirements for automated checkouts

## Compatibility

- n8n version 1.0.0 or later
- Node.js 18.x or later

## License

[MIT](LICENSE.md)

## Links

- [Reftab](https://reftab.com)
- [Reftab API Documentation](https://www.reftab.com/api-docs)
- [n8n Community Nodes](https://docs.n8n.io/integrations/community-nodes/)
