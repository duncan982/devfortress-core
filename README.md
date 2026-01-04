# DevFortress Core

Open-source core package for DevFortress platform.

## Installation

```bash
npm install @devfortress/core
```

## Usage

```typescript
import { createClient } from '@devfortress/core';

const client = createClient({
  supabaseUrl: process.env.SUPABASE_URL,
  supabaseKey: process.env.SUPABASE_ANON_KEY,
});
```

## Documentation

For full documentation, visit: https://docs.devfortress.io

## License

MIT - See LICENSE file for details
