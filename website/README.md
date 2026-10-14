# BaseHero website

This directory builds the site at [basehero.com](https://basehero.com/). It uses
Cloudflare Workers Static Assets, with a Worker for signup and confirmation.
The site's fonts and images are bundled locally.

From this directory, use Node.js 24:

```sh
npm ci --ignore-scripts
npm run check      # build, tests and local asset/link checks
npm run preview    # local Wrangler preview
```

The build output is `dist/`. The local preview runs with signup disabled. Tests
use an in-memory SQLite D1 adapter and a stub mail sink. The Worker source is in
`src/`, the static pages and assets in `public/`, and the D1 schema in
`schema.sql`.
