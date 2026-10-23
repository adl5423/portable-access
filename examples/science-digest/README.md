# Combined science and infrastructure digest

A complete independent Netlify project for the PAP `science-digest` connector operation. It uses its own production site, grant and tenant. The authority retrieves provider data and produces a bounded OpenAI summary; this application has no provider API key.

- `GET /api/briefing` requires a PAP DPoP credential and original GET proof. It relays those headers to the fixed broker operation without consuming the proof locally.
- The event-only `deploySucceeded` Function performs two protected reads at least 65 seconds apart. It caches a validated public-data result in private, project-scoped Blobs storage.
- `GET /api/result` reads only that existing sanitized result. It cannot start generation or spend an API quota.
- `GET /.well-known/pap/site-proof/:challenge_id` publishes only an internally generated, expiring public origin proof.
- `GET /status.json` reports configuration status.

The source defaults are disabled. See the repository's [use-case deployment guide](../../docs/use-cases.md) for registration, encrypted key provisioning, cost bounds and acceptance evidence. For a standalone release archive, use the same guide on GitHub; the archive includes its Node SDK in `vendor/`.

In the repository, build the SDK first:

```sh
(cd ../../adapters/netlify && npm ci --ignore-scripts && npm run build)
npm ci --ignore-scripts
npm run check
```

In the standalone release archive, start with `npm ci --ignore-scripts` directly. Set the Netlify base directory to this project when deploying the complete repository, or deploy the extracted standalone directory as its own project. Preview and branch deploys are disabled because the canonical production site is the identity boundary. Keep `.netlify/` untracked.

Use `npm run configure -- --help` to see required public binding arguments. No provider secret is accepted by that command. See `tools/configure.mjs` for the exact accepted options. Configure a dedicated upstream key and provider budget for sustained use. NASA and NLR public `DEMO_KEY` values are quota-limited starters, not private application secrets.

Apache-2.0. See the root LICENSE or the LICENSE included in a standalone release archive.
