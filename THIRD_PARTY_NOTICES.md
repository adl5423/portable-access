# Third-party notices

PAP source is Apache-2.0. Dependencies are installed separately and keep their own licenses. Release distributions must retain bundled dependency notices.

| Component | License | Distribution |
| --- | --- | --- |
| aiohttp | Apache-2.0 AND MIT | Python dependency |
| cryptography | Apache-2.0 OR BSD-3-Clause | Python dependency, includes OpenSSL notices |
| PyJWT | MIT | Python dependency |
| Pydantic | MIT | Python dependency |
| Netlify Functions and Blobs libraries | MIT | Node dependencies |
| TypeScript, esbuild | Apache-2.0, MIT | Build dependencies |
| OpenBao | MPL-2.0 | Independent service, not included in the PAP wheel |
| Caddy | Apache-2.0 | Independent gateway, not included in the PAP wheel |

The release workflow records installed Python license metadata and Node production dependency metadata. Check the lock files and package metadata for exact versions and transitive notices. No ownership of dependency names or provider trademarks is claimed.
