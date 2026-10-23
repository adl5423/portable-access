console.error("This security adapter requires a dedicated trusted production Netlify site. Deploy Previews and branch deploys are disabled by this template. Site settings must also exclude untrusted builds; this build check is not an isolation boundary.");
process.exitCode = 1;
