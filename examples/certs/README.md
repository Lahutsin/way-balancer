# Example Certificate Inputs

This directory documents the expected PEM inputs for HTTPS listener examples.

- `dev-server.pem`: PEM certificate chain for the HTTPS listener
- `dev-server.key`: PEM private key for the HTTPS listener

These files are not committed as reusable repository artifacts. Generate or provision development-only certificate material before using `examples/load-balancer/https-termination.json` in a local environment.