# Publishing

## Local Preview Workflow

Install the documentation dependencies:

```sh
python3 -m pip install -r requirements-docs.txt
```

Start the local preview server:

```sh
python3 -m mkdocs serve
```

Build the static site in strict mode:

```sh
python3 -m mkdocs build --strict
```

The generated site output is written to `site/`.

## Repository Files That Power The Site

- `mkdocs.yml`: navigation, theme, Markdown extensions, and site output
- `docs/`: source Markdown pages, including the existing runbooks
- `requirements-docs.txt`: local and CI documentation dependencies
- `.github/workflows/docs-pages.yml`: GitHub Pages build and deploy workflow

## GitHub Pages Deployment Model

The repository now includes a workflow that:

1. checks out the repository
2. installs the docs dependencies
3. runs `mkdocs build --strict`
4. uploads the generated `site/` directory as the Pages artifact
5. deploys that artifact with the official GitHub Pages actions

The workflow triggers on pushes to `main` that touch docs-related files and can also be run manually.

## Required Repository Setting

GitHub Pages still needs to be configured once in the repository settings:

- open `Settings -> Pages`
- set `Build and deployment` to `GitHub Actions`

After that, pushes to `main` will publish the documentation site automatically.

## Recommended Review Rules

- run `mkdocs build --strict` before merging substantial docs changes
- keep the root README concise and move long-form operational guidance into the site
- when behavior, API shape, or example configs change, update the corresponding docs page or runbook in the same PR