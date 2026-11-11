# Passport website

A product preview for Passport, built with Next.js, React, Tailwind's reset,
Motion for scroll parallax, and the Stageshow kit for the product
illustrations. System fonts, local assets, no analytics and no data
collection.

```sh
pnpm --dir web install --frozen-lockfile
pnpm --dir web dev            # http://127.0.0.1:3000
pnpm --dir web check          # tsc, eslint, prettier
pnpm --dir web build
pnpm --dir web exec playwright install chromium
pnpm --dir web test
```

The page opens on the iPhone app, told as one request and driven by the
scroll: read the chip, get asked, prove one fact. A grid of feature tiles
follows, then a section for verifiers. The iPhone is the Stageshow kit's
phone frame; the passport under it uses the app icon as its cover. The scenes
(`src/components/story.tsx`, `src/components/bento.tsx`,
`src/components/verifiers.tsx`) show the ICAO specimen passport and sample
data. They are pictures of the app, not controls. The kit is vendored in
`src/stageshow/kit` (see `src/stageshow/README.md`) and excluded from lint.

Keep the claims in line with the top-level README and `docs/security.md`: the
code is experimental and unaudited, the keys are development keys, and there
is no shared registry yet. The FAQ and the closing section say so.

The navigation shows the repository's GitHub star count. `src/app/page.tsx`
reads it on the server at most once an hour, so visitors' browsers make no
third-party request; the count is left out when GitHub cannot be reached.

## Deployment

Vercel project `passport` belongs to `ludogalabru-1362s-projects`. Project
root: `web`. Framework: Next.js. Node: 24.x. Install:
`pnpm install --frozen-lockfile`. Build: `pnpm run check && pnpm run build`.

GitHub Actions (`.github/workflows/web.yml`) runs formatting, TypeScript,
ESLint, the production build and the Chromium tests at desktop and mobile
sizes. The Vercel GitHub integration deploys `main` to production and creates
branch previews. No Vercel access token belongs in this repository or its
workflows.

Custom hostname: `passport.scarce.sh`, a CNAME on Cloudflare pointing at the
value Vercel shows for the project. Recheck with:

```sh
vercel domains inspect passport.scarce.sh --scope ludogalabru-1362s-projects
```
