import { defineConfig } from 'astro/config';

// SITE/BASE are set by the pages workflow from the GitHub repo; local builds serve from /.
export default defineConfig({
  site: process.env.SITE || 'http://localhost:4321',
  base: process.env.BASE || '/',
  trailingSlash: 'always',
  vite: { server: { fs: { allow: ['..'] } } },
});
