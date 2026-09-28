import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

export default defineConfig({
  // wasm() + topLevelAwait(): the generated WASM package is built with
  // `wasm-pack build --target bundler` (see package.json's prepare-wasm
  // script), whose glue code uses a static `.wasm` import plus top-level
  // await for instantiation - these plugins are what actually teach
  // Vite/Vitest how to load that import (wasm-pack's --target web
  // alternative instead does a runtime fetch() of the .wasm binary, which
  // works in a real browser or under Vite's dev server but has no HTTP
  // server to hit under Vitest's Node-based test runner).
  plugins: [react(), wasm(), topLevelAwait()],
  build: {
    // ES2022 is the floor at which esbuild can keep the wasm-bindgen glue's
    // destructuring patterns as-is. Vite's default build target ('modules'
    // = ES2020/Chrome87/Safari14) makes vite-plugin-top-level-await try to
    // downlevel those patterns to ES2020, which esbuild cannot do, so
    // `vite build` fails with "Transforming destructuring ... is not
    // supported yet". ES2022 (Chrome 94+/Firefox 93+/Safari 15.4+) needs no
    // downleveling and is the sensible floor for a web client that already
    // depends on WASM + top-level await. This only affects the production
    // build, not the dev server or Vitest.
    target: 'es2022',
  },
  // Relative base so the published artifact is relocatable: index.html
  // references its assets as `./assets/...` instead of `/assets/...`. The
  // CI artifact unzips to a `web-client-dist/` folder, so when a consumer
  // serves it from any subpath (e.g. `npx serve` in the parent dir → the
  // page lives at `/web-client-dist/`), absolute `/assets/...` paths 404.
  // A relative base makes the same zip work at the server root or any
  // subpath, on any static host or GitHub Pages project path.
  base: './',
  server: {
    fs: {
      // The generated WASM package (core/bindings/wasm/pkg, produced by
      // `npm run prepare-wasm`) lives outside this project's root
      // (clients/web), which Vite's dev server denies access to by
      // default - allow the monorepo root so imports of that package
      // resolve instead of failing with "Failed to resolve import ...
      // Does the file exist?" even though the file is genuinely present.
      allow: ['../..'],
    },
  },
});
