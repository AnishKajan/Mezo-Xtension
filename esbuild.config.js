const esbuild = require('esbuild');
esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  outfile: 'dist/index.js',
  format: 'esm',
  external: ['react', 'react-dom'],
  target: 'es2020',
}).catch(() => process.exit(1));
