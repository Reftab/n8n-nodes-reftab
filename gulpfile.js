const { src, dest, series } = require('gulp');

function buildIcons() {
  return src('nodes/**/*.{png,svg}')
    .pipe(dest('dist/nodes'));
}

function buildCodex() {
  return src('nodes/**/*.node.json')
    .pipe(dest('dist/nodes'));
}

exports['build:icons'] = series(buildIcons, buildCodex);
