#!/usr/bin/env node
/**
 * Release-integrity guard.
 *
 * VERIGUARD AI menjalankan mesin scanner dari source yang sama di tiga runtime
 * (Worker, host Node, dan Functions). Bila satu berkas source belum terlacak
 * Git, build yang diambil dari repository menghasilkan artefak yang diam-diam
 * kehilangan fitur, termasuk lapisan keamanan. Skrip ini membuat kondisi itu
 * gagal keras sebelum build, bukan setelah deploy.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const SOURCE_EXT = /\.(ts|tsx|mts|cts)$/;
const RELEASE_PATHS = [
  'functions/src',
  'functions/test',
  'workers/src',
  'workers/test',
  'server/src',
  'server/test',
  'web/src',
  'web/config',
  'web/scripts',
  'evaluation',
];
const RELEASE_FILES = ['firestore.rules', 'firestore.indexes.json', 'firebase.json', 'workers/wrangler.toml'];

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

function insideRelease(path) {
  if (RELEASE_FILES.includes(path)) return true;
  return RELEASE_PATHS.some((root) => path === root || path.startsWith(root + '/'));
}

function isRelevant(path) {
  if (insideRelease(path)) return SOURCE_EXT.test(path) || !/\./.test(path);
  return false;
}

function untrackedFiles() {
  const others = git(['ls-files', '--others', '--exclude-standard']).split(/\r?\n/).filter(Boolean);
  const found = new Set(others.filter((file) => insideRelease(file) || isRelevant(file)));
  return [...found].sort();
}

function staleBuildOutput() {
  const roots = [
    ['functions/src', 'functions/lib'],
    ['server/src', 'server/dist'],
  ];
  const stale = [];
  for (const [sourceRoot, outputRoot] of roots) {
    if (!existsSync(outputRoot)) continue;
    for (const file of walk(sourceRoot)) {
      if (!SOURCE_EXT.test(file)) continue;
      const relative = file.slice(sourceRoot.length + 1).replace(/\.tsx?$/, '.js');
      // outDir dapat menyalin rootDir ke dalam dist (dist/server/src/..) atau tidak (lib/..).
      const candidates = [`${outputRoot}/${relative}`, `${outputRoot}/${sourceRoot}/${relative}`];
      const built = candidates.find((candidate) => existsSync(candidate));
      if (!built) {
        stale.push(`${file} (tidak ada output build)`);
        continue;
      }
      if (statSync(file).mtimeMs > statSync(built).mtimeMs) {
        stale.push(`${file} (output lebih lama dari source)`);
      }
    }
  }
  return stale;
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(full.replace(/\\/g, '/'));
  }
  return out;
}

function main() {
  if (process.env.VERIGUARD_ALLOW_UNTRACKED === '1') {
    console.warn('[release-guard] dilewati lewat VERIGUARD_ALLOW_UNTRACKED=1; jangan pakai ini untuk rilis.');
    return;
  }

  // --pre-build hanya membuktikan source terlacak Git; pemeriksaan output basi
  // harus berjalan SETELAH build, karena build itulah yang menyegarkan output.
  const preBuild = process.argv.includes('--pre-build');

  let inRepo = true;
  try {
    git(['rev-parse', '--is-inside-work-tree']);
  } catch {
    inRepo = false;
  }
  if (!inRepo) {
    console.error('[release-guard] build ini bukan checkout Git; tidak dapat membuktikan source terlacak.');
    process.exitCode = 1;
    return;
  }

  const untracked = untrackedFiles();
  const stale = preBuild ? [] : staleBuildOutput();

  for (const file of untracked) console.error('[release-guard] source rilis belum terlacak Git: ' + file);
  for (const item of stale) console.error('[release-guard] output build tertinggal dari source: ' + item);

  if (untracked.length > 0 || stale.length > 0) {
    console.error(
      `[release-guard] GAGAL: ${untracked.length} berkas belum di-commit, ${stale.length} output build basi. ` +
        'Build dari repository akan kehilangan fitur. Commit (atau hapus) berkas tersebut lalu jalankan build ulang.',
    );
    process.exitCode = 1;
    return;
  }

  const dirty = git('status --porcelain'.split(' '))
    .split(/\r?\n/)
    .filter((line) => /^ M /.test(line) && insideRelease(line.slice(3).trim()));
  if (dirty.length > 0) {
    console.warn(
      `[release-guard] peringatan: ${dirty.length} berkas rilis terlacak tapi punya perubahan belum di-commit. ` +
        'Artefak lokal tidak dapat direproduksi dari commit.',
    );
  }
  console.log('[release-guard] LULUS - seluruh source rilis terlacak Git dan output build tidak tertinggal.');
}

main();
