import assert from 'node:assert/strict';

import { describe, test } from 'vitest';

import {
  MAX_FILES_PER_UPLOAD_REQUEST,
  chunkIntoBatches,
  enableDirectoryPicker,
  filterUploadFiles,
  formatUploadSkipSummary,
  getUploadPathSkipReason,
  mergeUploadSkipSummaries,
  runBatchedUpload,
  summarizeFileNames,
} from '@/modules/file-tree/utils/uploadBatching';

type FakeFile = { path: string; size: number };
const makeFiles = (count: number, size = 10): FakeFile[] =>
  Array.from({ length: count }, (_, index) => ({ path: `proj/f${index}.txt`, size }));

describe('getUploadPathSkipReason', () => {
  test('keeps normal files, .git and loose files', () => {
    assert.equal(getUploadPathSkipReason('proj/src/index.ts'), null);
    assert.equal(getUploadPathSkipReason('proj/.git/HEAD'), null);
    assert.equal(getUploadPathSkipReason('proj/.git/objects/ab/cdef'), null);
    assert.equal(getUploadPathSkipReason('node_modules'), null);
    assert.equal(getUploadPathSkipReason('Thumbs.db'), null);
    assert.equal(getUploadPathSkipReason('proj/dist/app.js'), null);
  });

  test('skips heavy folders at any depth below the chosen root', () => {
    for (const dir of ['node_modules', '.venv', 'venv', '__pycache__', '.next', '.cache']) {
      assert.deepEqual(getUploadPathSkipReason(`proj/${dir}/x/y.js`), {
        kind: 'directory',
        directoryPath: `proj/${dir}`,
      });
    }
    assert.deepEqual(getUploadPathSkipReason('proj/web/node_modules/react/index.js'), {
      kind: 'directory',
      directoryPath: 'proj/web/node_modules',
    });
    assert.deepEqual(getUploadPathSkipReason('proj\\api\\__pycache__\\m.pyc'), {
      kind: 'directory',
      directoryPath: 'proj/api/__pycache__',
    });
  });

  test('never skips the root folder the user explicitly chose', () => {
    assert.equal(getUploadPathSkipReason('venv/lib/site.py'), null);
    assert.deepEqual(getUploadPathSkipReason('venv/lib/__pycache__/a.pyc'), {
      kind: 'directory',
      directoryPath: 'venv/lib/__pycache__',
    });
  });

  test('skips OS junk inside folders', () => {
    assert.deepEqual(getUploadPathSkipReason('proj/.DS_Store'), { kind: 'junk' });
    assert.deepEqual(getUploadPathSkipReason('proj/img/Thumbs.db'), { kind: 'junk' });
    assert.deepEqual(getUploadPathSkipReason('proj/desktop.ini'), { kind: 'junk' });
  });
});

describe('filterUploadFiles / formatUploadSkipSummary', () => {
  test('counts skipped files and distinct skipped folders', () => {
    const paths = [
      'proj/a.ts',
      'proj/node_modules/x/1.js',
      'proj/node_modules/x/2.js',
      'proj/.venv/bin/python',
      'proj/.DS_Store',
      'proj/.git/config',
    ];
    const { files, skipped } = filterUploadFiles(paths, (p) => p);
    assert.deepEqual(files, ['proj/a.ts', 'proj/.git/config']);
    assert.equal(skipped.skippedFileCount, 4);
    assert.deepEqual(skipped.skippedDirectories.sort(), ['proj/.venv', 'proj/node_modules']);
    assert.equal(formatUploadSkipSummary(skipped), 'skipped 2 folders (.venv, node_modules), 4 files');
  });

  test('summary for nothing / junk only / drop-time folders without counts', () => {
    assert.equal(formatUploadSkipSummary({ skippedFileCount: 0, skippedDirectories: [] }), null);
    assert.equal(formatUploadSkipSummary({ skippedFileCount: 1, skippedDirectories: [] }), 'skipped 1 system file');
    assert.equal(
      formatUploadSkipSummary({ skippedFileCount: 0, skippedDirectories: ['p/node_modules'] }),
      'skipped 1 folder (node_modules)',
    );
  });

  test('merge de-duplicates folders and adds counts', () => {
    const merged = mergeUploadSkipSummaries(
      { skippedFileCount: 2, skippedDirectories: ['p/node_modules'] },
      { skippedFileCount: 3, skippedDirectories: ['p/node_modules', 'p/.next'] },
    );
    assert.equal(merged.skippedFileCount, 5);
    assert.deepEqual(merged.skippedDirectories, ['p/node_modules', 'p/.next']);
  });
});

describe('chunkIntoBatches', () => {
  test('splits into batches of at most the server limit', () => {
    assert.equal(MAX_FILES_PER_UPLOAD_REQUEST, 20);
    const batches = chunkIntoBatches(makeFiles(45));
    assert.deepEqual(batches.map((b) => b.length), [20, 20, 5]);
    assert.deepEqual(batches.flat().map((f) => f.path), makeFiles(45).map((f) => f.path));
    assert.deepEqual(chunkIntoBatches([]), []);
    assert.deepEqual(chunkIntoBatches(makeFiles(20)).map((b) => b.length), [20]);
  });

  test('rejects invalid batch sizes', () => {
    assert.throws(() => chunkIntoBatches([1], 0));
  });
});

describe('runBatchedUpload', () => {
  test('uploads batches sequentially with combined, monotonic progress', async () => {
    const files = makeFiles(50);
    const calls: number[] = [];
    let inFlight = 0;
    const progress: number[] = [];

    const result = await runBatchedUpload({
      files,
      getSize: (f) => f.size,
      uploadBatch: async (batch, index, onBatchProgress) => {
        inFlight += 1;
        assert.equal(inFlight, 1, 'batches must not overlap');
        calls.push(index);
        onBatchProgress(0.5);
        await Promise.resolve();
        onBatchProgress(1);
        inFlight -= 1;
        return batch.length;
      },
      onProgress: (p) => progress.push(p),
    });

    assert.deepEqual(result, { status: 'complete', uploadedCount: 50, requestedCount: 50 });
    assert.deepEqual(calls, [0, 1, 2]);
    assert.ok(progress.length > 0);
    for (let i = 1; i < progress.length; i += 1) {
      assert.ok(progress[i] >= progress[i - 1], `progress went backwards: ${progress}`);
    }
    assert.ok(progress.every((p) => p >= 0 && p <= 99));
    assert.equal(progress[progress.length - 1], 99);
    // After half of the first batch (10 of 50 files by bytes) we are at 20%.
    assert.equal(progress[0], 20);
  });

  test('weights progress by bytes', async () => {
    const files: FakeFile[] = [...makeFiles(20, 1), { path: 'proj/big.bin', size: 980 }];
    const progress: number[] = [];
    await runBatchedUpload({
      files,
      getSize: (f) => f.size,
      uploadBatch: async (batch) => batch.length,
      onProgress: (p) => progress.push(p),
    });
    assert.deepEqual(progress, [2, 99]);
  });

  test('stops at the first failed batch and reports every file not uploaded', async () => {
    const files = makeFiles(65);
    const calls: number[] = [];
    const result = await runBatchedUpload({
      files,
      getSize: (f) => f.size,
      uploadBatch: async (batch, index) => {
        calls.push(index);
        if (index === 1) throw new Error('Upload failed with status 500');
        return batch.length;
      },
    });

    assert.deepEqual(calls, [0, 1]);
    assert.equal(result.status, 'failed');
    if (result.status !== 'failed') return;
    assert.equal(result.uploadedCount, 20);
    assert.equal(result.requestedCount, 65);
    assert.equal(result.failedBatchIndex, 1);
    assert.equal(result.batchCount, 4);
    assert.equal(result.error.message, 'Upload failed with status 500');
    assert.deepEqual(result.notUploaded.map((f) => f.path), files.slice(20).map((f) => f.path));
  });

  test('uses the server-reported stored count and handles empty files', async () => {
    const result = await runBatchedUpload({
      files: makeFiles(25, 0),
      getSize: (f) => f.size,
      uploadBatch: async (batch) => batch.length - 1,
    });
    assert.deepEqual(result, { status: 'complete', uploadedCount: 23, requestedCount: 25 });
  });
});

test('summarizeFileNames truncates long lists', () => {
  assert.equal(summarizeFileNames(['a', 'b']), 'a, b');
  assert.equal(summarizeFileNames(['a', 'b', 'c', 'd', 'e', 'f', 'g'], 5), 'a, b, c, d, e and 2 more');
});

test('enableDirectoryPicker sets the folder-picker attributes', () => {
  const input = document.createElement('input');
  input.type = 'file';
  enableDirectoryPicker(input);
  assert.equal(input.hasAttribute('webkitdirectory'), true);
  assert.equal(input.hasAttribute('directory'), true);
  enableDirectoryPicker(null);
});
