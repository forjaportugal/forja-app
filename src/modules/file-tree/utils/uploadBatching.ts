// Pure helpers behind folder uploads: which paths to skip, how to split a large
// selection into server-sized batches, and how to run those batches one after
// another with a single combined progress value. Kept free of React so they
// can be unit tested directly.

/** Server-side multer limit per request (server/modules/file-tree/file-tree.module.ts). */
export const MAX_FILES_PER_UPLOAD_REQUEST = 20;

/** Overall cap for one upload action (folder picker, drop or file picker). */
export const MAX_TOTAL_UPLOAD_FILES = 5000;

/**
 * Heavy or generated folders that are never worth uploading: they are rebuilt
 * from lockfiles/requirements on the server. `.git` is intentionally absent —
 * the history matters.
 */
export const SKIPPED_UPLOAD_DIRECTORIES: ReadonlySet<string> = new Set([
  'node_modules',
  '.venv',
  'venv',
  '__pycache__',
  '.next',
  '.cache',
]);

/** Operating-system junk files dropped from folder uploads. */
export const IGNORED_UPLOAD_FILES: ReadonlySet<string> = new Set(['.DS_Store', 'Thumbs.db', 'desktop.ini']);

export const splitUploadPath = (relativePath: string) => relativePath.split(/[\\/]/).filter(Boolean);

/**
 * True when a directory name should be skipped. The root folder the user picked
 * or dropped (depth 0) is never skipped: choosing it explicitly means they want it.
 */
export const isSkippedUploadDirectory = (name: string, depth: number) =>
  depth > 0 && SKIPPED_UPLOAD_DIRECTORIES.has(name);

export type UploadPathSkipReason = { kind: 'directory'; directoryPath: string } | { kind: 'junk' } | null;

/** Decide whether one file (by its relative path) should be left out of an upload. */
export const getUploadPathSkipReason = (relativePath: string): UploadPathSkipReason => {
  const segments = splitUploadPath(relativePath);
  if (segments.length === 0) {
    return null;
  }

  // Only files that came from a folder carry directory segments; loose files are
  // uploaded exactly as chosen.
  if (segments.length === 1) {
    return null;
  }

  for (let index = 0; index < segments.length - 1; index += 1) {
    if (isSkippedUploadDirectory(segments[index], index)) {
      return { kind: 'directory', directoryPath: segments.slice(0, index + 1).join('/') };
    }
  }

  if (IGNORED_UPLOAD_FILES.has(segments[segments.length - 1])) {
    return { kind: 'junk' };
  }

  return null;
};

export type UploadSkipSummary = {
  /** Files that were known and dropped (picker gives them all; drops never read skipped folders). */
  skippedFileCount: number;
  /** Relative paths of skipped heavy folders, e.g. "my-app/node_modules". */
  skippedDirectories: string[];
};

export const emptyUploadSkipSummary = (): UploadSkipSummary => ({ skippedFileCount: 0, skippedDirectories: [] });

export const mergeUploadSkipSummaries = (a: UploadSkipSummary, b: UploadSkipSummary): UploadSkipSummary => ({
  skippedFileCount: a.skippedFileCount + b.skippedFileCount,
  skippedDirectories: Array.from(new Set([...a.skippedDirectories, ...b.skippedDirectories])),
});

/** Filter a flat file list (from the folder picker or a drop) by relative path. */
export const filterUploadFiles = <T>(
  files: T[],
  getRelativePath: (file: T) => string,
): { files: T[]; skipped: UploadSkipSummary } => {
  const kept: T[] = [];
  const skippedDirectories = new Set<string>();
  let skippedFileCount = 0;

  for (const file of files) {
    const reason = getUploadPathSkipReason(getRelativePath(file));
    if (!reason) {
      kept.push(file);
      continue;
    }
    skippedFileCount += 1;
    if (reason.kind === 'directory') {
      skippedDirectories.add(reason.directoryPath);
    }
  }

  return { files: kept, skipped: { skippedFileCount, skippedDirectories: Array.from(skippedDirectories) } };
};

/** Human-readable note about what was skipped, or null when nothing was. */
export const formatUploadSkipSummary = (skipped: UploadSkipSummary): string | null => {
  const folderCount = skipped.skippedDirectories.length;
  if (folderCount === 0 && skipped.skippedFileCount === 0) {
    return null;
  }

  if (folderCount === 0) {
    return `skipped ${skipped.skippedFileCount} system ${skipped.skippedFileCount === 1 ? 'file' : 'files'}`;
  }

  const names = Array.from(
    new Set(skipped.skippedDirectories.map((directoryPath) => splitUploadPath(directoryPath).pop() || directoryPath)),
  ).join(', ');
  const folderLabel = folderCount === 1 ? 'folder' : 'folders';
  const fileNote =
    skipped.skippedFileCount > 0
      ? `, ${skipped.skippedFileCount} ${skipped.skippedFileCount === 1 ? 'file' : 'files'}`
      : '';
  return `skipped ${folderCount} ${folderLabel} (${names})${fileNote}`;
};

/** Split a list into consecutive batches of at most `batchSize` items. */
export const chunkIntoBatches = <T>(items: T[], batchSize = MAX_FILES_PER_UPLOAD_REQUEST): T[][] => {
  if (!Number.isInteger(batchSize) || batchSize < 1) {
    throw new Error(`Invalid batch size: ${batchSize}`);
  }
  const batches: T[][] = [];
  for (let index = 0; index < items.length; index += batchSize) {
    batches.push(items.slice(index, index + batchSize));
  }
  return batches;
};

export type BatchUploadResult<T> =
  | { status: 'complete'; uploadedCount: number; requestedCount: number }
  | {
      status: 'failed';
      uploadedCount: number;
      requestedCount: number;
      error: Error;
      /** 0-based index of the batch that failed. */
      failedBatchIndex: number;
      batchCount: number;
      /** Every file from the failed batch onward (none of them are known to be stored). */
      notUploaded: T[];
    };

/**
 * Upload batches strictly one after another. Progress is combined across all
 * batches, weighted by byte size (falls back to file count when every file is
 * empty), and never reaches 100 before the last response arrives. Stops at the
 * first failed batch.
 */
export const runBatchedUpload = async <T>({
  files,
  batchSize = MAX_FILES_PER_UPLOAD_REQUEST,
  getSize,
  uploadBatch,
  onProgress,
}: {
  files: T[];
  batchSize?: number;
  getSize: (file: T) => number;
  /** Uploads one batch; `onBatchProgress` takes a 0..1 fraction. Resolves with the stored count. */
  uploadBatch: (batch: T[], batchIndex: number, onBatchProgress: (fraction: number) => void) => Promise<number>;
  onProgress?: (percent: number) => void;
}): Promise<BatchUploadResult<T>> => {
  const batches = chunkIntoBatches(files, batchSize);
  const totalBytes = files.reduce((sum, file) => sum + Math.max(0, getSize(file)), 0);
  const weightOf = (batch: T[]) =>
    totalBytes > 0 ? batch.reduce((sum, file) => sum + Math.max(0, getSize(file)), 0) : batch.length;
  const totalWeight = totalBytes > 0 ? totalBytes : files.length;

  let completedWeight = 0;
  let uploadedCount = 0;
  let lastReported = -1;

  const report = (weightDone: number) => {
    if (!onProgress || totalWeight === 0) return;
    const percent = Math.min(99, Math.floor((weightDone / totalWeight) * 100));
    if (percent !== lastReported) {
      lastReported = percent;
      onProgress(percent);
    }
  };

  for (let batchIndex = 0; batchIndex < batches.length; batchIndex += 1) {
    const batch = batches[batchIndex];
    const batchWeight = weightOf(batch);
    try {
      const stored = await uploadBatch(batch, batchIndex, (fraction) => {
        const clamped = Math.min(1, Math.max(0, fraction));
        report(completedWeight + batchWeight * clamped);
      });
      uploadedCount += stored;
      completedWeight += batchWeight;
      report(completedWeight);
    } catch (err) {
      return {
        status: 'failed',
        uploadedCount,
        requestedCount: files.length,
        error: err instanceof Error ? err : new Error(String(err)),
        failedBatchIndex: batchIndex,
        batchCount: batches.length,
        notUploaded: batches.slice(batchIndex).flat(),
      };
    }
  }

  return { status: 'complete', uploadedCount, requestedCount: files.length };
};

/** Short list of names for an error message: "a, b, c and 12 more". */
export const summarizeFileNames = (names: string[], limit = 5): string => {
  if (names.length <= limit) {
    return names.join(', ');
  }
  return `${names.slice(0, limit).join(', ')} and ${names.length - limit} more`;
};

/**
 * Turn a hidden <input type="file"> into a folder picker. React/TS do not know
 * the non-standard `webkitdirectory` attribute, so it is set on the DOM node
 * (use as a ref callback). Chromium, Electron, Firefox and Safari all honour it.
 */
export const enableDirectoryPicker = (input: HTMLInputElement | null) => {
  if (!input) return;
  input.setAttribute('webkitdirectory', '');
  input.setAttribute('directory', '');
};
