import { useCallback, useEffect, useRef, useState } from 'react';
import type { DragEvent } from 'react';

import { IS_PLATFORM } from '@/shared/utils';
import type { FileTreeUploadProgressState, Project } from '@/shared/types';
import { api } from '@/shared/api';
import { expireAuthSession, getStoredAuthToken, storeAuthToken } from '@/shared/authToken';
import { MAX_FILE_UPLOAD_SIZE_BYTES, MAX_FILE_UPLOAD_SIZE_LABEL } from '@/shared/constants';
import {
  IGNORED_UPLOAD_FILES,
  MAX_FILES_PER_UPLOAD_REQUEST,
  MAX_TOTAL_UPLOAD_FILES,
  emptyUploadSkipSummary,
  filterUploadFiles,
  formatUploadSkipSummary,
  isSkippedUploadDirectory,
  mergeUploadSkipSummaries,
  runBatchedUpload,
  splitUploadPath,
  summarizeFileNames,
} from '@/modules/file-tree/utils/uploadBatching';
import type { UploadSkipSummary } from '@/modules/file-tree/utils/uploadBatching';

type UseFileTreeUploadOptions = {
  selectedProject: Project | null;
  onRefresh: () => void;
  showToast: (message: string, type: 'success' | 'error') => void;
};


type UploadResponse = {
  error?: string;
  message?: string;
  files?: unknown[];
  uploadedCount?: number;
  requestedFileCount?: number;
};

const COMPLETE_PROGRESS_CLEAR_DELAY_MS = 1400;
const ERROR_PROGRESS_CLEAR_DELAY_MS = 3200;
// A partially failed batch upload lists the files that were not stored; keep it
// on screen long enough to read.
const PARTIAL_FAILURE_PROGRESS_CLEAR_DELAY_MS = 12000;

const pluralizeFiles = (count: number) => (count === 1 ? 'file' : 'files');

const getRelativePath = (file: File) => {
  const fileWithRelativePath = file as File & { webkitRelativePath?: string };
  return fileWithRelativePath.webkitRelativePath || file.name;
};

const getFileDisplayName = (file: File) => {
  const relativePath = getRelativePath(file);
  return relativePath.split(/[\\/]/).pop() || file.name;
};

const validateFilesForUpload = (files: File[]): string | null => {
  if (files.length > MAX_TOTAL_UPLOAD_FILES) {
    return `This upload has ${files.length} files; the limit is ${MAX_TOTAL_UPLOAD_FILES} per upload. Upload the folder in smaller parts.`;
  }

  const oversizedFile = files.find((file) => file.size > MAX_FILE_UPLOAD_SIZE_BYTES);
  if (oversizedFile) {
    return `${getFileDisplayName(oversizedFile)} is larger than ${MAX_FILE_UPLOAD_SIZE_LABEL}.`;
  }

  return null;
};

const parseUploadResponse = (xhr: XMLHttpRequest): UploadResponse => {
  if (!xhr.responseText) {
    return {};
  }

  try {
    return JSON.parse(xhr.responseText) as UploadResponse;
  } catch {
    return {};
  }
};

const withSkipNote = (message: string, skipped: UploadSkipSummary) => {
  const note = formatUploadSkipSummary(skipped);
  return note ? `${message} (${note})` : message;
};

const formatUploadSuccessMessage = (uploadedCount: number, requestedFileCount: number, skipped: UploadSkipSummary) => {
  if (uploadedCount !== requestedFileCount) {
    return withSkipNote(`Uploaded ${uploadedCount} of ${requestedFileCount} ${pluralizeFiles(requestedFileCount)}`, skipped);
  }

  return withSkipNote(`Uploaded ${uploadedCount} ${pluralizeFiles(uploadedCount)} successfully`, skipped);
};

const buildUploadFormData = (files: File[], targetPath: string) => {
  const formData = new FormData();
  const relativePaths: string[] = [];

  formData.append('targetPath', targetPath);
  formData.append('requestedFileCount', String(files.length));

  files.forEach((file) => {
    const relativePath = getRelativePath(file);
    const cleanFile = new File([file], relativePath.split(/[\\/]/).pop() || file.name, {
      type: file.type,
      lastModified: file.lastModified,
    });

    formData.append('files', cleanFile);
    relativePaths.push(relativePath);
  });

  formData.append('relativePaths', JSON.stringify(relativePaths));

  return formData;
};

const uploadFormDataWithProgress = (
  projectId: string,
  formData: FormData,
  onProgress: (fraction: number) => void,
) =>
  new Promise<UploadResponse>((resolve, reject) => {
    const xhr = new XMLHttpRequest();

    xhr.open('POST', api.uploadFilesUrl(projectId));

    const token = getStoredAuthToken();
    if (!IS_PLATFORM && token) {
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    }

    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) {
        return;
      }

      // Transfer fraction (0..1); the batch runner keeps 100% for the final
      // server response so the UI can tell transfer from the write/refresh step.
      onProgress(event.total > 0 ? event.loaded / event.total : 0);
    };

    xhr.onload = () => {
      const refreshedToken = xhr.getResponseHeader('X-Refreshed-Token');
      if (refreshedToken) {
        storeAuthToken(refreshedToken);
      }
      if (xhr.getResponseHeader('X-Auth-Error')) {
        expireAuthSession();
      }

      const payload = parseUploadResponse(xhr);
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(payload);
        return;
      }

      reject(new Error(payload.error || payload.message || `Upload failed with status ${xhr.status}`));
    };

    xhr.onerror = () => reject(new Error('Upload failed. Check your connection and try again.'));
    xhr.onabort = () => reject(new Error('Upload canceled.'));

    xhr.send(formData);
  });

// Helper function to read all files from a directory entry recursively
// Heavy/generated folders (node_modules, .venv, ...) are skipped without being
// read, so their file count is unknown; only the folder path is recorded.
const readAllDirectoryEntries = async (
  directoryEntry: FileSystemDirectoryEntry,
  basePath = '',
  skipped: UploadSkipSummary = emptyUploadSkipSummary(),
): Promise<File[]> => {
  const files: File[] = [];

  const reader = directoryEntry.createReader();
  let entries: FileSystemEntry[] = [];

  // Read all entries from the directory (may need multiple reads)
  let batch: FileSystemEntry[];
  do {
    batch = await new Promise<FileSystemEntry[]>((resolve, reject) => {
      reader.readEntries(resolve, reject);
    });
    entries = entries.concat(batch);
  } while (batch.length > 0);

  for (const entry of entries) {
    const entryPath = basePath ? `${basePath}/${entry.name}` : entry.name;

    if (entry.isFile) {
      const fileEntry = entry as FileSystemFileEntry;
      const file = await new Promise<File>((resolve, reject) => {
        fileEntry.file(resolve, reject);
      });

      // Skip ignored files
      if (IGNORED_UPLOAD_FILES.has(file.name)) {
        skipped.skippedFileCount += 1;
        continue;
      }

      // Create a new file with the relative path as the name
      const fileWithPath = new File([file], entryPath, {
        type: file.type,
        lastModified: file.lastModified,
      });
      files.push(fileWithPath);
    } else if (entry.isDirectory) {
      if (isSkippedUploadDirectory(entry.name, splitUploadPath(entryPath).length - 1)) {
        skipped.skippedDirectories.push(entryPath);
        continue;
      }
      const dirEntry = entry as FileSystemDirectoryEntry;
      const subFiles = await readAllDirectoryEntries(dirEntry, entryPath, skipped);
      files.push(...subFiles);
    }
  }

  return files;
};

const collectDroppedFiles = async (dataTransfer: DataTransfer) => {
  const files: File[] = [];
  const skipped = emptyUploadSkipSummary();

  // Use DataTransferItemList for folder support
  const { items } = dataTransfer;
  if (items) {
    for (const item of Array.from(items)) {
      if (item.kind !== 'file') {
        continue;
      }

      const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
      if (!entry) {
        const file = item.getAsFile();
        if (file) {
          files.push(file);
        }
        continue;
      }

      if (entry.isFile) {
        const file = await new Promise<File>((resolve, reject) => {
          (entry as FileSystemFileEntry).file(resolve, reject);
        });
        files.push(file);
      } else if (entry.isDirectory) {
        // Pass the directory name as basePath so files include the folder path
        const dirFiles = await readAllDirectoryEntries(entry as FileSystemDirectoryEntry, entry.name, skipped);
        files.push(...dirFiles);
      }
    }
    return { files, skipped };
  }

  // Fallback for browsers that don't support webkitGetAsEntry
  for (const file of Array.from(dataTransfer.files)) {
    files.push(file);
  }

  return { files, skipped };
};

export const useFileTreeUpload = ({
  selectedProject,
  onRefresh,
  showToast,
}: UseFileTreeUploadOptions) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const [operationLoading, setOperationLoading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<FileTreeUploadProgressState | null>(null);
  const treeRef = useRef<HTMLDivElement>(null);
  const clearProgressTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearProgressTimer = useCallback(() => {
    if (clearProgressTimerRef.current) {
      clearTimeout(clearProgressTimerRef.current);
      clearProgressTimerRef.current = null;
    }
  }, []);

  const scheduleProgressClear = useCallback(
    (delay: number) => {
      clearProgressTimer();
      clearProgressTimerRef.current = setTimeout(() => {
        setUploadProgress(null);
        clearProgressTimerRef.current = null;
      }, delay);
    },
    [clearProgressTimer],
  );

  useEffect(() => clearProgressTimer, [clearProgressTimer]);

  const setUploadError = useCallback(
    (
      message: string,
      fileCount: number,
      targetPath = '',
      fileName?: string,
      progress = 0,
      clearDelay = ERROR_PROGRESS_CLEAR_DELAY_MS,
    ) => {
      setUploadProgress({
        status: 'error',
        progress,
        fileCount,
        fileName,
        targetPath,
        error: message,
      });
      scheduleProgressClear(clearDelay);
    },
    [scheduleProgressClear],
  );

  const uploadFiles = useCallback(
    async (inputFiles: File[], targetPath = '', preSkipped: UploadSkipSummary = emptyUploadSkipSummary()) => {
      // Folder uploads (picker or drop) leave out node_modules, .venv, ... and OS junk.
      const filtered = filterUploadFiles(inputFiles, getRelativePath);
      const files = filtered.files;
      const skipped = mergeUploadSkipSummaries(preSkipped, filtered.skipped);

      if (files.length === 0) {
        const skipNote = formatUploadSkipSummary(skipped);
        if (skipNote) {
          const message = `Nothing to upload (${skipNote})`;
          showToast(message, 'error');
          setUploadError(message, 0, targetPath);
        }
        setDropTarget(null);
        return;
      }

      const fileName = files.length === 1 ? getFileDisplayName(files[0]) : undefined;

      if (!selectedProject) {
        const message = 'Select a project before uploading files.';
        showToast(message, 'error');
        setUploadError(message, files.length, targetPath, fileName);
        return;
      }

      const validationError = validateFilesForUpload(files);
      if (validationError) {
        showToast(validationError, 'error');
        setUploadError(validationError, files.length, targetPath, fileName);
        setDropTarget(null);
        return;
      }

      clearProgressTimer();
      setOperationLoading(true);
      setUploadProgress({
        status: 'uploading',
        progress: 0,
        fileCount: files.length,
        fileName,
        targetPath,
      });

      let latestProgress = 0;

      try {
        // The server accepts at most MAX_FILES_PER_UPLOAD_REQUEST files per
        // request, so large selections go out as sequential batches.
        const result = await runBatchedUpload({
          files,
          batchSize: MAX_FILES_PER_UPLOAD_REQUEST,
          getSize: (file) => file.size,
          uploadBatch: async (batch, _batchIndex, onBatchProgress) => {
            const response = await uploadFormDataWithProgress(
              selectedProject.projectId,
              buildUploadFormData(batch, targetPath),
              onBatchProgress,
            );
            return typeof response.uploadedCount === 'number'
              ? response.uploadedCount
              : response.files?.length ?? batch.length;
          },
          onProgress: (progress) => {
            latestProgress = progress;
            setUploadProgress((current) =>
              current && current.status === 'uploading'
                ? { ...current, progress }
                : current,
            );
          },
        });

        if (result.status === 'failed') {
          const notUploadedPaths = result.notUploaded.map(getRelativePath);
          console.error('Upload error:', result.error, 'Not uploaded:', notUploadedPaths);
          const message =
            result.batchCount > 1
              ? `${result.error.message} Uploaded ${result.uploadedCount} of ${files.length} ${pluralizeFiles(files.length)}; ` +
                `stopped at batch ${result.failedBatchIndex + 1} of ${result.batchCount}. ` +
                `Not uploaded (${notUploadedPaths.length}): ${summarizeFileNames(notUploadedPaths)}`
              : result.error.message;
          showToast(message, 'error');
          setUploadError(
            message,
            files.length,
            targetPath,
            fileName,
            latestProgress,
            result.uploadedCount > 0 ? PARTIAL_FAILURE_PROGRESS_CLEAR_DELAY_MS : ERROR_PROGRESS_CLEAR_DELAY_MS,
          );
          if (result.uploadedCount > 0) {
            onRefresh();
          }
          return;
        }

        setUploadProgress({
          status: 'complete',
          progress: 100,
          fileCount: result.requestedCount,
          uploadedCount: result.uploadedCount,
          fileName,
          targetPath,
        });

        showToast(formatUploadSuccessMessage(result.uploadedCount, result.requestedCount, skipped), 'success');
        scheduleProgressClear(COMPLETE_PROGRESS_CLEAR_DELAY_MS);
        onRefresh();
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Upload failed';
        console.error('Upload error:', err);
        showToast(message, 'error');
        setUploadError(message, files.length, targetPath, fileName, latestProgress);
      } finally {
        setOperationLoading(false);
        setDropTarget(null);
      }
    },
    [
      clearProgressTimer,
      onRefresh,
      scheduleProgressClear,
      selectedProject,
      setUploadError,
      showToast,
    ],
  );

  const handleFileSelect = useCallback(
    async (fileList: FileList | File[]) => {
      await uploadFiles(Array.from(fileList), '');
    },
    [uploadFiles],
  );

  const handleDragEnter = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  // Item rows stop propagation of their own dragover, so reaching this handler
  // means the cursor is over empty space and the drop should target the root.
  const handleDragOver = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDropTarget(null);
  }, []);

  const handleDragLeave = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    // Only set isDragOver to false if we're leaving the entire tree
    if (treeRef.current && !treeRef.current.contains(e.relatedTarget as Node)) {
      setIsDragOver(false);
      setDropTarget(null);
    }
  }, []);

  const handleDrop = useCallback(
    async (e: DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragOver(false);

      const targetPath = dropTarget || '';

      try {
        const { files, skipped } = await collectDroppedFiles(e.dataTransfer);
        await uploadFiles(files, targetPath, skipped);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Could not read dropped files';
        console.error('Upload error:', err);
        showToast(message, 'error');
        setUploadError(message, 0, targetPath);
        setDropTarget(null);
      }
    },
    [dropTarget, setUploadError, showToast, uploadFiles],
  );

  const handleItemDragOver = useCallback((e: DragEvent, itemPath: string) => {
    e.preventDefault();
    e.stopPropagation();
    setDropTarget(itemPath);
  }, []);

  return {
    isDragOver,
    dropTarget,
    operationLoading,
    uploadProgress,
    treeRef,
    uploadFiles,
    handleFileSelect,
    handleDragEnter,
    handleDragOver,
    handleDragLeave,
    handleDrop,
    handleItemDragOver,
  };
};
