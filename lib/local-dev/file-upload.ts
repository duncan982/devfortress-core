/**
 * Local Development File Upload Service
 * Handles file uploads for local testing (DEVELOPMENT ONLY)
 */

import { writeFile, mkdir } from 'fs/promises';
import { join } from 'path';
import { randomBytes } from 'crypto';
import { logInfo, logWarn, logError } from '@core/lib/logger';

const UPLOAD_DIR = join(process.cwd(), 'uploads');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const ALLOWED_EXTENSIONS = [
  '.js',
  '.ts',
  '.jsx',
  '.tsx',
  '.py',
  '.java',
  '.go',
  '.rb',
  '.php',
  '.rs',
  '.c',
  '.cpp',
  '.cs',
  '.swift',
  '.kt',
];

interface UploadedFile {
  id: string;
  filename: string;
  path: string;
  size: number;
  mimeType: string;
  uploadedAt: Date;
}

export class LocalFileUploadService {
  /**
   * Check if local dev mode is enabled
   */
  static isEnabled(): boolean {
    const devMode = process.env.DEV_LOGIN_ENABLED === 'true';
    const env = process.env.NODE_ENV;

    return devMode && env !== 'production';
  }

  /**
   * Validate file before upload
   */
  static validateFile(file: File): { valid: boolean; error?: string } {
    if (!this.isEnabled()) {
      return {
        valid: false,
        error: 'Local file uploads are disabled in production',
      };
    }

    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      return {
        valid: false,
        error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB`,
      };
    }

    // Check file extension
    const filename = file.name.toLowerCase();
    const hasValidExtension = ALLOWED_EXTENSIONS.some(ext =>
      filename.endsWith(ext)
    );

    if (!hasValidExtension) {
      return {
        valid: false,
        error: `Invalid file type. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`,
      };
    }

    return { valid: true };
  }

  /**
   * Upload file to local storage
   */
  static async uploadFile(file: File, userId: string): Promise<UploadedFile> {
    if (!this.isEnabled()) {
      throw new Error('Local file uploads are disabled');
    }

    try {
      logInfo('Uploading file locally', { filename: file.name, userId });

      // Validate file
      const validation = this.validateFile(file);
      if (!validation.valid) {
        throw new Error(validation.error);
      }

      // Generate unique ID
      const fileId = randomBytes(16).toString('hex');
      const extension = file.name.substring(file.name.lastIndexOf('.'));
      const safeFilename = `${fileId}${extension}`;

      // Create upload directory
      const userDir = join(UPLOAD_DIR, userId);
      await mkdir(userDir, { recursive: true });

      // Write file
      const filePath = join(userDir, safeFilename);
      const buffer = Buffer.from(await file.arrayBuffer());
      await writeFile(filePath, buffer);

      logInfo('File uploaded successfully', { fileId, path: filePath });

      return {
        id: fileId,
        filename: file.name,
        path: filePath,
        size: file.size,
        mimeType: file.type,
        uploadedAt: new Date(),
      };
    } catch (error) {
      logError('Failed to upload file', { error, filename: file.name });
      throw error;
    }
  }

  /**
   * Read file content from local storage
   */
  static async readFile(filePath: string): Promise<string> {
    if (!this.isEnabled()) {
      throw new Error('Local file access is disabled');
    }

    try {
      const { readFile } = await import('fs/promises');
      const content = await readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      logError('Failed to read file', { error, filePath });
      throw error;
    }
  }

  /**
   * Delete uploaded file
   */
  static async deleteFile(filePath: string): Promise<void> {
    if (!this.isEnabled()) {
      throw new Error('Local file deletion is disabled');
    }

    try {
      const { unlink } = await import('fs/promises');
      await unlink(filePath);
      logInfo('File deleted', { filePath });
    } catch (error) {
      logError('Failed to delete file', { error, filePath });
      throw error;
    }
  }

  /**
   * List uploaded files for a user
   */
  static async listFiles(userId: string): Promise<string[]> {
    if (!this.isEnabled()) {
      throw new Error('Local file listing is disabled');
    }

    try {
      const { readdir } = await import('fs/promises');
      const userDir = join(UPLOAD_DIR, userId);

      try {
        const files = await readdir(userDir);
        return files.map(f => join(userDir, f));
      } catch {
        return []; // Directory doesn't exist yet
      }
    } catch (error) {
      logError('Failed to list files', { error, userId });
      return [];
    }
  }

  /**
   * Get upload directory path
   */
  static getUploadDir(): string {
    return UPLOAD_DIR;
  }

  /**
   * Log warning when local dev mode is used
   */
  static logDevModeWarning(): void {
    if (this.isEnabled()) {
      logWarn(
        'LOCAL DEVELOPMENT MODE: File uploads enabled. Disable before production!',
        {
          uploadDir: UPLOAD_DIR,
          environment: process.env.NODE_ENV,
        }
      );
    }
  }
}

export type { UploadedFile };
