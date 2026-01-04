/**
 * Multimodal Document Upload Component
 *
 * Allows users to upload API documentation with text, images, diagrams, etc.
 * for enhanced RAG-based API generation and documentation.
 */

'use client';

import { useState, useCallback } from 'react';
import { Button } from '@core/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@core/components/ui/card';
import { Alert, AlertDescription } from '@core/components/ui/alert';
import { Upload, FileText, Image, Code, X, CheckCircle } from 'lucide-react';

interface UploadedFile {
  id: string;
  file: File;
  type: 'text' | 'image' | 'diagram' | 'code';
  preview?: string;
  status: 'pending' | 'uploading' | 'success' | 'error';
  error?: string;
}

interface DocumentUploadProps {
  onUploadComplete?: (files: UploadedFile[]) => void;
  maxFiles?: number;
  maxFileSize?: number; // in MB
}

export function DocumentUpload({
  onUploadComplete,
  maxFiles = 10,
  maxFileSize = 10,
}: DocumentUploadProps) {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const detectFileType = (
    file: File
  ): 'text' | 'image' | 'diagram' | 'code' => {
    if (file.type.startsWith('image/')) return 'image';
    if (file.name.endsWith('.md') || file.name.endsWith('.txt')) return 'text';
    if (
      file.name.endsWith('.js') ||
      file.name.endsWith('.ts') ||
      file.name.endsWith('.py') ||
      file.name.endsWith('.java')
    ) {
      return 'code';
    }
    return 'diagram';
  };

  const handleFiles = useCallback(
    async (fileList: FileList | null) => {
      if (!fileList) return;

      setError(null);

      const newFiles: UploadedFile[] = [];

      for (let i = 0; i < fileList.length; i++) {
        const file = fileList[i];

        // Check file count limit
        if (files.length + newFiles.length >= maxFiles) {
          setError(`Maximum ${maxFiles} files allowed`);
          break;
        }

        // Check file size
        if (file.size > maxFileSize * 1024 * 1024) {
          setError(`File ${file.name} exceeds ${maxFileSize}MB limit`);
          continue;
        }

        const uploadedFile: UploadedFile = {
          id: `${Date.now()}-${i}`,
          file,
          type: detectFileType(file),
          status: 'pending',
        };

        // Generate preview for images
        if (file.type.startsWith('image/')) {
          const reader = new FileReader();
          reader.onload = e => {
            uploadedFile.preview = e.target?.result as string;
            setFiles(prev =>
              prev.map(f =>
                f.id === uploadedFile.id
                  ? { ...f, preview: uploadedFile.preview }
                  : f
              )
            );
          };
          reader.readAsDataURL(file);
        }

        newFiles.push(uploadedFile);
      }

      setFiles(prev => [...prev, ...newFiles]);
    },
    [files.length, maxFiles, maxFileSize]
  );

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();

    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(false);

      handleFiles(e.dataTransfer.files);
    },
    [handleFiles]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      handleFiles(e.target.files);
    },
    [handleFiles]
  );

  const removeFile = useCallback((id: string) => {
    setFiles(prev => prev.filter(f => f.id !== id));
  }, []);

  const uploadFiles = async () => {
    setFiles(prev => prev.map(f => ({ ...f, status: 'uploading' as const })));

    const formData = new FormData();
    files.forEach(uploadedFile => {
      formData.append('files', uploadedFile.file);
      formData.append('types', uploadedFile.type);
    });

    try {
      const response = await fetch('/api/rag/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Upload failed');
      }

      setFiles(prev => prev.map(f => ({ ...f, status: 'success' as const })));

      if (onUploadComplete) {
        onUploadComplete(files);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
      setFiles(prev =>
        prev.map(f => ({
          ...f,
          status: 'error' as const,
          error: 'Upload failed',
        }))
      );
    }
  };

  const getFileIcon = (type: string) => {
    switch (type) {
      case 'text':
        return <FileText className="h-4 w-4" />;
      case 'image':
      case 'diagram':
        // eslint-disable-next-line jsx-a11y/alt-text
        return <Image className="h-4 w-4" />;
      case 'code':
        return <Code className="h-4 w-4" />;
      default:
        return <FileText className="h-4 w-4" />;
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Upload API Documentation</CardTitle>
        <CardDescription>
          Upload text, images, diagrams, or code files to enhance API generation
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Drop Zone */}
        <div
          className={`relative border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
            dragActive
              ? 'border-blue-500 bg-blue-50'
              : 'border-gray-300 hover:border-gray-400'
          }`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <input
            type="file"
            id="file-upload"
            multiple
            accept=".md,.txt,.png,.jpg,.jpeg,.svg,.pdf,.js,.ts,.py,.java"
            onChange={handleChange}
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          />
          <Upload className="mx-auto h-12 w-12 text-gray-400 mb-4" />
          <p className="text-sm text-gray-600 mb-2">
            Drag and drop files here, or click to browse
          </p>
          <p className="text-xs text-gray-500">
            Supports: Text (.md, .txt), Images (.png, .jpg, .svg), Code (.js,
            .ts, .py, .java)
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Max {maxFiles} files, {maxFileSize}MB per file
          </p>
        </div>

        {/* File List */}
        {files.length > 0 && (
          <div className="space-y-2">
            <h3 className="font-medium text-sm">
              Uploaded Files ({files.length})
            </h3>
            <div className="space-y-2">
              {files.map(uploadedFile => (
                <div
                  key={uploadedFile.id}
                  className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                >
                  <div className="flex items-center space-x-3 flex-1">
                    {getFileIcon(uploadedFile.type)}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">
                        {uploadedFile.file.name}
                      </p>
                      <p className="text-xs text-gray-500">
                        {uploadedFile.type} •{' '}
                        {(uploadedFile.file.size / 1024).toFixed(1)} KB
                      </p>
                    </div>
                    {uploadedFile.status === 'success' && (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    )}
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeFile(uploadedFile.id)}
                    disabled={uploadedFile.status === 'uploading'}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Upload Button */}
        {files.length > 0 && (
          <Button
            onClick={uploadFiles}
            disabled={files.some(f => f.status === 'uploading')}
            className="w-full"
          >
            {files.some(f => f.status === 'uploading')
              ? 'Uploading...'
              : 'Upload Files'}
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
