/**
 * Optimized Image component with lazy loading
 * Uses Next.js Image with performance optimizations
 */

import Image, { ImageProps } from 'next/image';

interface OptimizedImageProps extends Omit<ImageProps, 'loading'> {
  loading?: 'lazy' | 'eager';
  priority?: boolean;
  alt: string; // Make alt required
}

export function OptimizedImage({
  loading = 'lazy',
  priority = false,
  quality = 85,
  alt,
  ...props
}: OptimizedImageProps) {
  return (
    <Image
      {...props}
      alt={alt}
      loading={loading}
      priority={priority}
      quality={quality}
      placeholder="blur"
      blurDataURL="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mN8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg=="
    />
  );
}
