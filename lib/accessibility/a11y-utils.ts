/**
 * Accessibility Utilities
 * WCAG 2.1 AA compliance helpers
 */

/**
 * Skip to main content link component
 */
export function getSkipToMainLink(): string {
  return `
    <a 
      href="#main-content" 
      class="sr-only focus:not-sr-only focus:absolute focus:top-0 focus:left-0 focus:z-50 focus:px-4 focus:py-2 focus:bg-blue-600 focus:text-white"
    >
      Skip to main content
    </a>
  `;
}

/**
 * Check color contrast ratio (WCAG AA requires 4.5:1 for normal text)
 */
export function checkColorContrast(
  foreground: string,
  background: string
): { ratio: number; wcagAA: boolean; wcagAAA: boolean } {
  const getLuminance = (rgb: number[]) => {
    const [r, g, b] = rgb.map(val => {
      const sRGB = val / 255;
      return sRGB <= 0.03928
        ? sRGB / 12.92
        : Math.pow((sRGB + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };

  const hexToRgb = (hex: string): number[] => {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result
      ? [
          parseInt(result[1], 16),
          parseInt(result[2], 16),
          parseInt(result[3], 16),
        ]
      : [0, 0, 0];
  };

  const l1 = getLuminance(hexToRgb(foreground));
  const l2 = getLuminance(hexToRgb(background));
  const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);

  return {
    ratio: Math.round(ratio * 100) / 100,
    wcagAA: ratio >= 4.5, // Normal text
    wcagAAA: ratio >= 7, // Enhanced
  };
}

/**
 * Generate accessible form labels
 */
export function generateAccessibleLabel(
  id: string,
  label: string,
  required = false,
  helpText?: string
): string {
  return `
    <label for="${id}" class="block text-sm font-medium text-gray-700">
      ${label}
      ${required ? '<span class="text-red-500" aria-label="required">*</span>' : ''}
    </label>
    ${
      helpText
        ? `<p id="${id}-help" class="text-xs text-gray-500 mt-1">${helpText}</p>`
        : ''
    }
  `;
}

/**
 * Get keyboard navigation attributes
 */
export function getKeyboardNavAttributes(role: string): Record<string, string> {
  const baseAttrs = {
    role,
    tabIndex: '0',
  };

  switch (role) {
    case 'button':
      return { ...baseAttrs, 'aria-pressed': 'false' };
    case 'link':
      return { ...baseAttrs };
    case 'menu':
      return {
        ...baseAttrs,
        'aria-haspopup': 'true',
        'aria-expanded': 'false',
      };
    default:
      return baseAttrs;
  }
}

/**
 * Screen reader announcements
 */
export function createLiveRegion(id: string, polite = true): string {
  return `
    <div
      id="${id}"
      role="${polite ? 'status' : 'alert'}"
      aria-live="${polite ? 'polite' : 'assertive'}"
      aria-atomic="true"
      class="sr-only"
    ></div>
  `;
}

/**
 * Validate ARIA attributes
 */
export function validateAriaAttributes(element: Record<string, string>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Check required ARIA combinations
  if (element['aria-labelledby'] && !element.id) {
    errors.push('Element with aria-labelledby must have an id');
  }

  if (element['aria-describedby'] && !element.id) {
    errors.push('Element with aria-describedby must have an id');
  }

  if (
    element.role === 'button' &&
    !element['aria-label'] &&
    !element['aria-labelledby']
  ) {
    errors.push('Button role requires aria-label or aria-labelledby');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Focus management utilities
 */
export const FocusManager = {
  /**
   * Trap focus within a modal/dialog
   */
  trapFocus(containerId: string): void {
    if (typeof document === 'undefined') return;

    const container = document.getElementById(containerId);
    if (!container) return;

    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    if (focusableElements.length === 0) return;

    const firstElement = focusableElements[0] as HTMLElement;
    const lastElement = focusableElements[
      focusableElements.length - 1
    ] as HTMLElement;

    container.addEventListener('keydown', (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return;

      if (e.shiftKey && document.activeElement === firstElement) {
        e.preventDefault();
        lastElement.focus();
      } else if (!e.shiftKey && document.activeElement === lastElement) {
        e.preventDefault();
        firstElement.focus();
      }
    });
  },

  /**
   * Return focus to previous element
   */
  returnFocus(previousElement: HTMLElement | null): void {
    if (previousElement && typeof previousElement.focus === 'function') {
      previousElement.focus();
    }
  },
};

/**
 * Alternative text helpers
 */
export function generateAltText(context: {
  type: 'decorative' | 'informative' | 'functional';
  description?: string;
}): string {
  switch (context.type) {
    case 'decorative':
      return ''; // Empty alt for decorative images
    case 'informative':
      return context.description || 'Informative image';
    case 'functional':
      return context.description || 'Functional image';
    default:
      return '';
  }
}

/**
 * Loading state announcements
 */
export function announceLoadingState(
  element: HTMLElement,
  loading: boolean,
  label?: string
): void {
  if (loading) {
    element.setAttribute('aria-busy', 'true');
    if (label) element.setAttribute('aria-label', `${label} (loading)`);
  } else {
    element.setAttribute('aria-busy', 'false');
    if (label) element.setAttribute('aria-label', label);
  }
}

/**
 * Error message helpers
 */
export function associateErrorWithField(
  fieldId: string,
  errorId: string
): void {
  if (typeof document === 'undefined') return;

  const field = document.getElementById(fieldId);
  if (!field) return;

  field.setAttribute('aria-invalid', 'true');
  field.setAttribute('aria-describedby', errorId);
}

export function clearFieldError(fieldId: string): void {
  if (typeof document === 'undefined') return;

  const field = document.getElementById(fieldId);
  if (!field) return;

  field.setAttribute('aria-invalid', 'false');
  field.removeAttribute('aria-describedby');
}

/**
 * Enterprise accessibility features
 */

/**
 * ARIA roles enum
 */
export enum AriaRole {
  ALERT = 'alert',
  BUTTON = 'button',
  CHECKBOX = 'checkbox',
  DIALOG = 'dialog',
  GRID = 'grid',
  LISTBOX = 'listbox',
  MENU = 'menu',
  MENUITEM = 'menuitem',
  NAVIGATION = 'navigation',
  PROGRESSBAR = 'progressbar',
  RADIO = 'radio',
  SEARCHBOX = 'searchbox',
  SLIDER = 'slider',
  SPINBUTTON = 'spinbutton',
  TAB = 'tab',
  TABPANEL = 'tabpanel',
  TEXTBOX = 'textbox',
  TOOLTIP = 'tooltip',
}

/**
 * ARIA attributes builder
 */
export class AriaAttributesBuilder {
  private attributes: Record<string, string | boolean | number> = {};

  role(role: AriaRole): this {
    this.attributes.role = role;
    return this;
  }

  label(label: string): this {
    this.attributes['aria-label'] = label;
    return this;
  }

  labelledBy(id: string): this {
    this.attributes['aria-labelledby'] = id;
    return this;
  }

  describedBy(id: string): this {
    this.attributes['aria-describedby'] = id;
    return this;
  }

  expanded(expanded: boolean): this {
    this.attributes['aria-expanded'] = expanded;
    return this;
  }

  selected(selected: boolean): this {
    this.attributes['aria-selected'] = selected;
    return this;
  }

  checked(checked: boolean): this {
    this.attributes['aria-checked'] = checked;
    return this;
  }

  disabled(disabled: boolean): this {
    this.attributes['aria-disabled'] = disabled;
    return this;
  }

  hidden(hidden: boolean): this {
    this.attributes['aria-hidden'] = hidden;
    return this;
  }

  live(setting: 'off' | 'polite' | 'assertive'): this {
    this.attributes['aria-live'] = setting;
    return this;
  }

  controls(id: string): this {
    this.attributes['aria-controls'] = id;
    return this;
  }

  hasPopup(value: boolean | 'menu' | 'listbox' | 'tree' | 'grid' | 'dialog'): this {
    this.attributes['aria-haspopup'] = value;
    return this;
  }

  invalid(invalid: boolean): this {
    this.attributes['aria-invalid'] = invalid;
    return this;
  }

  required(required: boolean): this {
    this.attributes['aria-required'] = required;
    return this;
  }

  valueNow(value: number): this {
    this.attributes['aria-valuenow'] = value;
    return this;
  }

  valueMin(value: number): this {
    this.attributes['aria-valuemin'] = value;
    return this;
  }

  valueMax(value: number): this {
    this.attributes['aria-valuemax'] = value;
    return this;
  }

  valueText(text: string): this {
    this.attributes['aria-valuetext'] = text;
    return this;
  }

  build(): Record<string, string | boolean | number> {
    return { ...this.attributes };
  }
}

/**
 * Create ARIA attributes
 */
export function createAriaAttributes(): AriaAttributesBuilder {
  return new AriaAttributesBuilder();
}

/**
 * Screen reader announcement service
 */
class ScreenReaderAnnouncer {
  private liveRegion: HTMLElement | null = null;

  /**
   * Initialize live region for announcements
   */
  private initLiveRegion(): void {
    if (typeof document === 'undefined') return;
    if (this.liveRegion) return;

    this.liveRegion = document.createElement('div');
    this.liveRegion.setAttribute('role', 'status');
    this.liveRegion.setAttribute('aria-live', 'polite');
    this.liveRegion.setAttribute('aria-atomic', 'true');
    this.liveRegion.className = 'sr-only';
    this.liveRegion.style.cssText = `
      position: absolute;
      left: -10000px;
      width: 1px;
      height: 1px;
      overflow: hidden;
    `;

    document.body.appendChild(this.liveRegion);
  }

  /**
   * Announce message to screen readers
   */
  announce(message: string, priority: 'polite' | 'assertive' = 'polite'): void {
    if (typeof document === 'undefined') return;

    this.initLiveRegion();
    if (!this.liveRegion) return;

    this.liveRegion.setAttribute('aria-live', priority);
    
    // Clear previous message
    this.liveRegion.textContent = '';
    
    // Add new message after a brief delay to ensure it's announced
    setTimeout(() => {
      if (this.liveRegion) {
        this.liveRegion.textContent = message;
      }
    }, 100);

    // Clear message after announcement
    setTimeout(() => {
      if (this.liveRegion) {
        this.liveRegion.textContent = '';
      }
    }, 5000);
  }
}

/**
 * Singleton screen reader announcer
 */
export const screenReader = new ScreenReaderAnnouncer();

/**
 * Keyboard navigation handler
 */
export class KeyboardNavigationHandler {
  private handlers: Map<string, (event: KeyboardEvent) => void> = new Map();

  /**
   * Register keyboard shortcut
   */
  register(
    key: string,
    handler: (event: KeyboardEvent) => void,
    options?: {
      ctrl?: boolean;
      shift?: boolean;
      alt?: boolean;
      meta?: boolean;
    }
  ): () => void {
    const keyCombo = this.createKeyCombo(key, options);
    this.handlers.set(keyCombo, handler);

    const eventHandler = (event: KeyboardEvent): void => {
      const combo = this.getEventKeyCombo(event);
      const matchingHandler = this.handlers.get(combo);

      if (matchingHandler) {
        event.preventDefault();
        matchingHandler(event);
      }
    };

    if (typeof document !== 'undefined') {
      document.addEventListener('keydown', eventHandler);
    }

    // Return cleanup function
    return () => {
      this.handlers.delete(keyCombo);
      if (typeof document !== 'undefined') {
        document.removeEventListener('keydown', eventHandler);
      }
    };
  }

  /**
   * Create key combination string
   */
  private createKeyCombo(
    key: string,
    options?: {
      ctrl?: boolean;
      shift?: boolean;
      alt?: boolean;
      meta?: boolean;
    }
  ): string {
    const parts: string[] = [];
    if (options?.ctrl) parts.push('ctrl');
    if (options?.shift) parts.push('shift');
    if (options?.alt) parts.push('alt');
    if (options?.meta) parts.push('meta');
    parts.push(key.toLowerCase());
    return parts.join('+');
  }

  /**
   * Get key combination from event
   */
  private getEventKeyCombo(event: KeyboardEvent): string {
    const parts: string[] = [];
    if (event.ctrlKey) parts.push('ctrl');
    if (event.shiftKey) parts.push('shift');
    if (event.altKey) parts.push('alt');
    if (event.metaKey) parts.push('meta');
    parts.push(event.key.toLowerCase());
    return parts.join('+');
  }

  /**
   * Clear all handlers
   */
  clear(): void {
    this.handlers.clear();
  }
}

/**
 * Singleton keyboard navigation handler
 */
export const keyboardNav = new KeyboardNavigationHandler();
