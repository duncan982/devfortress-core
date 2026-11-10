// packages/devfortress-sdk/src/specialization/mode-composer.ts

import type { SpecializationModeId } from './manifest';
import type {
  SpecializationPlugin,
  DetectionContext,
  DetectionResult,
} from './plugin-interface';
import { SPECIALIZATION_MANIFESTS } from './manifest';

export class ModeComposer {
  private activePlugins: Map<SpecializationModeId, SpecializationPlugin> =
    new Map();

  async activate(
    modeId: SpecializationModeId,
    plugin: SpecializationPlugin
  ): Promise<void> {
    const manifest = SPECIALIZATION_MANIFESTS[modeId];
    if (!manifest) throw new Error(`Unknown specialization mode: ${modeId}`);
    if (this.activePlugins.has(modeId)) return; // already active

    await plugin.onActivate?.();
    this.activePlugins.set(modeId, plugin);
    console.info(
      `[DevFortress] Specialization mode activated: ${manifest.displayName}`
    );
  }

  async deactivate(modeId: SpecializationModeId): Promise<void> {
    const plugin = this.activePlugins.get(modeId);
    if (!plugin) return;
    await plugin.onDeactivate?.();
    this.activePlugins.delete(modeId);
  }

  async runAll(ctx: DetectionContext): Promise<DetectionResult[]> {
    const results: DetectionResult[] = [];
    for (const plugin of this.activePlugins.values()) {
      try {
        const result = await plugin.detect(ctx);
        if (result) results.push(result);
      } catch (e) {
        console.error(
          `[DevFortress] Plugin error in mode ${plugin.modeId}:`,
          e
        );
      }
    }
    return results;
  }

  getActiveModes(): SpecializationModeId[] {
    return Array.from(this.activePlugins.keys());
  }

  async healthCheck(): Promise<
    Record<SpecializationModeId, { healthy: boolean; details?: string }>
  > {
    const results = {} as Record<
      SpecializationModeId,
      { healthy: boolean; details?: string }
    >;
    for (const [modeId, plugin] of this.activePlugins.entries()) {
      results[modeId] = (await plugin.healthCheck?.()) ?? { healthy: true };
    }
    return results;
  }
}

// Singleton composer — imported and used by the main SDK
export const modeComposer = new ModeComposer();
