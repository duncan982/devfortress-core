/**
 * DevFortress SDK — Shadow Agent Registry
 *
 * Detects and tracks unauthorized ("shadow") AI agents that operate
 * without proper registration. Maintains a registry of known agents
 * and flags unregistered agent-like behavior.
 *
 * Patent Pending.
 *
 * @packageDocumentation
 */

export interface ShadowAgentConfig {
  /** Maximum time between agent heartbeats before marking as shadow (ms) */
  heartbeatTimeoutMs?: number;
  /** Behavioral patterns that indicate agent-like activity */
  agentPatterns?: string[];
  /** Whether to auto-block detected shadow agents */
  autoBlock?: boolean;
}

export interface RegisteredAgent {
  agentId: string;
  name: string;
  registeredAt: number;
  lastHeartbeat: number;
  owner: string;
  permissions: string[];
  active: boolean;
}

export interface ShadowAgentDetection {
  detected: boolean;
  agentFingerprint: string;
  indicators: string[];
  confidence: number;
  recommendation: 'register' | 'block' | 'monitor';
  matchedPatterns: string[];
}

export interface AgentRegistryStats {
  registeredCount: number;
  activeCount: number;
  shadowDetections: number;
  blockedShadows: number;
}

const DEFAULT_AGENT_PATTERNS = [
  'automated request pattern (>100 req/min)',
  'consistent timing between requests (<50ms variance)',
  'sequential resource enumeration',
  'user-agent indicates bot/automation',
  'no mouse/keyboard entropy in session',
  'API-only access (no page loads)',
];

export class ShadowAgentRegistry {
  private config: Required<ShadowAgentConfig>;
  private registry: Map<string, RegisteredAgent> = new Map();
  private shadowDetections: Map<string, ShadowAgentDetection> = new Map();
  private stats: AgentRegistryStats = {
    registeredCount: 0,
    activeCount: 0,
    shadowDetections: 0,
    blockedShadows: 0,
  };

  constructor(config: ShadowAgentConfig = {}) {
    this.config = {
      heartbeatTimeoutMs: config.heartbeatTimeoutMs ?? 300_000,
      agentPatterns: config.agentPatterns ?? DEFAULT_AGENT_PATTERNS,
      autoBlock: config.autoBlock ?? false,
    };
  }

  /** Register a known agent */
  register(
    agent: Omit<RegisteredAgent, 'registeredAt' | 'lastHeartbeat' | 'active'>
  ): RegisteredAgent {
    if (process.env.FEATURE_PLATFORM_INTEL === 'false') {
      return { ...agent, registeredAt: 0, lastHeartbeat: 0, active: false };
    }

    const registered: RegisteredAgent = {
      ...agent,
      registeredAt: Date.now(),
      lastHeartbeat: Date.now(),
      active: true,
    };
    this.registry.set(agent.agentId, registered);
    this.stats.registeredCount++;
    this.stats.activeCount++;
    return registered;
  }

  /** Record a heartbeat from a registered agent */
  heartbeat(agentId: string): boolean {
    const agent = this.registry.get(agentId);
    if (!agent) return false;
    agent.lastHeartbeat = Date.now();
    agent.active = true;
    return true;
  }

  /** Check if a request source is a registered agent or a shadow */
  detect(fingerprint: string, indicators: string[]): ShadowAgentDetection {
    if (process.env.FEATURE_PLATFORM_INTEL === 'false') {
      return {
        detected: false,
        agentFingerprint: fingerprint,
        indicators: [],
        confidence: 0,
        recommendation: 'monitor',
        matchedPatterns: [],
      };
    }

    // Check if any registered agent matches this fingerprint
    for (const agent of this.registry.values()) {
      if (agent.agentId === fingerprint && agent.active) {
        return {
          detected: false,
          agentFingerprint: fingerprint,
          indicators: [],
          confidence: 0,
          recommendation: 'monitor',
          matchedPatterns: [],
        };
      }
    }

    // Check indicators against known agent patterns
    const matchedPatterns = this.config.agentPatterns.filter(pattern => {
      const patternKey = pattern.split('(')[0].trim().toLowerCase();
      return indicators.some(i => i.toLowerCase().includes(patternKey));
    });

    const confidence = Math.min(1, matchedPatterns.length / 3);
    const detected = confidence > 0.3;

    if (detected) {
      this.stats.shadowDetections++;
      if (this.config.autoBlock && confidence > 0.7) {
        this.stats.blockedShadows++;
      }
    }

    const result: ShadowAgentDetection = {
      detected,
      agentFingerprint: fingerprint,
      indicators,
      confidence,
      recommendation:
        confidence > 0.7
          ? this.config.autoBlock
            ? 'block'
            : 'register'
          : 'monitor',
      matchedPatterns,
    };
    if (detected) this.shadowDetections.set(fingerprint, result);
    return result;
  }

  /** Prune inactive agents (no heartbeat within timeout) */
  pruneInactive(): string[] {
    const cutoff = Date.now() - this.config.heartbeatTimeoutMs;
    const pruned: string[] = [];
    for (const [id, agent] of this.registry.entries()) {
      if (agent.lastHeartbeat < cutoff) {
        agent.active = false;
        this.stats.activeCount--;
        pruned.push(id);
      }
    }
    return pruned;
  }

  getStats(): AgentRegistryStats {
    return { ...this.stats };
  }

  getRegistered(): RegisteredAgent[] {
    return Array.from(this.registry.values());
  }
}
