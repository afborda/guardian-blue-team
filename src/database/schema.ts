// Re-exports all tables from both schemas for backward compatibility.
// New code should import from guardian-schema.ts or automabothub-schema.ts directly.

export {
  socServers,
  securityEvents,
  socIncidents,
  playbookExecutions,
  threatIntelCache,
  vulnerabilities,
  blockedIps,
} from './guardian-schema.js';

export {
  instances,
  users,
  plans,
  instanceMetrics,
  instanceBehaviorProfiles,
  guardianDecisions,
  abuseIncidents,
} from './automabothub-schema.js';
