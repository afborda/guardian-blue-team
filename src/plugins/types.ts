export interface FormattedAlert {
  title: string;
  body: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  metadata: Record<string, string>;
}

export interface InteractiveAction {
  id: string;
  label: string;
  style: 'approve' | 'reject' | 'info';
}

export interface CallbackResult {
  handled: boolean;
  action?: string;
}

export interface NotifierPlugin {
  name: string;
  enabled: boolean;
  interactive: boolean;
  init?(): Promise<void>;
  send(alert: FormattedAlert): Promise<void>;
  sendInteractive?(alert: FormattedAlert, actions: InteractiveAction[]): Promise<void>;
  handleCallback?(source: string, payload: unknown): Promise<CallbackResult>;
}

export interface DetectorPlugin {
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  detect(events: NormalizedEvent[], buffer: NormalizedEvent[]): DetectedThreat[];
}

export interface ActionPlugin {
  name: string;
  description: string;
  execute(ctx: PlaybookContext, params: Record<string, unknown>): Promise<ActionResult>;
}

export interface EnricherPlugin {
  name: string;
  enrich(indicator: string, type: 'ip' | 'domain' | 'hash'): Promise<EnrichmentResult>;
}

export interface NormalizedEvent {
  id?: number;
  serverId: number;
  timestamp: Date;
  eventType: string;
  severity: string;
  sourceIp?: string;
  userName?: string;
  rawLog: string;
  source: string;
}

export interface DetectedThreat {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  sourceIp?: string;
  userName?: string;
  serverId: number;
  details: string;
  eventCount: number;
  relatedEvents: NormalizedEvent[];
}

export interface PlaybookContext {
  serverId: number;
  serverName: string;
  sourceIp?: string;
  incidentId?: number;
  triggeredBy: string;
  variables: Record<string, unknown>;
}

export interface ActionResult {
  success: boolean;
  message: string;
  data?: Record<string, unknown>;
}

export interface EnrichmentResult {
  source: string;
  data: Record<string, unknown>;
  score?: number;
  tags?: string[];
}
