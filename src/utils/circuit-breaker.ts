import { logger } from './logger.js';

type CircuitState = 'closed' | 'open' | 'half-open';

interface CircuitBreakerOptions {
  name: string;
  failureThreshold?: number;
  resetTimeoutMs?: number;
  halfOpenMaxAttempts?: number;
}

export class CircuitBreaker {
  private state: CircuitState = 'closed';
  private failures = 0;
  private lastFailureTime = 0;
  private readonly name: string;
  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;
  private readonly halfOpenMaxAttempts: number;
  private halfOpenAttempts = 0;

  constructor(opts: CircuitBreakerOptions) {
    this.name = opts.name;
    this.failureThreshold = opts.failureThreshold ?? 5;
    this.resetTimeoutMs = opts.resetTimeoutMs ?? 60_000;
    this.halfOpenMaxAttempts = opts.halfOpenMaxAttempts ?? 1;
  }

  async call<T>(fn: () => Promise<T>): Promise<T | null> {
    if (this.state === 'open') {
      if (Date.now() - this.lastFailureTime >= this.resetTimeoutMs) {
        this.state = 'half-open';
        this.halfOpenAttempts = 0;
        logger.debug({ breaker: this.name }, 'Circuit breaker half-open');
      } else {
        return null;
      }
    }

    if (this.state === 'half-open' && this.halfOpenAttempts >= this.halfOpenMaxAttempts) {
      return null;
    }

    try {
      if (this.state === 'half-open') this.halfOpenAttempts++;
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure(err);
      return null;
    }
  }

  private onSuccess(): void {
    if (this.state !== 'closed') {
      logger.info({ breaker: this.name, previousState: this.state }, 'Circuit breaker closed (recovered)');
    }
    this.failures = 0;
    this.state = 'closed';
  }

  private onFailure(err: unknown): void {
    this.failures++;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.failureThreshold || this.state === 'half-open') {
      this.state = 'open';
      logger.warn({ breaker: this.name, failures: this.failures, err }, 'Circuit breaker opened');
    }
  }

  getState(): CircuitState {
    return this.state;
  }

  getStats(): { state: CircuitState; failures: number; lastFailure: number } {
    return { state: this.state, failures: this.failures, lastFailure: this.lastFailureTime };
  }
}
