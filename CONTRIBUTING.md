# Contributing to Guardian Blue Team

Thank you for your interest in contributing! Guardian is a lightweight SOAR for solo operators and small teams. We welcome plugins, detectors, bug fixes, and documentation improvements.

## Development Setup

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
npm install
cp .env.example .env  # edit with your values
npm run dev
```

## Running Tests

```bash
npm run test          # run all tests
npm run test:watch    # watch mode
npm run type-check    # TypeScript validation
npm run build         # production build
```

## Adding a Notifier Plugin

1. Create `src/plugins/notifiers/your-notifier.ts`
2. Implement the `NotifierPlugin` interface:

```typescript
import type { NotifierPlugin, FormattedAlert, CallbackResult } from '../types.js';

export class YourNotifier implements NotifierPlugin {
  name = 'your-notifier';
  enabled = false;
  interactive = false; // true if supports buttons/callbacks

  async init(): Promise<void> {
    // Read env vars, set this.enabled = true if configured
  }

  async send(alert: FormattedAlert): Promise<void> {
    // Deliver the alert
  }

  async handleCallback(_source: string, _payload: unknown): Promise<CallbackResult> {
    return { handled: false };
  }
}
```

3. Register in `src/plugins/index.ts`:

```typescript
import { YourNotifier } from './notifiers/your-notifier.js';
registerNotifier('your-notifier', () => new YourNotifier());
```

4. Add a test in `tests/your-notifier.test.ts`
5. Update `.env.example` with your env vars

## Adding a Detector

Detectors analyze normalized security events and flag threats.

1. Create `src/plugins/detectors/your-detector.ts`
2. Implement the `DetectorPlugin` interface
3. Register with the detection pipeline

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include tests for new functionality
- Run `npm run type-check && npm run test` before submitting
- Follow existing code style (no comments unless explaining WHY)
- Update `.env.example` if adding new config

## Commit Messages

Use concise, descriptive commit messages:
- `add discord notifier plugin`
- `fix brute force threshold not respecting constants`
- `update CVE monitor to batch notifications`

## Code Style

- TypeScript strict mode
- ESM imports (`.js` extensions)
- No unnecessary abstractions
- Prefer `const` and function declarations
- Error handling only at boundaries

## Reporting Issues

- Use the GitHub issue templates
- Include Guardian version, Node.js version, and OS
- For security issues, see SECURITY.md
