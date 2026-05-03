import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';

export interface DockerVuln {
  image: string;
  tag: string;
  issue: string;
  severity: string;
}

export class DockerAuditor {
  static async audit(target: SSHTarget): Promise<DockerVuln[]> {
    const result = await SSHCollector.run(target,
      "docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedSince}}' 2>/dev/null | head -30",
      15_000
    );

    if (!result.success) return [];

    const vulns: DockerVuln[] = [];
    const lines = result.stdout.trim().split('\n').filter(Boolean);

    for (const line of lines) {
      const parts = line.split(' ');
      const imageTag = parts[0];
      const age = parts.slice(1).join(' ');

      const [image, tag] = imageTag.split(':');

      if (tag === 'latest') {
        vulns.push({
          image,
          tag,
          issue: 'Using :latest tag (unpinned version)',
          severity: 'medium',
        });
      }

      if (age.includes('months') || age.includes('years')) {
        const months = age.includes('years')
          ? parseInt(age) * 12
          : parseInt(age);
        if (months >= 6) {
          vulns.push({
            image,
            tag,
            issue: `Image is ${age} old`,
            severity: months >= 12 ? 'high' : 'medium',
          });
        }
      }
    }

    return vulns;
  }
}
