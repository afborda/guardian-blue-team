import type { MessageSpec } from '../messaging/types.js';
import { formatNumber, formatWhen } from '../messaging/style.js';

export function buildBlockLostSpec(
  serverName: string,
  ip: string,
  failures: number,
  lastChecked: string,
): MessageSpec {
  return {
    kind: 'block',
    severity: 'medium',
    title: `Bloqueio não confirmado em ${serverName}`,
    lead: `A checagem não encontrou a regra que deveria bloquear ${ip}.`,
    facts: [
      { label: 'Servidor', value: serverName },
      { label: 'IP', value: ip, code: true },
      { label: 'Falhas', value: formatNumber(failures) },
      ...(lastChecked ? [{ label: 'Última checagem', value: formatWhen(new Date(lastChecked)) }] : []),
    ],
    meaning: 'O IP pode continuar barrado e só a consulta estar errada. Isso é comum com IPv6, porque o firewall grava o endereço curto e o Guardian procurava o endereço longo.',
    action: {
      required: false,
      title: 'O que fazer agora',
      steps: ['O Guardian vai tentar aplicar a regra de novo. Não precisa bloquear esse IP na mão.'],
    },
    footer: 'Só avisamos na primeira falha e depois uma vez por semana.',
  };
}

export function buildPropagationFailedSpec(
  ip: string,
  serverName: string,
  attempts: number,
  lastError: string,
): MessageSpec {
  return {
    kind: 'block',
    severity: 'high',
    title: `Bloqueio não chegou em ${serverName}`,
    lead: `O IP ${ip} continua sem bloqueio nesse servidor depois de ${formatNumber(attempts)} tentativas.`,
    facts: [
      { label: 'Servidor', value: serverName },
      { label: 'IP', value: ip, code: true },
      { label: 'Último erro', value: lastError.slice(0, 160) },
    ],
    meaning: 'Enquanto a regra não existe nesse servidor, ele está desprotegido contra esse IP.',
    action: {
      required: true,
      title: 'O que fazer agora',
      steps: [
        'Verifique se o SSH desse servidor continua acessível.',
        'Confira o fail2ban e o firewall (UFW/iptables).',
      ],
      fallbackCommand: '/verify-blocks',
    },
  };
}

export function buildDdosEscalationSpec(ip: string, serverName: string, events: number): MessageSpec {
  return {
    kind: 'block',
    severity: 'critical',
    title: 'DDoS: bloqueio permanente aplicado',
    lead: `O IP ${ip} continuou atacando ${serverName} depois do limite de taxa e foi bloqueado em definitivo.`,
    facts: [
      { label: 'Servidor', value: serverName },
      { label: 'IP', value: ip, code: true },
      { label: 'Eventos após o limite', value: formatNumber(events) },
    ],
    action: {
      required: false,
      title: 'O que já foi feito',
      steps: ['O bloqueio permanente já está ativo. Não precisa fazer nada.'],
    },
  };
}
