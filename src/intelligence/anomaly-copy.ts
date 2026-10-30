import type { Anomaly } from './anomaly-detector.js';

const MBPS = 1_000_000;

/**
 * Drop alerts whose absolute value is healthy. A huge z-score on a quiet
 * network or on 40% CPU is a statistics artifact, not an incident.
 * Returns null when Telegram should stay silent.
 */
export function gateAnomaly(anomaly: Anomaly): Anomaly | null {
  const { metric, currentValue, expectedMean } = anomaly;

  if (metric === 'load_ratio') {
    if (currentValue < 0.75) return null;
    return anomaly;
  }

  if (metric === 'mem_used_percent' || metric === 'disk_max_percent') {
    if (currentValue < 85) return null;
    return anomaly;
  }

  if (metric === 'network_rx_bps' || metric === 'network_tx_bps') {
    // Quiet hours and modest bursts (streaming, backup) are normal on this host.
    if (currentValue < 8 * MBPS) return null;
    if (currentValue < expectedMean) return null;
    return anomaly;
  }

  return anomaly;
}

export function formatAnomalyAlert(serverName: string, anomaly: Anomaly): { title: string; body: string } {
  switch (anomaly.metric) {
    case 'load_ratio':
      return loadAlert(serverName, anomaly);
    case 'mem_used_percent':
      return capacityAlert(serverName, 'A memória', anomaly, '%');
    case 'disk_max_percent':
      return capacityAlert(serverName, 'O disco', anomaly, '%');
    case 'network_rx_bps':
      return networkAlert(serverName, 'recebendo', anomaly);
    case 'network_tx_bps':
      return networkAlert(serverName, 'enviando', anomaly);
    case 'kernel_errors':
      return errorAlert(serverName, 'erros de kernel', anomaly);
    case 'journal_errors':
      return errorAlert(serverName, 'erros no journal do sistema', anomaly);
    default:
      return {
        title: `Mudança fora do habitual em ${serverName}`,
        body: `${anomaly.metric}: agora ${anomaly.currentValue}, habitual neste horário cerca de ${anomaly.expectedMean}.`,
      };
  }
}

function pct(ratio: number): string {
  return `${Math.round(ratio * 100)}%`;
}

function loadAlert(serverName: string, anomaly: Anomaly): { title: string; body: string } {
  return {
    title: `Processador carregado em ${serverName}`,
    body: [
      `Agora: ${pct(anomaly.currentValue)} da capacidade da máquina.`,
      `O habitual neste horário: cerca de ${pct(anomaly.expectedMean)}.`,
      '',
      '100% significa todos os núcleos ocupados ao mesmo tempo. Abaixo de 75% este aviso não é enviado.',
      '',
      'O que fazer: se os sites abrirem, pode esperar. Se estiverem lentos, veja qual programa está pesado. Não é, sozinho, sinal de invasão.',
    ].join('\n'),
  };
}

function capacityAlert(serverName: string, noun: string, anomaly: Anomaly, unit: string): { title: string; body: string } {
  const rounded = Math.round(anomaly.currentValue);
  const usual = Math.round(anomaly.expectedMean);
  return {
    title: `${noun} está enchendo em ${serverName}`,
    body: [
      `Agora: ${rounded}${unit}.`,
      `O habitual: cerca de ${usual}${unit}.`,
      '',
      'Só avisamos a partir de 85%. Perto de 95% o serviço pode parar de gravar ou reiniciar.',
      '',
      'O que fazer: liberar espaço ou memória antes de chegar nesse ponto. Não precisa bloquear IP por causa deste aviso.',
    ].join('\n'),
  };
}

function networkAlert(serverName: string, direction: 'recebendo' | 'enviando', anomaly: Anomaly): { title: string; body: string } {
  return {
    title: `${serverName} está ${direction} dados demais`,
    body: [
      `Agora: ${formatBitRate(anomaly.currentValue)}.`,
      `O habitual neste horário: cerca de ${formatBitRate(anomaly.expectedMean)}.`,
      '',
      'Tráfego baixo ou um pico de alguns MB/s (backup, streaming, deploy) não gera aviso. Este aviso só sai acima de 8 MB/s, bem acima do uso normal.',
      '',
      'O que fazer: se os sites estiverem no ar, pode ser backup ou alguém baixando muito. Só trate como ataque se continuar alto por horas ou se o site cair. Não bloqueie IP nenhum só por este número.',
    ].join('\n'),
  };
}

function errorAlert(serverName: string, label: string, anomaly: Anomaly): { title: string; body: string } {
  return {
    title: `Subiram os ${label} em ${serverName}`,
    body: [
      `Agora: ${anomaly.currentValue}. O habitual: cerca de ${anomaly.expectedMean}.`,
      '',
      'Uma queda nesses números é boa e não avisa. Uma subida pode ser disco, serviço ou um problema real — vale olhar o journal, não o firewall.',
    ].join('\n'),
  };
}

export function formatBitRate(bps: number): string {
  const abs = Math.abs(bps);
  if (abs >= MBPS) {
    const mb = abs / MBPS;
    const text = mb >= 10 ? String(Math.round(mb)) : mb.toFixed(1).replace('.', ',');
    return `${text} MB/s`;
  }
  if (abs >= 1_000) return `${Math.round(abs / 1_000)} KB/s`;
  return `${Math.round(abs)} B/s`;
}
