export interface ThreatAdviceInput {
  score: number | null;
  totalReports: number;
  eventCount: number;
  alreadyBlocked: boolean;
  firewallEvents: number;
}

/**
 * Plain-language recommendation. An IP that is already in the block table
 * must not be told to /block again. firewall_block rows are the firewall
 * logging packets, not proof of a new breach.
 */
export function threatAdvice(input: ThreatAdviceInput): string[] {
  const firewallOnly = input.eventCount > 0 && input.firewallEvents === input.eventCount;

  if (input.alreadyBlocked) {
    const lines = [
      '✅ <b>JÁ ESTÁ BLOQUEADO</b>',
      'Esse IP já está na lista. Não precisa bloquear de novo e não precisa tocar em nada por causa desta mensagem.',
    ];
    if (input.firewallEvents > 0) {
      lines.push('Os eventos de firewall são o próprio firewall anotando pacotes. Isso é a defesa registrando, não um ataque novo.');
    }
    return lines;
  }

  if (firewallOnly && (input.score === null || input.score < 80)) {
    return [
      '🟡 <b>SÓ VARREDURA EM PORTA FECHADA</b>',
      'A única atividade local é o firewall recusando pacotes em portas que já não atendem.',
      'Não é urgente. Bloquear só passa a proteger SSH e o site se a regra entrar na frente das liberações dessas portas.',
    ];
  }

  if (input.score !== null && input.score >= 80) {
    return [
      '⚠️ <b>VALE BLOQUEAR</b>',
      `Reputação ruim (${input.score}/100), com ${input.totalReports} denúncias fora daqui.`,
      firewallOnly
        ? 'Aqui ele só esbarrou em portas fechadas. Mesmo assim a reputação é péssima.'
        : 'Também houve atividade nos nossos serviços, não só pacote recusado.',
      'Bloquear protege SSH e o site somente se a regra ficar antes da liberação dessas portas.',
    ];
  }

  if (input.score !== null && input.score >= 50) {
    return [
      '🟠 <b>SUSPEITO</b>',
      `Reputação média (${input.score}/100), ${input.totalReports} denúncias.`,
      input.eventCount > 5
        ? 'Várias tentativas nos nossos logs. Dá para bloquear se continuar.'
        : 'Pouca atividade aqui. Pode só observar.',
    ];
  }

  if (input.score !== null && input.score >= 25) {
    return [
      '🟡 <b>POUCO SINAL</b>',
      `Reputação baixa-média (${input.score}/100). Pode ser um scanner automático.`,
      input.eventCount > 10 ? 'Muita atividade local — considere bloquear.' : 'Não é urgente.',
    ];
  }

  if (input.score !== null) {
    return [
      '🟢 <b>SEM PRESSA</b>',
      `Reputação boa (${input.score}/100). Não precisa bloquear.`,
    ];
  }

  if (input.eventCount > 20) {
    return [
      '🟠 <b>MUITA ATIVIDADE, SEM REPUTAÇÃO EXTERNA</b>',
      'Não há dados do AbuseIPDB. O volume local é alto o bastante para bloquear se você reconhecer o padrão.',
    ];
  }

  return [
    '⚪ <b>DADOS INSUFICIENTES</b>',
    'Sem reputação externa e pouca atividade. Só observar.',
  ];
}
