/**
 * Copy humano por playbook. Substitui o antigo switch de `describePlaybookAction`
 * e o `includes('killed')` do notify: a mensagem não depende de adivinhar o
 * texto do parâmetro.
 */
export interface PlaybookCopy {
  /** O que a ação faz, em uma frase curta (usado no título). */
  actionTitle: string;
  /** Impacto/efeito para o operador. */
  impact: string;
  /** Próximo passo sugerido, quando houver. */
  nextStep?: string;
  /** Passos que serão executados (para o pedido de aprovação). */
  steps: string[];
}

const COPY: Record<string, PlaybookCopy> = {
  'ssh-brute-force': {
    actionTitle: 'Bloquear o IP',
    impact: 'O IP que tentou adivinhar a senha fica barrado no firewall deste servidor.',
    nextStep: 'Confira se o SSH continua acessível.',
    steps: ['Adicionar o IP à lista de bloqueio', 'Aplicar a regra no firewall', 'Confirmar que a regra está ativa'],
  },
  'port-scan-response': {
    actionTitle: 'Bloquear o IP',
    impact: 'O IP que varreu portas fica barrado no firewall deste servidor.',
    steps: ['Adicionar o IP à lista de bloqueio', 'Aplicar a regra no firewall'],
  },
  'crypto-mining-response': {
    actionTitle: 'Matar o minerador',
    impact: 'O processo de mineração é encerrado e o IP de origem é bloqueado.',
    nextStep: 'Verifique se o serviço voltou ao normal.',
    steps: ['Encerrar o processo', 'Bloquear o IP de origem', 'Confirmar o bloqueio'],
  },
  'container-escape-response': {
    actionTitle: 'Isolar o container',
    impact: 'O container é pausado e desconectado da rede. Ele fica inacessível até uma ação manual.',
    nextStep: 'Investigue o container antes de religá-lo.',
    steps: ['Pausar o container', 'Desconectar todas as redes', 'Avisar a equipe'],
  },
  'lateral-movement-response': {
    actionTitle: 'Bloquear o IP',
    impact: 'O IP usado para se mover entre máquinas fica barrado.',
    steps: ['Adicionar o IP à lista de bloqueio', 'Aplicar a regra no firewall'],
  },
  'connection-flood-response': {
    actionTitle: 'Bloquear o IP',
    impact: 'O IP que abriu conexões demais fica barrado.',
    steps: ['Adicionar o IP à lista de bloqueio', 'Aplicar a regra no firewall'],
  },
  'ddos-syn-flood-response': {
    actionTitle: 'Aplicar limite de taxa',
    impact: 'O IP passa a ser limitado a 10 conexões por segundo, em vez de bloqueado de imediato.',
    steps: ['Aplicar limite de taxa', 'Acompanhar se o volume cai'],
  },
  'connection-rate-response': {
    actionTitle: 'Aplicar limite de taxa',
    impact: 'O IP passa a ser limitado a 10 conexões por segundo.',
    steps: ['Aplicar limite de taxa', 'Acompanhar se o volume cai'],
  },
  'bandwidth-spike-response': {
    actionTitle: 'Avisar sobre o pico',
    impact: 'Nenhuma ação automática é tomada; este aviso serve para você olhar o tráfego.',
    nextStep: 'Se o site estiver lento, investigue o processo que está transferindo dados.',
    steps: ['Registrar o pico', 'Avisar a equipe'],
  },
  'suspicious-process': {
    actionTitle: 'Avisar sobre o processo',
    impact: 'Nenhuma ação automática é tomada; o processo não é morto sem sua decisão.',
    nextStep: 'Investigue o processo antes de encerrá-lo.',
    steps: ['Registrar o processo', 'Avisar a equipe'],
  },
  'password-login-alert': {
    actionTitle: 'Avisar sobre o login',
    impact: 'Nenhuma ação automática é tomada.',
    nextStep: 'Considere desabilitar login por senha no SSH.',
    steps: ['Registrar o login', 'Avisar a equipe'],
  },
  'unusual-hour-alert': {
    actionTitle: 'Avisar sobre o horário',
    impact: 'Nenhuma ação automática é tomada.',
    steps: ['Registrar o login', 'Avisar a equipe'],
  },
  'file-integrity-response': {
    actionTitle: 'Avisar sobre o arquivo',
    impact: 'Nenhuma ação automática é tomada; o arquivo não é restaurado sozinho.',
    nextStep: 'Investigue a mudança imediatamente: pode ser backdoor.',
    steps: ['Registrar a mudança', 'Avisar a equipe'],
  },
  'sudo-suspicious-response': {
    actionTitle: 'Avisar sobre o comando',
    impact: 'Nenhuma ação automática é tomada.',
    steps: ['Registrar o comando', 'Avisar a equipe'],
  },
  'cron-persistence-response': {
    actionTitle: 'Avisar sobre o cron',
    impact: 'Nenhuma ação automática é tomada; o cron não é removido.',
    nextStep: 'Confirme se o agendamento é legítimo.',
    steps: ['Registrar o cron', 'Avisar a equipe'],
  },
  'ssh-key-response': {
    actionTitle: 'Avisar sobre a chave',
    impact: 'Nenhuma ação automática é tomada.',
    nextStep: 'Confirme se a chave é conhecida.',
    steps: ['Registrar a chave', 'Avisar a equipe'],
  },
  'dns-c2-response': {
    actionTitle: 'Avisar sobre o DNS',
    impact: 'Nenhuma ação automática é tomada; o domínio não é bloqueado.',
    steps: ['Registrar a consulta', 'Avisar a equipe'],
  },
  'dns-suspicious-tld-response': {
    actionTitle: 'Avisar sobre o domínio',
    impact: 'Nenhuma ação automática é tomada.',
    steps: ['Registrar a consulta', 'Avisar a equipe'],
  },
  'container-crypto-response': {
    actionTitle: 'Matar o minerador e isolar o container',
    impact: 'O processo é morto, o container é desconectado da rede e reiniciado.',
    nextStep: 'Verifique se o container voltou saudável.',
    steps: ['Matar o processo', 'Desconectar a rede', 'Reiniciar o container'],
  },
  'container-mining-network-response': {
    actionTitle: 'Isolar e reiniciar o container',
    impact: 'O container é desconectado da rede e reiniciado. Há alguns segundos de indisponibilidade.',
    nextStep: 'Verifique se o container voltou saudável.',
    steps: ['Desconectar a rede', 'Reiniciar o container'],
  },
  'container-rce-containment': {
    actionTitle: 'Isolar o container',
    impact: 'O container é desconectado da rede e fica sem acesso até uma ação manual. Nada é reiniciado, para preservar a evidência.',
    nextStep: 'Investigue o processo e o binário antes de religar a rede.',
    steps: ['Desconectar o container da rede', 'Avisar a equipe'],
  },
  'container-egress-containment': {
    actionTitle: 'Isolar o container',
    impact: 'O container é desconectado da rede e fica sem acesso até uma ação manual. Nada é reiniciado, para preservar a evidência.',
    nextStep: 'Investigue o processo que iniciou as conexões antes de religar a rede.',
    steps: ['Desconectar o container da rede', 'Avisar a equipe'],
  },
  'container-fs-tampering-response': {
    actionTitle: 'Avisar sobre o arquivo no container',
    impact: 'Nenhuma ação destrutiva automática é tomada.',
    nextStep: 'Investigue o arquivo antes de reiniciar o container.',
    steps: ['Registrar o arquivo', 'Avisar a equipe'],
  },
  'container-auto-update': {
    actionTitle: 'Atualizar a imagem do container',
    impact: 'A imagem corrigida é baixada e o container é recriado. O serviço fica ~10 segundos fora do ar.',
    nextStep: 'Confirme se o container voltou saudável.',
    steps: ['Baixar a imagem corrigida', 'Recriar o container', 'Avisar a equipe'],
  },
  'container-suspicious-exec-response': {
    actionTitle: 'Matar o processo do container',
    impact: 'O processo iniciado de /tmp ou /dev/shm é encerrado.',
    nextStep: 'Investigue como o binário chegou ali.',
    steps: ['Encerrar o processo', 'Avisar a equipe'],
  },
  'proxy-scanner-block': {
    actionTitle: 'Bloquear o scanner',
    impact: 'O IP que varre rotas sensíveis fica barrado permanentemente.',
    steps: ['Adicionar o IP à lista de bloqueio', 'Aplicar a regra no firewall'],
  },
  'backup-missing-alert': {
    actionTitle: 'Avisar sobre o backup',
    impact: 'Nenhuma ação automática é tomada.',
    nextStep: 'Verifique o cron e o script de backup.',
    steps: ['Registrar a falha', 'Avisar a equipe'],
  },
  'backup-too-small-alert': {
    actionTitle: 'Avisar sobre o backup',
    impact: 'Nenhuma ação automática é tomada.',
    nextStep: 'Confira o dump antes de descartar o backup anterior.',
    steps: ['Registrar a falha', 'Avisar a equipe'],
  },
  'unexpected-container-alert': {
    actionTitle: 'Avisar sobre o container',
    impact: 'Nenhuma ação automática é tomada.',
    nextStep: 'Confirme se o container é legítimo.',
    steps: ['Registrar o container', 'Avisar a equipe'],
  },
};

const GENERIC: PlaybookCopy = {
  actionTitle: 'Executar a ação',
  impact: 'Nenhuma ação automática adicional é tomada.',
  steps: ['Executar o playbook', 'Registrar o resultado'],
};

export function playbookCopy(name?: string | null): PlaybookCopy {
  if (!name) return GENERIC;
  return COPY[name] ?? GENERIC;
}
