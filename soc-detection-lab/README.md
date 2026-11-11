# SOC Detection Lab — Detection Engineering com MITRE ATT&CK

Projeto de portfólio de **engenharia de detecção**. Para cada técnica de ataque
conhecida, este repositório documenta: como ela foi simulada de forma controlada
no lab, qual telemetria ela gera, a regra que a detecta no SIEM (Wazuh e/ou
Splunk) e a análise de falsos positivos.

O objetivo não é "atacar" — é provar que sei **transformar atividade suspeita em
detecção acionável**, que é o trabalho de um analista de SOC.

---

## Arquitetura do lab

| Papel | Máquina | Função |
|---|---|---|
| **SIEM** | Ubuntu 24.04 (VirtualBox) | Wazuh manager + dashboard |
| **SIEM (alt.)** | Ubuntu (VirtualBox) | Splunk Enterprise (free) |
| **Alvo** | Windows 10/11 | Endpoint monitorado (agente Wazuh + Universal Forwarder) |
| **Emulação** | Kali Linux | Origem dos testes de rede (ex.: brute force RDP) |

### Telemetria habilitada no alvo Windows (pré-requisito)

A qualidade da detecção depende do que o endpoint registra. Antes de qualquer teste:

- **Sysmon** com uma config de referência (ex.: a do SwiftOnSecurity ou a do
  Olaf Hartong). É o que dá visibilidade de criação de processo, linha de
  comando, conexões de rede e acesso a processos.
- **Auditoria avançada do Windows** ligada via GPO/`auditpol`:
  - Logon/Logoff → sucesso e falha (4624/4625)
  - User Account Management → sucesso (4720)
  - Security Group Management → sucesso (4732)
  - Process Creation (4688) com linha de comando habilitada
  - Other Object Access Events → sucesso (4698, tarefas agendadas)
- **PowerShell Script Block Logging** (Event ID 4104).

> Sem Sysmon + linha de comando no 4688 + Script Block Logging, metade das
> detecções abaixo não dispara. Esse é o aprendizado número um do projeto.

O passo a passo completo de montagem está em [`GUIA-EXECUCAO.md`](GUIA-EXECUCAO.md).

---

## Metodologia (igual para toda técnica)

1. **Mapear** a técnica no ATT&CK (ID + tática).
2. **Simular** com um teste atômico do [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
   (`Invoke-AtomicTest T#### -TestNumbers #`). O ART é a ferramenta padrão de
   *adversary emulation* e já traz os testes documentados e com *cleanup*.
3. **Observar** qual log/Event ID foi gerado.
4. **Escrever** a regra de detecção (Wazuh XML e/ou Splunk SPL).
5. **Validar**: disparar o teste de novo e confirmar o alerta.
6. **Documentar** no formato de [relatório de incidente](reports/incident-report-template.md),
   com falsos positivos.

---

## Índice de técnicas

| # | Técnica | ATT&CK ID | Tática | Detecção |
|---|---|---|---|---|
| 1 | Brute force RDP | T1110.001 | Credential Access | [01-brute-force-rdp.md](detections/01-brute-force-rdp.md) |
| 2 | Criação de usuário local | T1136.001 | Persistence | [02-local-account-creation.md](detections/02-local-account-creation.md) |
| 3 | Persistência via tarefa agendada | T1053.005 | Persistence / Execution | [03-scheduled-task.md](detections/03-scheduled-task.md) |
| 4 | PowerShell codificado | T1059.001 / T1027 | Execution / Defense Evasion | [04-encoded-powershell.md](detections/04-encoded-powershell.md) |
| 5 | Acesso a credenciais via LSASS | T1003.001 | Credential Access | [05-lsass-access.md](detections/05-lsass-access.md) |

---

## Estrutura do repositório

```
soc-detection-lab/
├── README.md
├── GUIA-EXECUCAO.md          # como montar e rodar o lab
├── detections/               # uma análise por técnica
│   ├── 01-brute-force-rdp.md
│   ├── 02-local-account-creation.md
│   ├── 03-scheduled-task.md
│   ├── 04-encoded-powershell.md
│   └── 05-lsass-access.md
├── reports/
│   └── incident-report-template.md
└── img/                      # prints dos alertas e logs
```

---

## Status

- [x] Lab montado (Wazuh, Splunk, alvo Windows, Kali)
- [x] Telemetria base (Sysmon + auditoria + PowerShell logging)
- [ ] Técnica 1 — detecção validada
- [ ] Técnica 2 — detecção validada
- [ ] Técnica 3 — detecção validada
- [ ] Técnica 4 — detecção validada
- [ ] Técnica 5 — detecção validada
