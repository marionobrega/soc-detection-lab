# Relatório de Incidente — [Nome da técnica]

> Preencha um destes para cada detecção validada. É esse formato que mostra ao
> recrutador que você raciocina como analista, não só que instalou ferramentas.

## 1. Resumo
Uma frase: o que foi detectado, em qual host, quando.

## 2. Técnica (MITRE ATT&CK)
- **ID / Nome:** T####.### — …
- **Tática:** …

## 3. Linha do tempo
| Horário (UTC-3) | Evento |
|---|---|
| | |

## 4. O que gerou o alerta
- **Fonte de log / Event ID:** …
- **Regra que disparou:** (Wazuh rule id / SPL)
- **Print do alerta:** `![alerta](../img/....png)`

## 5. Evidências
Campos-chave do evento (usuário, processo pai, IP de origem, linha de comando,
hashes). Cole o trecho do log relevante.

## 6. Análise
Como interpretei o evento. Por que é (ou não é) malicioso. Confiança.

## 7. Falsos positivos
Em que cenário legítimo isto dispararia e como diferenciar.

## 8. Recomendações
O que um analista recomendaria: conter o host, resetar senha, bloquear IP,
ajustar a regra, criar baseline, etc.
