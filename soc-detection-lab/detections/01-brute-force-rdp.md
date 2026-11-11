# T1110.001 — Brute Force: Password Guessing (RDP)

| Campo | Valor |
|---|---|
| **Tática** | Credential Access (TA0006) |
| **Técnica** | T1110.001 |
| **Alvo** | Windows (RDP habilitado na rede do lab) |
| **Origem** | Kali |

## Simulação

Tentativas repetidas de autenticação RDP a partir do Kali com uma wordlist
pequena contra uma conta de teste. O objetivo é gerar o padrão de muitas falhas
seguidas, eventualmente seguidas de um sucesso, e não comprometer a conta.

Teste equivalente no Atomic Red Team: `T1110.001`.

## Telemetria gerada

| Event ID | Significado | Campos úteis |
|---|---|---|
| **4625** | Falha de logon | `LogonType=3` (com NLA, padrão no Windows 10/11) ou `LogonType=10` (RemoteInteractive, sem NLA), `IpAddress`, `TargetUserName`, `Status`/`SubStatus` |
| **4624** | Logon com sucesso | `LogonType=3` seguido de `LogonType=10`, mesmo `IpAddress` → indica brute force **bem-sucedido** |

O sinal de detecção é a **frequência**: N falhas (4625) do mesmo IP numa janela curta.
O sinal de maior severidade é um 4624 do mesmo IP **após** a rajada de 4625.

> **Atenção ao NLA:** com Network Level Authentication ligado (padrão no
> Windows 10/11), a senha é validada antes de a sessão RDP abrir, então as
> falhas aparecem como 4625 com `LogonType=3`, não 10. Filtrar só por
> `LogonType=10` deixa o brute force passar. Por isso as regras abaixo aceitam
> os dois tipos.

## Detecção — Wazuh (`local_rules.xml`)

```xml
<group name="windows,authentication_failures,attack,">

  <!-- Regra base: falha de logon de rede/RDP (LogonType 3 com NLA, 10 sem NLA) -->
  <rule id="100101" level="5">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4625$</field>
    <field name="win.eventdata.logonType">^(3|10)$</field>
    <description>Falha de logon remoto de $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

  <!-- Correlação por frequência: 8 falhas em 120s do mesmo IP = possível brute force -->
  <rule id="100102" level="10" frequency="8" timeframe="120">
    <if_matched_sid>100101</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Possível brute force RDP: múltiplas falhas de $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
  </rule>

</group>
```

## Detecção — Splunk (SPL)

```spl
index=wineventlog EventCode=4625 Logon_Type IN (3, 10)
| bin _time span=2m
| stats count values(Account_Name) as contas by _time, Source_Network_Address
| where count >= 8
| sort - count
```

Variante de **alta severidade** (falhas seguidas de sucesso do mesmo IP):

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624) Logon_Type IN (3, 10)
| transaction Source_Network_Address maxspan=5m
| search EventCode=4625 EventCode=4624
| table _time, Source_Network_Address, Account_Name, eventcount
```

## Falsos positivos

- **Administradores legítimos** errando a senha (especialmente após troca de senha
  ou expiração). Mitigação: *allowlist* de IPs de administração.
- **Servidores de pulo / jump hosts** e ferramentas de monitoramento que fazem
  logon RDP com frequência.
- **Contas de serviço mal configuradas** que tentam reconectar em loop.
- Com `LogonType=3` entram também falhas de compartilhamento de rede (SMB). Se
  gerar ruído, filtre pelo processo de logon ou cruze com conexões na porta 3389.

Ajuste o `frequency`/janela ao volume real do ambiente — num endpoint doméstico 8/120s
é alto; num servidor compartilhado pode ser ruído.
