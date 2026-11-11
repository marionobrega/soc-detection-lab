# T1003.001 — OS Credential Dumping: LSASS Memory

| Campo | Valor |
|---|---|
| **Tática** | Credential Access (TA0006) |
| **Técnica** | T1003.001 |
| **Alvo** | Windows |

## Simulação

Simular o **acesso à memória do processo `lsass.exe`**, que é o indicador que
antecede um dump de credenciais. Para o lab, o objetivo é gerar o evento de
acesso ao processo e detectá-lo — não extrair credenciais reais.

Teste equivalente no Atomic Red Team: `T1003.001` (há variantes que apenas
abrem um handle para o LSASS, ideais para exercitar a detecção sem material
sensível).

> Mantenha isto numa VM de lab isolada e com snapshot. Faça a simulação com uma
> ferramenta pública de emulação (ART), não com credenciais reais. O Microsoft
> Defender costuma bloquear esses testes — na VM de lab, desative a proteção em
> tempo real ou crie uma exclusão para a pasta `C:\AtomicRedTeam` durante o teste.

## Telemetria gerada

| Event ID | Fonte | Significado |
|---|---|---|
| **Sysmon 10** | Sysmon | ProcessAccess — um processo abriu handle para outro. `TargetImage=lsass.exe` é o sinal |
| **4656 / 4663** | Security | Handle solicitado/acesso a objeto (precisa de SACL no LSASS; mais ruidoso) |
| **Sysmon 1** | Sysmon | Execução da ferramenta de dumping, se houver binário em disco |

A detecção de referência é o **Sysmon Event ID 10** com `TargetImage` terminando
em `lsass.exe` e uma máscara de acesso (`GrantedAccess`) que inclui leitura de
memória (valores clássicos: `0x1010`, `0x1410`, `0x143a`, `0x1fffff`).

## Detecção — Wazuh (`local_rules.xml`)

```xml
<group name="windows,sysmon,credential_access,attack,">

  <rule id="100501" level="12">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe$</field>
    <description>Acesso a LSASS: $(win.eventdata.sourceImage) -> lsass.exe (possível dump de credenciais)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>

</group>
```

> Em algumas versões o grupo é `sysmon_event_10`; se não bater, troque por
> `<field name="win.system.eventID">^10$</field>` dentro de
> `<if_group>windows</if_group>`.

## Detecção — Splunk (SPL)

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| table _time, host, SourceImage, SourceProcessId, GrantedAccess, CallTrace
| sort - _time
```

Reduzir ruído excluindo acessos legítimos conhecidos:

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
NOT SourceImage IN ("*\\MsMpEng.exe","*\\wininit.exe","*\\csrss.exe","*\\services.exe","*\\lsass.exe")
| table _time, host, SourceImage, GrantedAccess, CallTrace
```

## Falsos positivos

- **Processos legítimos do próprio Windows e de segurança** acessam o LSASS:
  antivírus (`MsMpEng.exe`), EDRs, `wininit.exe`, `csrss.exe`, ferramentas de
  monitoramento.
- Por isso a detecção depende de **allowlist de `SourceImage`** e da inspeção da
  `GrantedAccess` e da `CallTrace`.

Mitigação: construa a allowlist com o que acessa o LSASS no ambiente limpo;
alerte sobre qualquer `SourceImage` fora dessa lista — especialmente processos em
`Temp`/`AppData` ou sem assinatura.
