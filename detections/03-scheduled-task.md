# T1053.005 — Scheduled Task/Job: Scheduled Task

| Campo | Valor |
|---|---|
| **Tática** | Persistence (TA0003), Execution (TA0002), Privilege Escalation (TA0004) |
| **Técnica** | T1053.005 |
| **Alvo** | Windows |

## Simulação

Criação de uma tarefa agendada que executa um binário/script num gatilho
(logon, intervalo). É um dos mecanismos de persistência mais comuns.

Teste equivalente no Atomic Red Team: `T1053.005`.

## Telemetria gerada

| Event ID | Fonte | Significado |
|---|---|---|
| **4698** | Security | Tarefa agendada criada (traz o XML da tarefa, incl. o comando) |
| **106** | TaskScheduler/Operational | Tarefa registrada |
| **Sysmon 1** | Sysmon | Execução de `schtasks.exe` (linha de comando com `/create`) |

O **4698** é o mais rico: o campo da tarefa contém a ação (o executável/comando),
o que permite inspecionar o que a tarefa roda. Ele depende da subcategoria
**Other Object Access Events** auditada.

## Detecção — Wazuh (`local_rules.xml`)

```xml
<group name="windows,persistence,attack,">

  <rule id="100301" level="8">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4698$</field>
    <description>Tarefa agendada criada: $(win.eventdata.taskName)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

  <!-- Sobe severidade quando a ação aponta p/ interpretadores (LOLBins) -->
  <rule id="100302" level="12">
    <if_sid>100301</if_sid>
    <field name="win.eventdata.taskContent" type="pcre2">(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32)</field>
    <description>Tarefa agendada executando intérprete/LOLBin (suspeito)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

</group>
```

> O nome exato do campo com o conteúdo da tarefa pode variar conforme o decoder.
> Valide com um evento real no dashboard (aba *Events* → expanda o 4698) e
> ajuste `win.eventdata.taskContent` para o campo que aparecer.

## Detecção — Splunk (SPL)

```spl
index=wineventlog EventCode=4698
| rex field=_raw "(?i)<Command>(?<task_command>[^<]+)</Command>"
| table _time, host, Task_Name, Subject_Account_Name, task_command
```

Com foco nos interpretadores:

```spl
index=wineventlog EventCode=4698
| search _raw="*powershell*" OR _raw="*cmd.exe*" OR _raw="*mshta*" OR _raw="*rundll32*"
| table _time, host, Task_Name, Subject_Account_Name
```

## Falsos positivos

- **Alto volume legítimo**: Windows, instaladores e softwares (updaters,
  antivírus, Office, navegadores) criam tarefas agendadas o tempo todo.
- Por isso a regra base (100301) é informativa; o valor está no filtro por
  **ação suspeita** (interpretadores, caminhos em `AppData`/`Temp`, comandos
  codificados) e por **quem criou** a tarefa.

Mitigação: *baseline*. Rode o ambiente limpo por alguns dias, liste as tarefas
recorrentes e crie uma *allowlist*. Alerte sobre o que fugir do baseline.
