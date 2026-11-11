# T1059.001 / T1027 — PowerShell com comando codificado

| Campo | Valor |
|---|---|
| **Tática** | Execution (TA0002) + Defense Evasion (TA0005) |
| **Técnica** | T1059.001 (PowerShell) + T1027 (Obfuscated Files or Information) |
| **Alvo** | Windows |

## Simulação

Execução de `powershell.exe` com a flag `-EncodedCommand` (ou uma abreviação dela,
como `-enc`, `-ec` ou `-e`) passando um comando **benigno** em Base64 (ex.: um
`Write-Host`/`whoami`). A codificação em si é o indicador — não é preciso rodar
nada malicioso para gerar o padrão de detecção.

Teste equivalente no Atomic Red Team: `T1059.001`.

## Telemetria gerada

| Event ID | Fonte | Significado |
|---|---|---|
| **4688** | Security | Criação de processo com linha de comando (precisa estar habilitado) |
| **Sysmon 1** | Sysmon | Criação de processo, com `CommandLine`, `ParentImage`, hashes |
| **4104** | PowerShell/Operational | Script Block Logging — mostra o conteúdo **já decodificado** |

O **4104** é o mais poderoso: mesmo que o comando venha em Base64, o Script Block
Logging registra o script decodificado que o PowerShell executou.

> **Por que o regex cobre várias formas:** o PowerShell aceita qualquer
> abreviação inequívoca de `-EncodedCommand` (`-e`, `-ec`, `-en`, `-enc`,
> `-enco`… até o nome inteiro), com `-` ou `/`. Um regex que só procura `-enc`
> é contornado com `-en` ou `-ec`.

## Detecção — Wazuh (`local_rules.xml`)

```xml
<group name="windows,powershell,attack,">

  <!-- Linha de comando com flag de codificação (qualquer abreviação de -EncodedCommand) -->
  <rule id="100401" level="10">
    <if_group>windows</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell(\.exe)?.*\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s</field>
    <description>PowerShell com comando codificado (Base64) — T1059.001/T1027</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1027</id>
    </mitre>
  </rule>

  <!-- Outros sinais de ofuscação/execução sem restrição -->
  <rule id="100402" level="8">
    <if_group>windows</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-nop|-noprofile|-w\s*hidden|-windowstyle\s+hidden|frombase64string|iex\s*\(|downloadstring)</field>
    <description>PowerShell com argumentos de execução suspeitos</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>
```

## Detecção — Splunk (SPL)

Via **Sysmon** (recomendado):

```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
| regex CommandLine="(?i)\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s"
| table _time, host, User, ParentImage, CommandLine
```

Via **Script Block Logging** (vê o conteúdo decodificado):

```spl
index=powershell EventCode=4104
| search ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*DownloadString*"
| table _time, host, UserID, ScriptBlockText
```

## Falsos positivos

- **Administração legítima**: muitas ferramentas de gestão (SCCM/Intune,
  Chocolatey, instaladores) usam `-EncodedCommand` como mecanismo normal de
  passar scripts.
- Isso significa que a presença de `-enc` sozinha **não é malícia** — por isso a
  regra 100401 é nível médio-alto, não crítico.

Mitigação: enriqueça com **processo pai** (`ParentImage`). PowerShell codificado
filho de `winword.exe`, `excel.exe`, `outlook.exe` ou `mshta.exe` é muito mais
suspeito do que filho de `sccm`/`services.exe`. Decodifique o Base64 na análise e
verifique o que o comando realmente fazia.
