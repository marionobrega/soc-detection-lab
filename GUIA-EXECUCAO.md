# Guia de execução — como rodar o lab

Ordem recomendada. **Faça snapshot de cada VM antes de começar.**

```
[1] Subir SIEM → [2] Instalar agentes no alvo Windows →
[3] Ligar telemetria → [4] Aplicar regras →
[5] Disparar teste → [6] Validar alerta → [7] Documentar
```

---

## 0. Rede

Deixe as VMs na mesma rede (**Rede Interna** ou **Host-Only** no VirtualBox) e
anote os IPs. Exemplo usado neste guia:

| Máquina | IP (exemplo) |
|---|---|
| Wazuh manager (Ubuntu) | 192.168.56.10 |
| Splunk (Ubuntu) | 192.168.56.11 |
| Alvo Windows | 192.168.56.20 |
| Kali | 192.168.56.30 |

---

## 1. Subir o SIEM

### Wazuh (all-in-one, Ubuntu 24.04)

```bash
# confira a versão atual em https://documentation.wazuh.com e troque o "4.9" se necessário
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Ao final, o script imprime a senha do usuário `admin`. Acesse o dashboard em
`https://192.168.56.10` e guarde a senha.

### Splunk (opcional, em paralelo)

Baixe o Splunk Enterprise (licença Free/Trial) para Linux, instale e inicie:

```bash
sudo tar -xzf splunk-*.tgz -C /opt
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
```

Crie os índices que as buscas usam: `wineventlog`, `sysmon`, `powershell`
(Settings → Indexes → New Index) e habilite a porta de recebimento 9997
(Settings → Forwarding and receiving → Configure receiving).

---

## 2. Instalar os agentes no alvo Windows

### Agente Wazuh

No dashboard: **Agents → Deploy new agent**, escolha Windows, informe o IP do
manager (`192.168.56.10`) e rode o comando gerado no PowerShell **como admin**.
Depois:

```powershell
NET START WazuhSvc
```

### Universal Forwarder (se for usar Splunk)

Instale o **Splunk Universal Forwarder** no Windows, aponte para o Splunk
(`192.168.56.11:9997`) e instale os add-ons **Splunk_TA_windows** e
**Splunk_TA_microsoft_sysmon** (eles normalizam os campos usados nas buscas SPL).

---

## 3. Ligar a telemetria no alvo Windows ⚠️ passo mais importante

Rode num PowerShell **como administrador**.

### 3.1 Sysmon

```powershell
# baixe o Sysmon (Sysinternals) e uma config de referência (ex.: SwiftOnSecurity)
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```

### 3.2 Auditoria avançada (Event IDs do Security)

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable                 # 4624 / 4625
auditpol /set /subcategory:"User Account Management" /success:enable               # 4720
auditpol /set /subcategory:"Security Group Management" /success:enable             # 4732
auditpol /set /subcategory:"Process Creation" /success:enable                      # 4688
auditpol /set /subcategory:"Other Object Access Events" /success:enable            # 4698
```

> Os nomes das subcategorias estão em inglês. Se o Windows estiver em português,
> use `auditpol /list /subcategory:*` para ver os nomes locais, ou use o GUID da
> subcategoria.

### 3.3 Linha de comando no evento 4688 (sem isto, a técnica 4 não detecta)

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### 3.4 PowerShell Script Block Logging (Event ID 4104)

```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

### 3.5 Fazer o agente coletar os canais Sysmon e PowerShell

No Windows, edite `C:\Program Files (x86)\ossec-agent\ossec.conf` e adicione:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Depois: `Restart-Service WazuhSvc`.

No Splunk, o equivalente é liberar esses canais no `inputs.conf` do forwarder (os
add-ons já trazem os stanzas; basta habilitar `WinEventLog:Security`, Sysmon e
`WinEventLog:Microsoft-Windows-PowerShell/Operational`).

### 3.6 Habilitar RDP no alvo (necessário para a técnica 1)

```powershell
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"   # em Windows PT-BR: "Área de Trabalho Remota"
```

---

## 4. Aplicar as regras de detecção (Wazuh)

No manager (Ubuntu), cole as regras `100101…100501` dos arquivos de
`detections/` em:

```
/var/ossec/etc/rules/local_rules.xml
```

Valide e reinicie:

```bash
sudo /var/ossec/bin/wazuh-logtest   # opcional: testa um log de exemplo
sudo systemctl restart wazuh-manager
```

No Splunk não há "aplicar regra": as buscas SPL dos arquivos você roda direto na
barra de busca (e pode salvá-las como *Saved Search/Alert*).

---

## 5. Disparar um teste (Atomic Red Team)

No alvo Windows, PowerShell **como admin**. O Microsoft Defender bloqueia vários
testes: na VM de lab, crie uma exclusão para `C:\AtomicRedTeam` antes.

```powershell
# instala o módulo e baixa a pasta de testes (atomics)
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force
Import-Module invoke-atomicredteam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicsfolder.ps1' -UseBasicParsing)
Install-AtomicsFolder

# lista os testes disponíveis daquela técnica
Invoke-AtomicTest T1136.001 -ShowDetailsBrief

# instala os pré-requisitos e executa
Invoke-AtomicTest T1136.001 -GetPrereqs
Invoke-AtomicTest T1136.001

# SEMPRE limpe o que o teste criou
Invoke-AtomicTest T1136.001 -Cleanup
```

Troque o ID conforme a técnica: `T1136.001`, `T1053.005`, `T1059.001`, `T1003.001`.

A técnica 1 (brute force RDP) você dispara do **Kali** contra o `192.168.56.20`,
com uma wordlist curta e uma conta de teste — o objetivo é só gerar os 4625.

---

## 6. Validar o alerta

### Wazuh

Dashboard → **Threat Hunting / Events** → filtre por `rule.id` (ex.: `100102`) ou
pela janela de tempo do teste. Abra o evento e confirme os campos
(`win.eventdata.ipAddress`, `commandLine`, etc.).

Se não disparar, o motivo quase sempre é um destes:

- a telemetria do passo 3 não está ligada (confira com `auditpol /get /category:*`);
- o agente não está coletando o canal (veja se o evento aparece em *Events* sem a regra);
- o nome do campo na regra não bate com o do evento real → abra o evento no
  dashboard, veja o campo que apareceu e ajuste o `<field name="...">`.

### Splunk

Rode a busca SPL do arquivo da técnica, ajustando o `index=` para o seu. Se vier
vazio, verifique o nome real dos campos com:

```spl
index=* host=<alvo> | head 20 | fields *
```

---

## 7. Documentar

Para cada técnica validada, copie `reports/incident-report-template.md`,
preencha e tire prints (do comando, do log cru e do alerta) na pasta `img/`.
Depois marque a técnica como validada na seção **Status** do `README.md`.
É a documentação que dá valor ao portfólio.
