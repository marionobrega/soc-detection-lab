# T1136.001 — Create Account: Local Account

| Campo | Valor |
|---|---|
| **Tática** | Persistence (TA0003) |
| **Técnica** | T1136.001 (+ T1098 quando a conta vai para um grupo privilegiado) |
| **Alvo** | Windows |

## Simulação

Criação de uma conta local nova no alvo (`net user` ou `New-LocalUser`),
opcionalmente adicionando-a ao grupo **Administradores**. Simula um atacante
estabelecendo acesso persistente.

Teste equivalente no Atomic Red Team: `T1136.001`.

## Telemetria gerada

| Event ID | Significado |
|---|---|
| **4720** | Conta de usuário criada (subcategoria *User Account Management*) |
| **4732** | Membro adicionado a grupo local de segurança, ex.: Administradores (subcategoria *Security Group Management*) |
| **4688 / Sysmon 1** | Execução de `net.exe` / `net1.exe` com linha de comando |

A combinação 4720 + 4732 (Administradores) em segundos é o sinal forte: conta
nova já com privilégio administrativo.

> O 4732 só aparece se a subcategoria **Security Group Management** estiver
> auditada — ela é diferente de *User Account Management*. Veja o passo 3.2 do
> [guia](../GUIA-EXECUCAO.md).

## Detecção — Wazuh (`local_rules.xml`)

```xml
<group name="windows,account_changes,attack,">

  <!-- Conta local criada -->
  <rule id="100201" level="8">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4720$</field>
    <description>Conta local criada: $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
  </rule>

  <!-- Membro adicionado ao grupo Administradores (SID S-1-5-32-544) -->
  <rule id="100202" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4732$</field>
    <field name="win.eventdata.targetSid">^S-1-5-32-544$</field>
    <description>Conta $(win.eventdata.memberSid) adicionada ao grupo Administradores</description>
    <mitre>
      <id>T1098</id>
    </mitre>
  </rule>

</group>
```

> **Por que duas regras independentes:** uma regra com `<if_matched_sid>100201`
> vira "filha" da 100201 no Wazuh, ou seja, só é avaliada em eventos 4720. Se ela
> exigir `eventID 4732`, nunca dispara. A correlação "criou + virou admin" fica
> com o analista (os dois alertas saem em sequência) ou com a busca do Splunk
> abaixo.

## Detecção — Splunk (SPL)

Correlação no mesmo host em até 2 minutos:

```spl
index=wineventlog (EventCode=4720 OR EventCode=4732)
| transaction host maxspan=2m
| search EventCode=4720 EventCode=4732
| table _time, host, Account_Name, Group_Name, Subject_Account_Name
```

Só criação de conta (menor severidade):

```spl
index=wineventlog EventCode=4720
| table _time, host, Account_Name, Subject_Account_Name
```

## Falsos positivos

- **Provisionamento legítimo** por TI, scripts de imagem/MDM ou instaladores que
  criam contas de serviço.
- **Ferramentas de backup/monitoramento** que criam contas locais na instalação.

Mitigação: correlacione o `Subject_Account_Name` (quem criou) — criação feita
por uma conta que não é de administração, ou fora de horário/janela de mudança,
é o que deve subir de severidade.
