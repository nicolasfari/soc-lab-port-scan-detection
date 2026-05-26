# soc-lab-port-scan-detection
# Detecção de Port Scanning com Sysmon e Splunk

Documentação prática de um pipeline de detecção de reconhecimento de rede (Port Scanning) utilizando Sysmon como sensor de host e Splunk como SIEM, com foco em otimização de ingestão (SIEM Tuning) e automação de alertas.

---

## Arquitetura do Laboratório

| Papel     | Host                                          |
|-----------|-----------------------------------------------|
| Atacante  | Kali Linux — `192.168.56.104`                 |
| Vítima    | Windows Client — `192.168.56.103` (Sysmon v15.20 + Universal Forwarder) |
| SIEM      | Splunk Enterprise — `192.168.56.102` / `index="main"` |

Todas as máquinas operam em rede isolada (Host-Only), sem exposição à rede doméstica.

---

## Fase 1 — Otimização de Ingestão (SIEM Tuning)

Em ambientes de produção, o custo de licenciamento do SIEM e a performance de busca são variáveis críticas. Enviar todos os eventos do canal `Security` sem filtragem gera saturação por eventos de baixo valor operacional, como o EventCode 4672 (Special Logon).

A solução adotada foi configurar uma whitelist diretamente no agente emissor (`inputs.conf`), garantindo que apenas eventos acionáveis de autenticação fossem ingeridos pelo Splunk.

```
[WinEventLog://Security]
disabled = 0
renderXml = 1
# Apenas Logon com Sucesso (4624) e Falha de Logon (4625)
whitelist = 4624, 4625
index = main

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = 1
index = main
```

Filtrar na origem reduz o volume de dados transmitidos pelo forwarder, diminui o processamento de queries e evita consumo desnecessário de licença.

---

## Fase 2 — Simulação do Ataque

A partir do host atacante (Kali Linux), foi executado um scan TCP Connect rápido contra o alvo Windows para mapear serviços ativos:

```bash
nmap -sT -F 192.168.56.103
```
Serviços identificados no alvo:

<img width="674" height="301" alt="image" src="https://github.com/user-attachments/assets/11908c52-9b20-4e75-ab20-3d8676c70558" />

---

## Fase 3 — Lógica de Detecção

Port scans são caracterizados por um comportamento estatisticamente anômalo: um único IP de origem tenta conexão com múltiplas portas distintas em um curto intervalo de tempo.

Utilizando eventos de conexão de rede gerados pelo Sysmon (EventCode 3) a seguinte query foi desenvolvida para correlacionar esse comportamento no Splunk:

```spl
index="main" sourcetype="XmlWinEventLog" EventCode=3
| stats dc(DestinationPort) as portas_distintas values(DestinationPort) as lista_portas by SourceIp
| where portas_distintas > 15
```
<img width="1641" height="801" alt="image" src="https://github.com/user-attachments/assets/990d58a0-202d-4f28-b27e-e67bd433ce9f" />

Por que essa lógica funciona:

- `dc(DestinationPort)` calcula a cardinalidade de portas únicas acessadas por cada IP de origem.
- O threshold `> 15` elimina falsos positivos de tráfego administrativo legítimo, que gera muitos eventos mas sempre direcionados aos mesmos poucos serviços.
- A detecção é agnóstica à ferramenta: funciona independentemente de o atacante usar Nmap, Netcat, Masscan ou scripts customizados.

---

## Fase 4 — Automação do Alerta no Splunk

A query de detecção foi convertida em um alerta para garantir resposta imediata a tentativas de reconhecimento de rede.

<img width="841" height="776" alt="image" src="https://github.com/user-attachments/assets/9013f5d0-89bd-4d71-9842-fda9f69f3023" />
<img width="1647" height="271" alt="image" src="https://github.com/user-attachments/assets/b5266350-214a-43b5-bcf9-dcba3325bea9" />

---
## MITRE ATT&CK Mapping

| Tática         | Técnica                  | ID     | Descrição                                      |
|----------------|--------------------------|--------|------------------------------------------------|
| Reconnaissance | Network Service Discovery| T1046  | Varredura de portas com Nmap (-sT -F)          |
| Discovery      | Network Service Scanning | T1046  | Identificação de RDP, SMB e RPC no alvo        |
| Detection      | Network Traffic Analysis | DS0029 | Detecção via cardinalidade no Sysmon EventID 3 |
| Detection      | Logon Session Monitoring | DS0028 | Monitoramento de 4624/4625 pós-reconhecimento  |

## Conclusões

**Redução de ruído:** A whitelist no `inputs.conf` reduziu a ingestão de eventos de baixo valor, otimizando o processamento das queries e o consumo de licença.

**Visibilidade de rede:** O Sysmon preencheu a lacuna dos logs nativos do Windows, fornecendo telemetria de camada de rede (EventID 3) com IP de origem, IP de destino e porta — dados essenciais para qualquer investigação de reconhecimento.

**Detecção comportamental:** A abordagem por cardinalidade se mostrou resiliente a variações de técnica. Qualquer ferramenta de scan que gere conexões a múltiplas portas em sequência será detectada pela mesma regra.
