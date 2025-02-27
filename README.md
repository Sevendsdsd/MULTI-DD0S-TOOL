# 🚀 MULTIDDOSTOOL

**👨‍💻 Desenvolvido por:** Seven & xAI

> ⚠️ **Aviso Importante:**
> Este software é um protótipo e **não recebe suporte**. O uso indevido da ferramenta é de inteira responsabilidade do usuário. **Utilizar contra sistemas sem permissão é ilegal e eticamente inaceitável.**

## 🛠️ Descrição Geral

MULTIDDOSTOOL é uma **ferramenta avançada de simulação de ataques DDoS** (negação de serviço distribuída) projetada para **testes de segurança e análise de resistência** de redes, servidores e dispositivos IoT. Desenvolvida em **C++**, oferece diversos métodos de ataque, permitindo que administradores de sistemas avaliem a robustez de suas infraestruturas.

🔹 **Inundação de pacotes** (UDP, TCP, ICMP, SYN, ACK, RST, FIN)
🔹 **Ataques amplificados** (DNS, NTP, SNMP, SSDP, Memcached, Chargen, QOTD)
🔹 **Exploração de protocolos específicos**
🔹 **Simulação de botnets** (Mirai, Hoax)
🔹 **Ataques a websites e APIs** (HTTP Flood, Slowloris, RUDY, Pingback XML-RPC)
🔹 **Ataques a redes locais e dispositivos IoT**

## ⚡ Funcionalidades Principais

### 🔹 **Ataques a IPs**
- **Inundação UDP, TCP, ICMP, SYN, ACK, RST, FIN**: Envio massivo de pacotes para sobrecarga do alvo.
- **Ping da Morte**: Explora pacotes ICMP grandes para causar instabilidade.
- **Ataque Smurf**: Amplifica tráfego via redes de broadcast.
- **Inundação por Fragmentação**: Sobrecarrega processamento do alvo com pacotes fragmentados.
- **Ataque LAND**: Spoofa o IP de origem para criar loops no alvo.
- **Falsificação ARP**: Confunde redes com pacotes ARP falsos.

### 🔹 **Ataques Amplificados**
- **DNS, NTP, SNMP, SSDP, Memcached, Chargen, QOTD**: Utiliza servidores vulneráveis para multiplicar o tráfego ao alvo.

### 🔹 **Simulação de Botnets**
- **Mirai, Hoax**: Simula ataques coordenados por múltiplos "bots".

### 🔹 **Ataques a Websites**
- **Inundação HTTP**: Envio massivo de requisições GET/POST para sobrecarga.
- **Slowloris**: Mantém conexões abertas lentamente para esgotar os recursos do servidor.
- **Ataque RUDY**: Envia POSTs lentos com payloads grandes para esgotar conexões.
- **Pingback XML-RPC**: Explora amplificação via XML-RPC.
- **Cookie Bomb**: Envia cookies enormes para travar o servidor.

### 🔹 **Ataques a Redes Locais**
- **Inundação MAC**: Preenche tabelas MAC com endereços falsos.
- **Ataque Broadcast DHCP**: Sobrecarrega redes com solicitações DHCP.
- **MAC Spoofing**: Falsifica endereços MAC para enganar switches.

### 🔹 **Ataques a Dispositivos IoT**
- **Inundação Telnet, MQTT, CoAP**: Ataca portas específicas de dispositivos IoT.
- **Jammer de Caixas de Som**: Envia pacotes UDP para interferir em dispositivos de áudio.

### 🔹 **Ferramentas de Detecção**
- **Detecção de IP Real**: Resolve URLs para obter o IP real.
- **Verificação Cloudflare**: Identifica proteção Cloudflare no alvo.
- **Geolocalização**: Obtém uma localização aproximada do IP.

## 🔥 Características Adicionais
- **🛡️ Uso de Proxies**: Permite ataques via proxies pré-configurados.
- **🔀 IPs Falsos**: Gera IPs de origem aleatórios para spoofing.
- **📜 Log de Atividades**: Registra pacotes enviados, falhas e bytes transmitidos.
- **🎨 Interface Colorida**: Usa cores RGB no console para melhor visualização.
- **🚀 Alta Performance**: Suporta múltiplas threads para ataques simultâneos (limite de **5000 threads**).

## 🖥️ Uso
A ferramenta inicia com um **menu principal intuitivo**, permitindo escolher entre ataques a:

✅ IPs
✅ Websites
✅ Redes Locais
✅ Dispositivos IoT
✅ Ferramentas de Detecção

Cada opção leva a submenus detalhados, onde o usuário configura:

- **IP/URL alvo**
- **Porta**
- **Duração do ataque**
- **Número de threads**

🛑 **O usuário pode optar por utilizar proxies ou IPs falsos para maior anonimato.**

## ⚖️ Aviso Legal
🔴 **O MULTIDDOSTOOL é destinado exclusivamente para testes de segurança em ambientes autorizados.**

Os desenvolvedores **não se responsabilizam** pelo uso indevido da ferramenta. Utilize apenas **em ambientes nos quais você tenha permissão explícita** para testar vulnerabilidades.

---
⚠️ **Uso indevido desta ferramenta pode resultar em sanções legais.** Certifique-se de **seguir as diretrizes éticas e legais** antes de utilizá-la!
