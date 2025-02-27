Nome: MULTIDDOSTOOL

Desenvolvido por: Seven & xAI

LEMBRANDO NAO DOU SUPORTE ISSO E UM PROTOTIPO NAO ME RESPONSABILIZO PELO USO ERRADO DA FERRAMENTA

Descricao Geral:

MULTIDDOSTOOL e uma ferramenta avancada de simulacao de ataques de negacao de servico (DDoS) projetada para testes de seguranca e analise de resistencia de redes, servidores e dispositivos IoT. Desenvolvida em C++, a ferramenta oferece uma ampla variedade de metodos de ataque, incluindo inundacao de pacotes, ataques amplificados, exploracao de protocolos especificos e simulacao de botnets. Seu objetivo e permitir que administradores de sistemas avaliem a robustez de suas infraestruturas contra diferentes tipos de ataques DDoS.

Funcionalidades Principais:

Ataques a IPs:
Inundacao UDP, TCP, ICMP, SYN, ACK, RST, FIN: Envia pacotes massivos para sobrecarregar o alvo.
Ping da Morte: Explora pacotes ICMP grandes para causar instabilidade.
Ataque Smurf: Usa redes de broadcast para amplificar trafego.
Inundacao por Fragmentacao: Sobrecarrega o processamento com pacotes fragmentados.
Ataque LAND: Spoofa o IP de origem para criar loops no alvo.
Falsificacao ARP: Confunde redes com pacotes ARP falsos.
Amplificacao (DNS, NTP, SNMP, SSDP, Memcached, Chargen, QOTD): Usa servidores vulneraveis para multiplicar o trafego.
Simulacao de Botnets (Mirai, Hoax): Simula ataques coordenados por multiplos "bots".
Inundacao Multi-Alvo: Ataca varios IPs simultaneamente.
Ataques a Websites:
Inundacao HTTP: Envia requisicoes GET/POST massivas.
Slowloris: Mantem conexoes abertas lentamente para esgotar slots do servidor.
Ataque RUDY: Envia POSTs lentos com payloads grandes.
Inundacao WebSocket e SSL/TLS: Sobrecarrega conexoes especificas.
Ataques de Leitura/Post Lento: Ocupa recursos com operacoes prolongadas.
Pingback XML-RPC: Explora amplificacao via XML-RPC.
Inundacao HEAD, OPTIONS, TRACE: Usa metodos HTTP secundarios para sobrecarga.
Ataque Cookie Bomb: Envia cookies grandes para travar o servidor.
Ataque Range Header: Usa cabecalhos Range maliciosos.
GET/POST Flood: Envia requisicoes com queries ou formularios extensos.
Ataques a Redes Locais:
Inundacao MAC: Enche tabelas MAC com enderecos falsos.
Ataque Broadcast DHCP: Sobrecarrega redes com solicitacoes DHCP.
MAC Spoofing: Falsifica enderecos MAC para confundir switches.
Inundacao ARP: Satura redes com pacotes ARP falsos.
Ataques a Dispositivos IoT:
Inundacao Telnet, MQTT, CoAP: Ataca portas especificas de dispositivos IoT.
Inundacao SSDP IoT e UPnP: Explora protocolos comuns em IoT.
Jammer de Caixas de Som: Envia pacotes UDP para interferir em dispositivos de audio.
Ferramentas de Deteccao:
Deteccao de IP Real: Resolve URLs para IPs reais.
Verificacao Cloudflare: Identifica protecao Cloudflare no alvo.
Geolocalizacao: Fornece localizacao simulada do IP com link para Google Maps.
Caracteristicas Adicionais:

Uso de Proxies: Permite ataques via proxies pre-configurados.
IPs Falsos: Gera IPs de origem aleatorios para spoofing.
Log de Atividades: Registra pacotes enviados, falhas e bytes em arquivo.
Interface Colorida: Usa cores RGB no console para mensagens informativas (verde para sucesso, vermelho para alertas).
Modularidade: Suporta multiplas threads para ataques simultaneos, com limite de 5000 threads.
Uso:

A ferramenta inicia com um menu principal simplificado, permitindo escolher entre ataques a IPs, websites, redes locais, dispositivos IoT ou ferramentas de deteccao. Cada opcao leva a submenus com tipos de ataque especificos, solicitando configuracoes como IP/URL alvo, porta, duracao e numero de threads. O usuario pode optar por usar proxies ou IPs falsos para maior anonimato.

Aviso:

MULTIDDOSTOOL e destinada exclusivamente para testes de seguranca em ambientes autorizados. O uso indevido contra sistemas sem permissao e ilegal e eticamente inaceitavel. Os desenvolvedores nao se responsabilizam por misuse da ferramenta.
