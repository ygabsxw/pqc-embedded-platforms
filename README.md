# Criptografia Pós-Quântica em Ambientes Simulados de IoT: Um Estudo Comparativo de Desempenho
 
Este projeto realiza uma avaliação experimental comparativa de algoritmos criptográficos tradicionais, leves e pós-quânticos em um ecossistema físico de IoT. O objetivo é mensurar o custo computacional (tempo de execução, uso de memória) e o impacto na rede (latência, overhead de pacotes, throughput) de quatro algoritmos — AES-256-GCM, Ascon-128a, ML-KEM-768 e Classic McEliece-348864 — em dispositivos com diferentes capacidades: um ESP32 (microcontrolador), um Raspberry Pi 3 Model B (nó de borda) e um servidor local (gateway).
 
Os resultados mostram que a adoção de criptografia pós-quântica em IoT é tecnicamente viável, mas exige escolhas criteriosas. O ML-KEM-768 se destacou como a alternativa pós-quântica mais adequada para dispositivos restritos, enquanto o Classic McEliece revelou limitações severas de desempenho, memória e volume de dados transmitidos.
 
---
 
## Alunos integrantes da equipe
 
- Arthur Costa Serra Negra
- Gabriel Costa Vianna
- Gabriel Diniz Reis Vianna
- Matheus Silva Coxir
- Pedro Henrique Felix dos Santos
## Professores responsáveis
 
- Matheus Alcântara Souza
- Rafael Henriques Nogueira Diniz
---
 
## Algoritmos avaliados
 
| Algoritmo | Categoria | Função |
|---|---|---|
| AES-256-GCM | Simétrico tradicional | Cifragem autenticada (linha de base) |
| Ascon-128a | Criptografia leve | Cifragem autenticada para dispositivos restritos |
| ML-KEM-768 | Pós-quântico (KEM) | Encapsulamento de chave (ex-Kyber, padrão NIST) |
| Classic McEliece-348864 | Pós-quântico (KEM) | Encapsulamento de chave (caso extremo) |
 
---
 
## Arquitetura do ambiente de testes
 
```
[ESP32]         [Raspberry Pi 3B]
  |  (fechadura inteligente)   |  (câmera / nó de borda)
  |                            |
  +----------+  TCP/IP  +------+
             |          |
          [Servidor local / PC]
          (gateway: recebe, decifra e registra métricas)
```
 
---
 
## Principais resultados
 
- **ML-KEM-768**: ciclo KEM completo em ~36 ms no ESP32 e ~1,1 ms no Raspberry Pi — viável para IoT. Transmite 2.272 B por handshake.
- **Classic McEliece**: ~2,54 s por ciclo no Raspberry Pi, variabilidade >50% e 261 KB por handshake. Não executa no ESP32 por falta de memória.
- **Ascon-128a**: mais eficiente que AES para cifragem isolada no ESP32 (2,15× mais rápido) e para grandes volumes de dados no Raspberry Pi (3,86× mais rápido em 64 KB).
- **AES-256-GCM**: latência fim-a-fim inferior ao Ascon no ESP32 via Wi-Fi, com amplo suporte industrial e aceleração nativa em ARM Cortex-A53.
**Recomendação**: arquitetura híbrida com ML-KEM-768 para o handshake inicial + AES-256-GCM ou Ascon-128a para cifrar o canal de dados.
 
---
