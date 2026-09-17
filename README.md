🛡️ SecuraPy - SIEM Simplificado

Disciplina: Coding for Security  
 
📖 Visão Geral do Projeto
O **SecuraPy** é um *Security Information and Event Management* (SIEM) simplificado, desenvolvido em Python para a empresa fictícia CyberShield Ltda. O sistema foi projetado para automatizar as rotinas analíticas de um Centro de Operações de Segurança (SOC), operando de forma 100% autônoma e offline.

O sistema varre logs heterogêneos de múltiplas origens (Firewalls, Servidores Web e Autenticação), mitiga anomalias de formatação nos arquivos de entrada e cruza os dados contra um motor de regras customizáveis em JSON, gerando um panorama de ameaças priorizado por cores no terminal.

🏗️ Arquitetura de Diretórios
Para garantir a separação de responsabilidades, o projeto foi modularizado na seguinte estrutura:

- `/logs`: Repositório de dados (Data Lake). Contém os arquivos brutos (`auth.log`, `firewall.log`, `web_access.log`).
- `/config`: Repositório de negócios. Contém o arquivo `regras.json`, permitindo o ajuste de alertas sem alterar o código Python.
- `/saida`: Repositório de resultados estruturados (arquitetura reservada para expansões futuras).

🧩 Guia de Módulos
O pipeline do SecuraPy baseia-se em módulos independentes:
* **`main.py`:** Orquestrador principal que coordena a leitura e renderiza os alertas de ameaça.
* **`coletor.py`:** Motor de Parsing e Normalização. Varre textos brutos, trata erros de linhas corrompidas e os converte em dicionários padronizados.
* **`regras.py`:** Motor de Detecção. Analisa os dados coletados contra os padrões maliciosos estabelecidos e calcula a severidade (INFO à CRÍTICA).
* **Módulos Stubs (`detector`, `relatorios`, etc):** Esqueletos de código alocados para garantir a arquitetura e escalabilidade futura do MVP.

Como Executar o Projeto

1. Certifique-se de ter o Python instalado na sua máquina.
2. Abra o terminal (CMD ou PowerShell) na pasta raiz do projeto.
3. Execute o comando principal:
   ```bash
   python main.py

## 👥 Equipe de Desenvolvimento (CyberShield)
* [Gabriel](https://github.com/Gabrielpinheiro314)
* [Artur](https://github.com/Ninjinha64)
* [Vitória](https://github.com/vitoresca)
* [Pedro](https://github.com/PellKkj)
* [Yuri](https://github.com/yuripregeljhoffmann)
