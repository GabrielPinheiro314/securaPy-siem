# SecuraPy - SIEM Simplificado

## Descrição
Projeto Final da disciplina Coding for Security.
O SecuraPy é um SIEM (Security Information and Event Management) simplificado para coletar, analisar e correlacionar eventos de segurança em tempo real.

## Estrutura
- `main.py`: Ponto de entrada do sistema.
- `coletor.py`: Leitura e parsing de logs.
- `regras.py`: Motor de regras de detecção.
- `detector.py`: (Stub) Detecção avançada e correlação.
- `servidor_alertas.py` / `cliente_alertas.py`: (Stub) Sistema de alertas em tempo real.
- `enriquecimento.py`: (Stub) Consultas a APIs de Threat Intelligence.
- `relatorios.py`: (Stub) Geração de relatórios.

## Execução
Para executar o sistema básico de coleta e análise baseada em regras:
```bash
python main.py
```
