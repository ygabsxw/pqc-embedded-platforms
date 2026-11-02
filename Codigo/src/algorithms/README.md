# Guia de Testes dos Algoritmos Criptográficos

Este diretório contém as implementações dos algoritmos criptográficos do projeto. Cada algoritmo é organizado em seu próprio subdiretório para manter o projeto limpo.

O processo de compilação é totalmente automatizado por um `Makefile` genérico.

## 🚀 Executando os Testes

1.  Abrir o terminal e navegar até este diretório (`Codigo/src/algorithms/`).
2.  Executar o comando `make` para compilar todos os algoritmos encontrados nos subdiretórios:
   ```bash
   make
   ```
3.  O `Makefile` irá criar um diretório `bin/` e colocar todos os executáveis de teste lá. Para executá-los, utilizar:
    - **Linux / macOS / WSL**: `./bin/test_aes256.out`
    - **Windows (CMD / PowerShell)**: `.\bin\test_aes256.out`
4.  Para limpar todos os arquivos compilados, executar:
   ```bash
   make clean
   ```

## 🛠️ Adicionando um Novo Algoritmo

A estrutura do `Makefile` é **genérica**, o que significa que **não é necessário editá-lo** ao adicionar um novo algoritmo. Basta seguir a estrutura de diretórios:

1.  **Criar um novo diretório**: O nome do diretório deve ser o nome do algoritmo. Exemplo: `aes256`.
2.  **Adicionar os arquivos**: Dentro do novo diretório (`aes256/`), colocar os arquivos de implementação e teste, seguindo o padrão de nomenclatura:
    - `aes256.c` (implementação)
    - `aes256.h` (cabeçalho)
    - `test_aes256.c` (código de teste com a função `main`)
3.  **Compilar**: Rodar `make` na raiz do diretório `algorithms/`. O `Makefile` encontrará o novo diretório e compilará `test_aes256.c` e `aes256.c`, gerando o executável `bin/test_aes256.out`.

### Estrutura de arquivos esperada:
```text
algorithms/
├── Makefile            # Gerencia a compilação (não é necessário editar)
├── README.md           # Esta documentação
├── bin/                # Criado pelo 'make', contém os executáveis (ignorado pelo .gitignore)
│   ├── test_aes256.out
│   └── test_kyber.out
└── aes256/
    ├── aes256.c
    ├── aes256.h
    └── test_aes256.c
```

> **Observação:** Os arquivos de saída da compilação (com extensão `.out`, `.o`, ou `.exe`) já estão sendo ignorados pelo `.gitignore` na raiz do projeto, então você não precisa se preocupar com eles "sujando" os commits!