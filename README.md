# Vault Network

Implementação incremental do PRD v1.1.

## Pré-requisitos

- Rust stable via `rustup` e `cargo`.
- `cargo-tauri` 2.x: `cargo install tauri-cli --version '^2'`.
- Dependências nativas do Tauri instaladas para o sistema operacional.

O frontend é vanilla HTML/CSS/JavaScript; não há `npm install`, bundler ou servidor frontend obrigatório.

## Aplicações e comandos

### Desktop principal

O desktop é o package Tauri `vault-network`, em `src-tauri/`, e usa a raiz do repositório como `frontendDist`.

Executar em desenvolvimento, com reload da janela Tauri:

```bash
cargo tauri dev
```

Compilar somente o binário Rust em debug:

```bash
cargo build -p vault-network
```

Gerar o bundle/instalador de produção para a plataforma atual:

```bash
cargo tauri build
```

Executar a interface sem Tauri, em modo demonstrativo:

```bash
python3 -m http.server 8080
```

Abra `http://127.0.0.1:8080`. Nesse modo `window.__TAURI__` não existe e as operações nativas ficam desabilitadas ou simuladas.

### Relay

O relay executável é o package `vault-relay`, que usa a biblioteca `vault-transport` e escuta, por padrão, somente em `127.0.0.1:9000`.

Executar em desenvolvimento:

```bash
cargo run -p vault-relay
```

Usar outra porta ou endereço:

```bash
cargo run -p vault-relay -- --listen 127.0.0.1:9001
```

Em um terminal de desenvolvimento, encerre de forma graciosa com `Ctrl-D`; o binário executado diretamente também trata `Ctrl-C`. O processo aceita `--help`.

Compilar o binário:

```bash
cargo build -p vault-relay
cargo build --release -p vault-relay
```

Validar a implementação e o binário do relay:

```bash
cargo test -p vault-transport
cargo check -p vault-relay
```

O binário usa os limites de `RelayConfig::default()`. Ele é um host mínimo para desenvolvimento; configuração operacional e TLS terminante ainda devem ser adicionadas antes de exposição pública.

## Deploy do relay em uma VPS

O relay usa TCP puro e não HTTP. Não o coloque atrás de um reverse proxy HTTP. Como a política atual é `application-encryption-only`, o relay não termina TLS; os clientes devem cifrar e autenticar o conteúdo na camada de aplicação.

### 1. Compilar o binário

Compile para a mesma arquitetura e sistema operacional da VPS. A forma mais simples é compilar na própria VPS:

```bash
git clone <URL_DO_REPOSITORIO> vault-network
cd vault-network
cargo build --release -p vault-relay
sudo install -m 0755 target/release/vault-relay /usr/local/bin/vault-relay
```

O artefato é `target/release/vault-relay`. Não é necessário instalar o desktop Tauri na VPS.

### 2. Criar usuário dedicado

```bash
sudo useradd --system --home-dir /var/lib/vault-relay --create-home --shell /usr/sbin/nologin vault-relay
sudo chown -R vault-relay:vault-relay /var/lib/vault-relay
```

### 3. Criar o serviço systemd

Crie `/etc/systemd/system/vault-relay.service`:

```ini
[Unit]
Description=Vault Network relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vault-relay
Group=vault-relay
WorkingDirectory=/var/lib/vault-relay
ExecStart=/usr/local/bin/vault-relay --listen 0.0.0.0:9000
Restart=on-failure
RestartSec=5
KillSignal=SIGINT
TimeoutStopSec=15
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
LimitNOFILE=4096
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Ative e inicie:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-relay
sudo systemctl status vault-relay
```

`SIGINT` é convertido pelo binário em shutdown gracioso; os circuitos ativos têm até o timeout configurado para drenar.

### 4. Liberar a porta

Libere TCP/9000 no firewall da VPS e no security group do provedor. Com UFW:

```bash
sudo ufw allow 9000/tcp
sudo ufw status
```

Verifique a escuta:

```bash
sudo ss -ltnp | grep ':9000'
```

Configure nos convites o endpoint público no formato `IP_OU_DNS:9000`. Não use `127.0.0.1:9000` fora da própria VPS.

### 5. Operação e atualização

Consultar status e logs operacionais:

```bash
sudo systemctl status vault-relay
sudo journalctl -u vault-relay -f
```

Atualizar:

```bash
cd vault-network
git pull --ff-only
cargo build --release -p vault-relay
sudo systemctl stop vault-relay
sudo install -m 0755 target/release/vault-relay /usr/local/bin/vault-relay
sudo systemctl start vault-relay
```

O serviço grava somente saída operacional no journal; não deve receber nem registrar plaintext, convites ou chaves.

## Compilar o workspace

Compilar todas as bibliotecas e o package desktop:

```bash
cargo build --workspace
```

Compilar ou testar um crate individual:

```bash
cargo build -p vault-core
cargo build -p vault-protocol
cargo build -p vault-identity
cargo build -p vault-sharing
cargo build -p vault-discovery
cargo build -p vault-transport
cargo build -p vault-transfer
cargo build -p vault-relay

cargo test --workspace
```

## Verificar o núcleo

```bash
cargo test -p vault-core
# O relay sem dependências externas também pode ser testado isoladamente:
rustc --edition=2021 --test crates/vault-transport/src/lib.rs -o /tmp/vault-transport-tests && /tmp/vault-transport-tests
```

O núcleo M1 implementa containers múltiplos abertos no shell, diretório `.vault`, keyslots de senha, recovery e keyfile opcional, Argon2id, XChaCha20-Poly1305, HKDF-SHA-256, BLAKE3, blocos STREAM, índice cifrado, pastas virtuais cifradas, importação por streaming, renomeação/movimentação lógica, exclusão lógica, checkpoints cifrados de transferência, rotação de senha, recovery key e CMK, backup/restauração do header, recuperação de cauda parcial de segmento, épocas de revogação cifradas, lock advisory, atraso progressivo de autenticação e testes de integridade. Também possui leitura e ingestão de objetos já cifrados para transferência sem plaintext. `vault-protocol` implementa capabilities Ed25519, assinatura de manifests, handshake com challenge-response, framing limitado e mensagens versionadas. `vault-identity` implementa identidade por container, cartões de contato com fingerprint e Participation Keys por swarm. `vault-sharing` implementa convites assinados pelo owner e cifrados por HPKE X25519/HKDF-SHA-256/ChaCha20-Poly1305; o comando Tauri gera o blob sem expor CEK ou Participation Key ao frontend.
`vault-discovery` implementa IDs de discovery derivados por swarm, registros de rendezvous assinados, serialização bounded, servidor HTTP mínimo de registro/consulta e cliente HTTP usado pelo shell, com TTL e capacidade limitados.
`vault-transport` fornece cliente e servidor de relay opaco com circuitos pareados, frames limitados e sem conexão direta. O relay opera explicitamente somente com criptografia de aplicação (`RELAY_SECURITY_POLICY = "application-encryption-only"`); ele não termina TLS, não deve receber plaintext e expõe apenas o tráfego TCP e metadados necessários ao encaminhamento. O servidor tem shutdown gracioso, limite de bytes por circuito, timeout de handshake, limite de handshakes pendentes, rate limit por IP e métricas atômicas; não registra payloads, convites, IDs ou chaves. `vault-protocol` inclui frame de manifest cifrado e assinado e `vault-transfer` implementa o fluxo autenticado `HELLO` → manifest → requisições de blocos → commit, sem plaintext na rede, com retomada e agendamento concorrente entre múltiplas fontes relay. Destinatários com permissão `seed` podem servir o objeto recebido usando a Capability original do owner.

Compactação transacional remove blocos órfãos e recupera journals interrompidos; checkpoints de transferência sobrevivem ao reinício do app e a rotação transacional da CMK recriptografa o índice e a identidade sem tocar nos blocos. Os gates multiplataforma do PRD ainda dependem do ambiente Tauri/OS.
