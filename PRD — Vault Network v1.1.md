# PRD — Vault Network: Armazenamento Criptografado e Compartilhamento P2P Privado

**Versão:** 1.1 (revisão técnica da v1.0) **Data:** 25 de outubro de 2026 **Status:** Revisado; pronto para a Fase 0 (spikes de validação) **Plataformas:** Windows e Linux **Stack principal:** Tauri 2, React, TypeScript, Rust; transporte P2P a decidir na Fase 0 (libp2p ou iroh, ADR-002) **Nome provisório:** Vault Network

---

# 0. Registro de alterações (v1.0 → v1.1)

| # | Problema na v1.0 | Correção na v1.1 | Seção |
| --- | --- | --- | --- |
| 1 | Autorização de C por B sem A online não definida | Capabilities assinadas pelo owner, verificáveis offline; chave de participação por destinatário | 10.3, 12 |
| 2 | Camadas de criptografia ambíguas (container × objeto) | Modelo em dois planos: índice cifrado pelo container; blocos cifrados pela CEK do objeto | 8, 9 |
| 3 | Relay como padrão sem viabilidade (limites default do circuit relay v2: 120 s / 128 KiB; custo; ponto de observação) | Relay próprio semi-confiável com limites customizados, orçamento de banda, relay configurável por swarm; spike libp2p × iroh | 11 |
| 4 | Identidade multi-dispositivo e recuperação em aberto | Decididos: identidade por container, keyslots, recovery key | 8.6, 11.4, 23 |
| 5 | WebView como vetor de vazamento de plaintext | Decodificação em Rust, protocolo custom `no-store`, hardening da WebView, auditoria obrigatória | 7.2, 14, 15 |
| 6 | Cifra de blocos sem especificação | Construção STREAM com nonce, AAD e flag de bloco final | 8.3 |
| 7 | Hash indefinido (BLAKE3 ou SHA-256) | BLAKE3 sobre o ciphertext | 8.2, 9.4 |
| 8 | Argon2id sem parâmetros | Pisos mínimos e calibração por dispositivo | 8.2 |
| 9 | Vazamento de metadados do container | Índice cifrado, lookup por HMAC, padding, vazamento residual documentado | 9 |
| 10 | Arquivo único `.vault` com risco de corrupção e conflito com pastas sincronizadas | Container em diretório com store transacional, segmentos append-only e lock | 9.1, 9.5 |
| 11 | Segredo em URL de deep link | Segredo apenas em fragmento; nunca em path/query/log | 12.3 |
| 12 | Sem tratamento de DoS, Sybil, eclipse e seeder malicioso | Controles explícitos | 10.7, 15 |
| 13 | Sem política de abuso e responsabilidade dos operadores | Política dos serviços auxiliares | 16.4 |
| 14 | Atualização assinada sem processo | Chave offline, rotação, verificação | 15.5 |
| 15 | Tauri sem especificação de permissões | Capabilities mínimas, CSP, allowlist de comandos | 14.2 |
| 16 | MVP excessivo | MVP fatiado em M1/M2/M3 com gates | 6, 19 |
| 17 | Métricas "zero ocorrências" não verificáveis | Método de verificação por métrica | 18 |
| 18 | Inconsistência §1.1 × DA-005 | Texto unificado | 1.1, 22 |

---

# 1. Resumo executivo

## 1.1. Visão do produto

Aplicativo desktop multiplataforma que permite criar containers criptografados, organizar arquivos privados em um sistema de arquivos virtual e compartilhá-los com participantes autorizados por uma rede Peer-to-Peer.

Os containers não são montados como unidades de disco. O usuário navega e visualiza arquivos pela interface do aplicativo.

Conteúdos permanecem criptografados em repouso e em trânsito. A descriptografia ocorre somente na memória do processo Rust do aplicativo, para visualização e operações autorizadas pelo usuário.

A distribuição usa blocos criptografados por objeto. Os blocos são idênticos para todos os participantes autorizados, de modo que qualquer um deles pode servi-los sem descriptografar ou recriptografar. A disponibilidade deixa de depender do remetente original.

A plataforma minimiza dados pessoais e metadados de rede: não há catálogo público de arquivos, seeders ou atividades.

## 1.2. Proposta de valor

**"Seus arquivos. Seu controle. Sua rede."**

- Armazenamento criptografado controlado pelo usuário.
- Pastas virtuais e visualização sem exportação por padrão.
- Compartilhamento por convite ou link.
- Download de um mesmo arquivo a partir de múltiplos seeders.
- Minimização da exposição de IPs e identidade.
- Conteúdo hospedado pelos participantes, não por um provedor de nuvem.

## 1.3. Limites declarados

O produto não oculta arquivos do kernel do sistema operacional, não protege contra sistema comprometido e não garante anonimato absoluto. O modo privado reduz a exposição de IP entre peers, mas **o relay observa os IPs de ambos os lados** e é um componente semi-confiável (seção 11.3).

---

# 2. Problema a resolver

- **P-01 — Exposição de arquivos armazenados:** arquivos comuns são acessíveis a processos com permissão suficiente.
- **P-02 — Dependência de provedores centralizados:** arquivos compartilhados precisam ser enviados a servidores externos.
- **P-03 — Exposição de participantes:** a descoberta P2P convencional expõe IPs e identificadores dos seeders.
- **P-04 — Duplicação desnecessária:** o mesmo arquivo é baixado da origem mesmo existindo cópias na rede.
- **P-05 — Experiência fragmentada:** criptografia, organização, visualização e compartilhamento exigem aplicativos distintos.

---

# 3. Objetivos

## 3.1. Principais

- **OBJ-01 Confidencialidade:** arquivos criptografados em repouso e em trânsito contra quem não possui autorização criptográfica.
- **OBJ-02 Controle local:** gestão em containers próprios.
- **OBJ-03 Distribuição descentralizada:** transferência P2P com múltiplas fontes.
- **OBJ-04 Privacidade dos participantes:** minimizar coleta, publicação e correlação de identidades e IPs.
- **OBJ-05 Disponibilidade distribuída:** arquivo disponível com o remetente offline, desde que seeders autorizados estejam online. Depende de seeders com container desbloqueado (seção 10.7).
- **OBJ-06 Experiência integrada:** criar, navegar, visualizar e compartilhar em uma interface.
- **OBJ-07 Segurança verificável:** controles testáveis, auditoria e tratamento consistente de falhas.

## 3.2. Secundários

- Extensão futura para outras plataformas.
- Compartilhamento de pastas (snapshots).
- Retomada de downloads interrompidos.
- Controle de banda e privacidade.
- Arquitetura preparada para sincronização futura.

## 3.3. Não objetivos da primeira versão

- Ocultar o aplicativo do sistema operacional.
- Proteger contra kernel comprometido.
- Impedir que destinatários autorizados copiem conteúdos.
- Edição colaborativa simultânea.
- Armazenamento em nuvem ilimitado ou disponibilidade garantida sem seeders.
- Criptomoeda, mineração ou incentivos financeiros.
- Substituir antivírus, firewall ou criptografia de disco.
- Suporte a múltiplos dispositivos para a mesma identidade.

---

# 4. Público-alvo

- **Usuário individual:** documentos e imagens privados. Necessita simplicidade, controle e recuperação segura.
- **Usuário que compartilha:** envia arquivos a destinatários específicos sem hospedar em servidores convencionais. Necessita convites, acompanhamento e controle de permissões.
- **Grupos privados:** distribuem arquivos entre vários computadores. Necessitam eficiência e disponibilidade.
- **Usuário avançado:** deseja controle de rede e transparência sobre garantias de privacidade.

---

# 5. Princípios de produto

- **Security by Design:** proteção definida desde formatos, protocolos e fluxos.
- **Privacy by Default:** mínimo de exposição de identidade e atividade.
- **Local First:** arquivos sob controle do usuário, sem armazenamento centralizado de conteúdo.
- **Zero Plaintext Persistence by Default:** o aplicativo não grava conteúdo descriptografado em temporários, caches ou pastas externas. A garantia vale para o comportamento controlado pelo aplicativo, incluindo o cache da WebView (seção 14.3). Não cobre swap, hibernação ou memória do processo.
- **Least Privilege:** cada componente com as permissões estritamente necessárias.
- **Explicit User Control:** exportação, conexão direta, compartilhamento público e exclusão definitiva são transparentes e controláveis.
- **Offline First:** gerenciamento local funciona sem internet.
- **Fail Securely:** falhas de conexão, criptografia, autenticação ou armazenamento nunca expõem dados nem relaxam a política de privacidade.

---

# 6. Escopo e priorização

O MVP é fatiado em três marcos, cada um com gate de aceitação próprio. Nenhum marco começa sem o gate do anterior.

| Recurso | M1 Local | M2 A→B | M3 A,B→C | Completo |
| --- | --- | --- | --- | --- |
| Containers criptografados, keyslots e recovery key | Sim | Sim | Sim | Sim |
| Pastas e arquivos virtuais, importação | Sim | Sim | Sim | Sim |
| Visualização interna de imagens (PNG, JPEG, WebP) | Sim | Sim | Sim | Sim |
| Outros formatos de visualização | Não | Não | Não | Expandida |
| Identidade criptográfica e contatos | Não | Sim | Sim | Sim |
| Convite privado com capability | Não | Sim | Sim | Sim |
| Transferência entre dois usuários via relay | Não | Sim | Sim | Sim |
| Descoberta privada (rendezvous) | Não | Sim | Sim | Sim |
| Múltiplos seeders e semeadura | Não | Não | Sim | Sim |
| Retomada de downloads | Não | Sim | Sim | Sim |
| Links transferíveis | Não | Não | Não | Sim |
| Snapshots de pastas | Não | Não | Não | Sim |
| Semeadura com container bloqueado (seed-only) | Não | Não | Não | Opcional |
| Rede anônima Tor/I2P, backup distribuído, mobile | Não | Não | Não | Futuro |

**Gates:**

- **M1:** CT-001, CT-002, CT-003, CT-010 aprovados em Windows e Linux; auditoria de vazamento da WebView (spike S3) aprovada.
- **M2:** CT-004, CT-007, CT-008, CT-009 aprovados; autorização por capability verificada por testes adversariais.
- **M3:** CT-005, CT-006 aprovados em rede real, com origem offline e C recebendo blocos de A e B.

---

# 7. Requisitos funcionais

## 7.1. Containers criptografados

### RF-001 — Criar container

Campos: nome de apresentação, local, senha, confirmação, keyfile opcional, bloqueio automático opcional.

O aplicativo gera os materiais criptográficos (seção 8) e **apresenta a recovery key uma única vez, exigindo confirmação de que foi guardada** antes de concluir a criação.

Critérios de aceitação:

- Container criado em Windows e Linux.
- Nenhum nome de arquivo ou nome interno em texto puro no disco.
- Conteúdo irrecuperável sem a chave correta.
- Senha nunca gravada em claro.
- Parâmetros Argon2id respeitam o piso da seção 8.2.

### RF-002 — Desbloquear container

Abertura mediante senha (e keyfile, se configurado) ou recovery key. O aplicativo valida o keyslot antes de disponibilizar qualquer estrutura. Falhas não expõem dados internos nem distinguem causa (senha incorreta × arquivo corrompido) além do necessário. Tentativas repetidas aplicam atraso crescente.

### RF-003 — Bloquear container

Bloqueio manual e por inatividade. O bloqueio:

- Invalida sessões e encerra visualizações.
- Descarta chaves e buffers controlados pelo aplicativo (`zeroize`).
- Interrompe transferências que exijam descriptografia.
- **Interrompe a semeadura**, pois seeding exige container desbloqueado na v1 (seção 10.7).

### RF-004 — Múltiplos containers

Vários containers locais, com senhas, keyslots e identidades independentes.

### RF-005 — Integridade e recuperação

Escrita transacional conforme seção 9.5. Falha em importação, exclusão, compactação ou atualização do índice não corrompe dados previamente confirmados. Ao abrir, o aplicativo detecta e reverte escritas incompletas.

### RF-012 — Troca de senha e recovery key

A troca de senha recria o keyslot de senha sem recriptografar conteúdo. O usuário pode regenerar a recovery key, invalidando a anterior. A perda simultânea de senha e recovery key torna os dados permanentemente inacessíveis, e a interface informa isso.

### RF-013 — Exclusividade de acesso

Um container só pode ser aberto por uma instância por vez (lock, seção 9.5). Tentativa concorrente é recusada com mensagem clara.

## 7.2. Sistema de arquivos virtual

### RF-006 — Navegação por pastas

Criar, renomear, mover, copiar e excluir pastas e arquivos; navegar por caminhos; seleção múltipla; pesquisa por nome em container desbloqueado.

### RF-007 — Importar arquivos

O processo:

1. Recebe a seleção do usuário.
2. Lê o arquivo de origem por streaming.
3. Divide em blocos e criptografa progressivamente (seção 8.3).
4. Persiste os blocos e executa `fsync`.
5. Confirma a transação no índice somente após a persistência durável.

O arquivo de origem não é excluído automaticamente. Nenhum plaintext temporário é gravado.

### RF-008 — Renomear e mover

Alteram somente o índice cifrado, sem recriptografar blocos.

### RF-009 — Excluir arquivos

Remove as referências lógicas e marca blocos sem referência para coleta. O aplicativo não promete apagamento físico irrecuperável em SSDs.

### RF-010 — Visualização interna

O MVP visualiza PNG, JPEG e WebP sem exportação. Fluxo obrigatório:

1. O núcleo Rust descriptografa os blocos em memória.
2. O núcleo Rust decodifica a imagem (decoders sob fuzzing) e entrega ao frontend apenas pixels ou imagem re-codificada, por protocolo custom com `Cache-Control: no-store`.
3. O frontend nunca recebe o arquivo original, nem cria Blob URL persistente, nem acessa caminho de disco.

Arquivos não suportados oferecem apenas exportação explícita, sem execução automática. SVG, HTML e executáveis nunca são interpretados.

### RF-011 — Exportação

Exportação somente por ação explícita. A interface informa que o arquivo exportado perde a proteção do container.

---

# 8. Criptografia e gerenciamento de chaves

## 8.1. Hierarquia de chaves

| Chave | Origem | Função | Armazenamento |
| --- | --- | --- | --- |
| Unlock Key (UK) | Argon2id(senha \[+ hash do keyfile\]) | Abre o keyslot de senha | Nunca persistida |
| Recovery Key (RK) | 256 bits aleatórios, exibida uma vez (Base32 com checksum) | Abre o keyslot de recuperação | Com o usuário |
| Container Master Key (CMK) | 256 bits aleatórios | Raiz das chaves do container | Embrulhada em cada keyslot |
| `index-key`, `keystore-key`, `identity-wrap-key` | HKDF-SHA-256(CMK, label de domínio) | Cifram índice, cofre de CEKs e identidade; HMAC de lookup | Derivadas em memória |
| Content Encryption Key (CEK) | 256 bits aleatórios por objeto | Cifra blocos e manifest do objeto | No cofre de CEKs, cifrado por `keystore-key` |
| Identity Key | Ed25519 (assinatura) + X25519 (HPKE), uma por container | Assinar capabilities, receber convites | Cifrada por `identity-wrap-key` |
| Participation Key | Ed25519 gerada pelo owner, uma por (swarm, destinatário) | Identidade de rede no swarm | Dentro do convite; no cofre do destinatário |

Chaves nunca são reutilizadas entre funções. Todo uso de HKDF leva label de domínio versionado (ex.: `vault/v1/index-key`).

**Keyslots:** o `header.bin` contém um ou mais slots, cada um com a CMK cifrada (XChaCha20-Poly1305) sob a UK ou sob a RK. Trocar a senha recria o slot de senha sem tocar nos dados.

## 8.2. Algoritmos (fixos na versão 1 do formato)

| Função | Algoritmo | Observações |
| --- | --- | --- |
| KDF de senha | Argon2id | Piso: m ≥ 64 MiB, t ≥ 3, p = 1. Calibrar no dispositivo para 0,5–1 s. Parâmetros gravados no header e autenticados como AAD do keyslot; abrir com parâmetros abaixo do piso é recusado |
| AEAD | XChaCha20-Poly1305 | Único AEAD na v1. AES-256-GCM removido da v1 para evitar negociação e downgrade; a versão do formato permite adicioná-lo depois |
| Derivação | HKDF-SHA-256 | Com labels de domínio |
| Distribuição de CEK | HPKE (RFC 9180), DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 | Envelope assinado pelo owner |
| Assinaturas | Ed25519 | Manifests, capabilities, revogações |
| Hash e IDs | BLAKE3 | Calculado sobre o **ciphertext** |
| Segredos em memória | `zeroize`, tipos `Secret` | Ver 8.7 |

Bibliotecas com versão fixada e `cargo-deny`/`cargo-audit` no CI. Qualquer escolha adicional exige ADR e revisão criptográfica.

## 8.3. Cifra de blocos (construção STREAM)

O objeto é dividido em blocos de `B` bytes de plaintext (seção 9.3). Cada bloco `i`:

```text
nonce_i = nonce_prefix(15 bytes, aleatório por objeto) || i (u64 LE) || last_flag (1 byte)   # 24 bytes
AAD_i   = "vault/v1/block" || object_id || i (u64) || last_flag || plaintext_len (u32)
ct_i    = XChaCha20-Poly1305(CEK, nonce_i, plaintext_i, AAD_i)
block_id_i = BLAKE3(ct_i)          # ct_i inclui a tag
```

- A CEK é única por objeto e `i` é único por objeto, logo nenhum par (chave, nonce) se repete.
- `i` e `object_id` no AAD impedem reordenação e troca de blocos entre objetos.
- `last_flag` no bloco final impede truncamento silencioso.
- Uma nova versão do arquivo é um **novo objeto com nova CEK**. Nunca se reaproveita (CEK, `i`).

## 8.4. Manifest

O manifest é cifrado com a CEK (AAD `"vault/v1/manifest" || object_id`) e contém: nome, tipo, tamanho, `block_size`, `nonce_prefix`, lista ordenada de `block_id` e `integrity_root = BLAKE3(block_ids || tamanho || block_size)`.

- `manifest_id = BLAKE3(manifest_ciphertext)`.
- O owner assina `manifest_id || swarm_id || object_id` (Ed25519). O destinatário verifica contra a `owner_pubkey` recebida no convite.
- Seeders servem blocos por `block_id` e não precisam do manifest em claro. O manifest cifrado é distribuído como um bloco especial, identificado por `manifest_id`.

## 8.5. Sem deduplicação global

Não há criptografia determinística baseada no conteúdo. Como cada objeto tem CEK própria, o mesmo arquivo importado duas vezes gera blocos distintos. A identidade de blocos é compartilhada apenas dentro de um swarm autorizado.

## 8.6. Recuperação

- O keyslot de recuperação, protegido pela RK, é criado junto com o container.
- O usuário pode exportar um **backup do header** (keyslots e identidade cifrada). Sem senha ou RK, o backup é inútil.
- A recuperação da identidade após perda do computador exige o backup do header e a RK ou a senha.
- Rotação da CMK recriptografa apenas índice e cofre de CEKs, nunca os blocos.
- Perda de senha e RK implica perda permanente dos dados.

## 8.7. Higiene de memória

- Tipos `Secret` sem `Debug`, `Clone` implícito ou `Serialize`; `zeroize` no `Drop`.
- Chaves em páginas bloqueadas (`mlock` / `VirtualLock`) quando possível.
- Core dumps desativados (`prctl(PR_SET_DUMPABLE, 0)` no Linux; exclusão de relatórios do WER no Windows).
- Swap e hibernação não são controlados pelo app. A limitação é documentada ao usuário (seção 16.3).

---

# 9. Arquitetura de armazenamento

## 9.1. Container físico (ADR-001)

O container é um **diretório opaco** com extensão `.vault`. A decisão substitui o arquivo único por três motivos: transações e compactação por segmento, sem reescrever um arquivo gigante; menor risco de corrupção; lock explícito contra pastas sincronizadas. Um empacotamento em arquivo único para transporte (`.vaultpack`) fica para versão posterior.

```text
meu.vault/
  header.bin          # versão do formato, parâmetros KDF, keyslots (autenticado)
  index/              # store transacional embarcado (candidato: redb); valores cifrados com index-key
  seg/00000001.seg    # segmentos append-only de blocos cifrados, sem cabeçalho identificável
  lock                # lock advisory + identificador da instância
```

Nomes de arquivo são numerados e nunca derivados de IDs ou nomes de usuário.

## 9.2. Dois planos

- **Plano de índice** (protegido pela CMK): árvore do VFS, manifests locais, envelopes e cofre de CEKs, estado de transferências, e o mapa `HMAC(index-key, block_id) → (segmento, offset, tamanho)`.
- **Plano de blocos** (protegido pela CEK do objeto): ciphertext nos segmentos.

Consequências:

- Um segmento copiado não revela nomes nem estrutura, e confirmar a presença de um bloco conhecido exige a `index-key`.
- Os blocos são idênticos entre participantes (DA-006). A confidencialidade deles depende da CEK, que só existe cifrada pela CMK ou em envelopes HPKE.
- Seeding precisa do índice. Por isso exige container desbloqueado na v1.

## 9.3. Blocos

Tamanho padrão: 1 MiB, parametrizado no formato (256 KiB a 4 MiB). O valor final sai de benchmark na Fase 0 (memória, latência, overhead, throughput por relay). O bloco final é preenchido até múltiplo de 64 KiB dentro do plaintext autenticado.

**Vazamento residual documentado:** tamanho aproximado dos objetos, número total de blocos, tamanho dos segmentos e timestamps do sistema de arquivos. Padding não elimina isso.

## 9.4. Integridade

- Cada bloco recebido tem `BLAKE3(ct)` comparado ao `block_id` esperado do manifest antes de qualquer persistência.
- O `integrity_root` do manifest vincula a sequência de blocos à versão do arquivo.
- A assinatura do owner vincula manifest a swarm e objeto.
- Blocos inválidos são descartados e a fonte penalizada.

## 9.5. Transações, recuperação e lock

**Escrita:**

1. Anexar blocos ao segmento ativo e executar `fsync`.
2. Confirmar transação no índice com as referências (commit durável).
3. Em criação de segmento, `fsync` do diretório.

O índice nunca referencia bloco não durável. Blocos sem referência são órfãos coletados por GC.

**Abertura:** valida header e keyslot, reaplica o log do store e trunca cauda parcial de segmento.

**Compactação:** copia blocos vivos para novo segmento, atualiza referências em uma transação e só então remove o segmento antigo.

**Lock:** lock advisory do SO (`flock` / `LockFileEx`) mais arquivo `lock` com ID de instância. Se o diretório estiver em pasta sincronizada conhecida (Dropbox, OneDrive etc.), o aplicativo avisa sobre risco de corrupção.

**Testes obrigatórios:** injeção de falha em cada ponto de `fsync`, `kill -9` durante importação, GC e compactação, e fuzzing de `header.bin`, índice e segmentos.

---

# 10. Rede P2P

## 10.1. Visão geral

O motor de transferência, em Rust e independente da interface, cuida de: identificar objetos, localizar fontes autorizadas, negociar conexões, solicitar blocos, validar integridade, retomar transferências, semear blocos e controlar banda.

## 10.2. Transporte (ADR-002, decisão na Fase 0)

O protocolo de aplicação (`vault-protocol`) é independente do transporte. Candidatos:

- **rust-libp2p:** QUIC, Noise, circuit relay v2, rendezvous.
- **iroh:** QUIC, relay, iroh-blobs com verificação BLAKE3 e download multi-provider.

Critérios do spike S1:

- Throughput real via relay com limites customizados.
- Controle de identidade e chaves por swarm.
- Possibilidade de desligar hole punching e descoberta local.
- Autorização e quotas no relay.
- Maturidade, auditoria e esforço de integração.

Independentemente da escolha: sem DHT pública global, sem mDNS, sem anúncio de endereços observados.

## 10.3. Autorização de acesso

Nenhuma resposta além de `HELLO` é enviada antes da validação de uma **Capability**:

```text
Capability {
  version, swarm_id, object_id (ou "*" no swarm),
  subject_pubkey,        # Participation Key do destinatário
  perms,                 # download | seed | delegate
  not_before, expires,
  epoch,                 # época de revogação
  owner_sig              # Ed25519 do owner sobre os campos acima
}
```

O seeder valida: assinatura contra `owner_pubkey` do swarm, janela de validade, `epoch` ≥ época revogada conhecida, permissão suficiente, e posse da chave do sujeito (desafio-resposta no handshake). Isso funciona **sem o owner online**, o que sustenta CT-006.

```text
HELLO(version, capability, challenge_response)
BLOCK_BITMAP(object_id, bitmap)         # não confiável; ver 10.8
REQUEST_BLOCKS(object_id, [block_id])   # lote limitado
BLOCK(block_id, bytes)
HAVE(object_id, [block_id])
CANCEL(request_id)
REVOKE_NOTICE(swarm_id, epoch, owner_sig)
ERROR(code)
```

Todas as mensagens são versionadas, com limites explícitos de tamanho e validação estrita. Erro de autorização resulta em encerramento da conexão (fail closed).

## 10.4. Download multiponto

1. Obter e verificar o manifest.
2. Descobrir fontes (seção 11).
3. Consultar bitmaps de blocos.
4. Distribuir requisições entre fontes.
5. Verificar cada bloco (9.4) antes de persistir.
6. Persistir, atualizar progresso e tornar o bloco elegível à semeadura conforme a política local.

## 10.5. Agendamento

Critérios: disponibilidade, velocidade e latência observadas, confiabilidade, limites de banda e raridade (rarest-first com priorização adaptativa). Requisições redundantes só no fim do download (endgame).

## 10.6. Retomada

O progresso é mantido no índice. Somente blocos verificados e confirmados em transação contam como concluídos. Retomada após reinicialização não repete blocos confirmados.

## 10.7. Semeadura

- Na v1, **seeding exige container desbloqueado**. Isso limita OBJ-05: um objeto só está disponível enquanto ao menos um seeder tiver o container aberto e o app em execução.
- Modo opcional **seed-only** (pós-MVP): chave de seeding separada, guardada no cofre do SO (DPAPI / Secret Service), com índice reduzido contendo apenas `block_id → localização` dos objetos marcados. Ativação explícita, com aviso de que o índice reduzido fica acessível a processos do usuário.
- Controles: habilitar/desabilitar, limite de upload, conexões máximas, redes limitadas. Desativar a semeadura não exclui arquivos.

## 10.8. Resistência a abuso

- Timeout de handshake (padrão 5 s), limite de handshakes pendentes e de conexões por peer e por IP.
- Limite de requisições simultâneas, de bytes em voo e de taxa por peer.
- Bitmaps são tratados como não confiáveis. Fonte que anuncia e não entrega, ou entrega bloco inválido, perde pontuação e é banida temporariamente.
- Sybil/eclipse: só conectam participantes com Capability válida do owner do swarm, o que limita o atacante a quem recebeu convite.
- Descartar mensagens malformadas sem alocar memória proporcional ao campo declarado.

---

# 11. Descoberta privada e privacidade dos participantes

## 11.1. Princípio

Não existe catálogo público global de usuários, arquivos ou seeders. A descoberta ocorre dentro de escopos de compartilhamento autorizados.

## 11.2. Swarms privados

- `swarm_id`: 256 bits aleatórios, gerado pelo owner, nunca derivado de nome ou conteúdo.
- `discovery_id = HKDF(swarm_id, "vault/v1/discovery")`: único valor que o serviço de rendezvous vê.
- Registros assinados pela Participation Key, com TTL ≤ 15 min e renovação ativa.
- A consulta exige conhecer o `discovery_id` (não enumerável). Rate limit por IP e por `discovery_id`; teto de registros por `discovery_id`.
- O rendezvous não conhece a `owner_pubkey` e não valida Capabilities. Registros falsos podem poluir a lista, mas a autorização real ocorre no seeder (10.3). O risco residual é de disponibilidade, mitigado pelos limites acima e pela penalização de fontes.
- No modo privado, o endpoint registrado é o **endereço de circuito do relay**, nunca o IP direto.

## 11.3. Relay e rendezvous: componentes semi-confiáveis

O relay e o rendezvous não armazenam arquivos nem chaves de conteúdo. Sem mecanismos adicionais, observam IPs, Peer IDs, volume e horários. Em modo privado o **relay conhece os IPs de ambos os lados** da transferência.

Requisitos de relay:

- Limites de duração e bytes por circuito configurados para transferência real. Os padrões do circuit relay v2 (120 s e 128 KiB) não servem.
- Quotas por IP e por peer, e orçamento de banda do operador definido antes do lançamento. No modo privado, todo byte transferido atravessa o relay duas vezes (entrada e saída), portanto custo e capacidade são requisitos de projeto (seção 21).
- Convite pode apontar para **relay próprio do owner ou do grupo** (`relay_hints`), removendo a dependência do operador padrão.
- Retenção de logs conforme 16.4.

## 11.4. Identidades de rede (decisão)

- A Identity Key é **por container**, nunca exposta na rede.
- Cada participante usa uma **Participation Key distinta por swarm**, gerada pelo owner e entregue no convite. O Peer ID de rede deriva dela. Não há correlação por chave entre swarms.
- O owner conhece o mapeamento destinatário → Participation Key. Isso é aceito: o owner já é parte confiável do swarm.
- Multi-dispositivo não faz parte da v1. A extensão prevista usa certificados de dispositivo assinados pela Identity Key.

## 11.5. Privacidade de IP (modo privado, padrão)

- Transferências somente por relay.
- Hole punching e conexões diretas desativados, sem fallback automático para direto.
- Sem mDNS/descoberta local; sem escuta em endereços públicos; protocolo de identificação não publica endereços observados.
- IPs de terceiros não aparecem na interface.
- Se o relay estiver indisponível, a transferência **falha**; não há degradação para conexão direta (fail closed).
- **Modo direto:** exige autorização explícita por swarm, com aviso de que IPs serão expostos aos participantes.

## 11.6. Rede anônima

Tor Onion Services ou I2P ficam como extensão futura, com política fail-closed. O termo "anônimo" não será usado como garantia absoluta contra análise de tráfego.

---

# 12. Compartilhamento

## 12.1. Contatos e verificação

O **cartão de contato** contém as chaves públicas de identidade (Ed25519 e X25519) e um nome sugerido. Para impedir substituição por intermediário, o aplicativo exibe um **fingerprint curto** (verificação por canal externo). Convites só são emitidos para contatos; contatos não verificados exibem aviso.

## 12.2. Convite privado

O owner seleciona arquivo ou pasta e um contato. O aplicativo:

1. Cria (ou reutiliza) o swarm do objeto.
2. Gera uma Participation Key para o destinatário.
3. Emite uma Capability assinada para essa chave, com validade e permissões.
4. Monta o convite e o cifra via HPKE para a chave X25519 do contato:

```text
Invitation {
  object_id, manifest_id, swarm_id, owner_pubkey,
  cek,
  participation_secret, capability,
  relay_hints, permissions
}
```

O convite é um blob cifrado e assinado, entregue por qualquer canal (arquivo, texto). Somente o destinatário o abre. Não há etapa online com o owner depois da emissão, e a Capability permite que o destinatário baixe e semeie sem o owner.

## 12.3. Link transferível (pós-MVP)

O link carrega o convite como credencial ao portador:

```text
vault://join#<payload_base64url>
https://vault.exemplo.com/join#<payload_base64url>
```

- O segredo fica **somente no fragmento**. Nunca em path ou query, nunca em logs, nunca em argumentos de linha de comando.
- A página `https` é estática; o fragmento não é enviado ao servidor.
- O aplicativo remove o fragmento da interface e do histórico após a leitura.
- Esquemas de URL customizados podem ser interceptados por outros aplicativos do usuário. O app oferece colar o link manualmente como alternativa.
- O link concede acesso a qualquer portador até expirar ou ser revogado. A interface deixa isso explícito ao criar.

## 12.4. Fluxo de referência: três usuários

1. A importa um arquivo; blocos são cifrados e persistidos.
2. A cria o swarm e envia convites a B e C (Participation Keys e Capabilities distintas).
3. B abre o convite, baixa o manifest e os blocos de A via relay e verifica cada bloco.
4. B habilita a semeadura (container desbloqueado).
5. C abre o convite e descobre A e B pelo `discovery_id`.
6. Cada fonte valida a Capability de C offline e só então responde.
7. C baixa blocos de A e B em paralelo, verifica e persiste.
8. C visualiza o conteúdo após desbloquear o container, usando a CEK do convite.
9. Com A offline e B online, C ainda conclui o download.

## 12.5. Compartilhamento de pastas

Snapshots criptografados descrevem a estrutura de uma pasta. Cada arquivo é um objeto com CEK própria; o snapshot é um objeto-manifest que referencia os objetos filhos e entrega suas CEKs no mesmo envelope. O destinatário integra a estrutura ao seu container.

## 12.6. Permissões

| Permissão | Significado | Garantia |
| --- | --- | --- |
| `download` | Obter blocos e CEK | Aplicada criptograficamente (Capability e CEK) |
| `seed` | Servir blocos a outros participantes | Aplicada por Capability; o seeder só serve a quem tem Capability válida |
| `delegate` | Emitir convites a terceiros | **Declarativa**: quem tem a CEK pode enviá-la a outros. O owner não consegue impedí-lo criptograficamente |
| `publish` | Publicar novas versões | Exige assinatura de chave autorizada pelo owner |

O produto não impede que um destinatário copie ou redistribua o conteúdo após obtê-lo.

## 12.7. Revogação

- Capabilities têm validade curta por padrão (7 dias) e o app do destinatário as renova junto ao owner quando online. Se o owner permanecer offline, o acesso expira.
- O owner pode publicar uma **revogação assinada** (`epoch++`), distribuída pelo rendezvous e por `REVOKE_NOTICE` entre seeders. A propagação é best-effort.
- A revogação impede **novas** conexões e downloads com a Capability revogada. Não apaga CEKs, conteúdos nem cópias já obtidas, e a interface explica isso.
- Para impedir a leitura futura de uma nova versão, o owner publica novo objeto com nova CEK a partir de um novo swarm apenas para os destinatários mantidos.

---

# 13. Interface e experiência do usuário

## 13.1. Direção de design

Experiência de gerenciador de arquivos moderno, sem exigir conhecimento de criptografia ou P2P para operações comuns: minimalista, temas claro e escuro, acessibilidade por teclado, estados vazios e erros compreensíveis, animações discretas.

## 13.2. Navegação

```text
Início               containers recentes, atividade, convites recebidos
Meus Containers      arquivos, pastas, pesquisa, compartilhar
Compartilhamentos    enviados, recebidos, permissões, contatos
Transferências       downloads, uploads, em pausa, concluídos
Configurações        segurança, privacidade, rede, armazenamento, atualizações
```

## 13.3. Explorador

Grade e lista, breadcrumbs, ordenação, menus de contexto, seleção múltipla, arrastar e soltar, pesquisa local, miniaturas geradas em memória (não persistidas em claro) e indicador de disponibilidade local.

## 13.4. Transferências

Exibem nome (quando autorizado), progresso, volume, velocidade, estado, número aproximado de fontes ativas, tempo estimado e ações de pausar, retomar e cancelar. IPs e identificadores persistentes de terceiros não aparecem na interface padrão.

## 13.5. Máquinas de estado

```text
Container: LOCKED -> UNLOCKING -> UNLOCKED -> LOCKING -> LOCKED ; qualquer -> ERROR
Transfer:  CREATED -> DISCOVERING -> CONNECTING -> DOWNLOADING <-> PAUSED
           DOWNLOADING -> VERIFYING -> COMPLETED ; qualquer -> FAILED | CANCELLED
Sharing:   DRAFT -> ACTIVE -> EXPIRED | REVOKED
```

Cada transição possui condições, efeitos e tratamento de erro definidos no documento de arquitetura (TDD). Falhas em `CONNECTING` no modo privado levam a `FAILED`, nunca a conexão direta.

---

# 14. Arquitetura técnica

## 14.1. Organização

```text
vault-network/
  apps/desktop/{src,src-tauri}/
  crates/
    vault-core/       tipos, erros, estado
    vault-crypto/     keyslots, AEAD, HKDF, HPKE, assinaturas
    vault-storage/    segmentos, índice transacional, GC, lock
    vault-vfs/        sistema de arquivos virtual
    vault-identity/   identidade, contatos, Participation Keys
    vault-sharing/    manifests, convites, Capabilities, revogação
    vault-protocol/   mensagens e máquina de estados (independente do transporte)
    vault-p2p/        adaptador de transporte (libp2p ou iroh)
  services/{rendezvous,relay}/
  tests/{integration,interoperability,security,recovery}/
  docs/{adr,tdd}/
```

## 14.2. Frontend e Tauri

- Frontend: React e TypeScript. Renderiza interface, navegação e eventos; solicita operações ao backend.
- **Capabilities do Tauri:** conceder apenas os comandos do aplicativo. Sem plugin de sistema de arquivos exposto ao frontend, sem shell, sem HTTP genérico.
- **CSP:** `default-src 'self'`; sem conteúdo remoto; sem `eval`; `img-src` limitado ao protocolo custom do aplicativo.
- **IPC:** comandos tipados, argumentos validados, autorização por sessão do container. O frontend nunca recebe chaves, CEKs ou plaintext de arquivos.
- **Deep link:** parser estrito; o payload nunca é passado a shell ou registrado em log.

## 14.3. Endurecimento da WebView

- Diretório de dados da WebView isolado, com cache desativado e limpo no encerramento.
- Imagens chegam por protocolo custom com `Cache-Control: no-store`; sem Blob URLs persistentes, sem `localStorage`/IndexedDB para conteúdos.
- Verificar ativamente cache de disco, histórico, crash dumps e memória da WebView2 (Windows) e WebKitGTK (Linux).
- Linux: avaliar o isolamento real da WebKitGTK; se insuficiente, a decodificação ocorre em processo auxiliar restrito (seccomp/Landlock). Pós-MVP no Windows: processo auxiliar com job object/AppContainer.

## 14.4. Backend Rust

Criptografia, chaves, armazenamento, VFS, permissões, sessões, rede, integridade e recuperação. O núcleo (`vault-core`, `-crypto`, `-storage`, `-vfs`) não depende de Tauri nem do transporte P2P, permitindo testes diretos e ferramentas de manutenção.

---

# 15. Segurança e modelo de ameaças

## 15.1. Ameaças e defesas

| Ameaça | Defesa |
| --- | --- |
| Roubo do `.vault` bloqueado | AEAD, Argon2id com piso, keyslots, índice cifrado |
| Interceptação em trânsito | Canal autenticado e cifrado; blocos já cifrados pela CEK |
| Seeder malicioso | Verificação de `block_id`, penalização, banimento temporário |
| Manipulação de manifests | Assinatura do owner; `integrity_root` |
| Peer sem convite | Capability obrigatória antes de qualquer resposta |
| Enumeração de compartilhamentos | `discovery_id` não enumerável; rate limit |
| Rastreamento entre swarms | Participation Key por swarm |
| Exposição de IP a peers | Relay-only e fail closed no modo privado |
| Observação pelo relay/rendezvous | Documentada; relay próprio configurável por swarm |
| Substituição de contato (MITM) | Fingerprint verificado por canal externo |
| Link roubado | Validade curta, escopo, revogação de acessos futuros |
| Queda durante escrita | Transações, `fsync`, recuperação na abertura |
| DoS e Sybil | Limites e quotas (10.8); Capability válida para conectar |
| Arquivo malicioso | Decoders sob fuzzing, formatos restritos |
| Atualização adulterada | Assinatura verificada, chave offline (15.5) |

## 15.2. Ameaças não solucionáveis

Sem garantia contra kernel comprometido, administrador com controle total, malware com acesso à memória, captura de tela, destinatário autorizado de má-fé ou componentes de terceiros fora do controle do app. Sem anonimato perante observadores globais de rede.

## 15.3. Visualizadores

Somente os formatos suportados (PNG, JPEG, WebP no MVP), decodificados em Rust, com limites de dimensão e memória e fuzzing contínuo. SVG, HTML e executáveis nunca são interpretados.

## 15.4. Testes de segurança obrigatórios

- Corrupção de header, índice e segmentos; falhas de autenticação; downgrade de parâmetros KDF.
- Fuzzing: parsers de formato, mensagens do protocolo, decoders de imagem.
- Replay e reordenação de mensagens e blocos; troca de blocos entre objetos.
- Capability expirada, revogada, de outro swarm, com assinatura inválida ou sem posse da chave.
- Downgrade de privacidade: tentativa de conexão direta no modo privado, com relay indisponível.
- Vazamento de segredos em logs, crash dumps e cache da WebView.
- Auditoria de dependências em cada release.
- Revisão criptográfica externa antes de qualquer distribuição pública ampla.

## 15.5. Atualizações

Atualização via updater do Tauri com assinatura verificada. A chave privada de assinatura fica offline (HSM ou máquina isolada). Há procedimento documentado de rotação e de revogação de chave, e builds com dependências fixadas.

---

# 16. Privacidade, dados e operação

## 16.1. Coleta

O aplicativo não coleta nomes de arquivos, caminhos, conteúdos, senhas, chaves, histórico de visualização ou listas persistentes de participação em swarms. Telemetria mínima e opt-in.

## 16.2. Logs

Somente identificadores operacionais. Nunca: senhas, chaves, CEKs, segredos de convites ou links, plaintext, nomes privados de arquivos. Tipos `Secret` impedem log acidental.

## 16.3. Transparência ao usuário

A interface explica: o que é armazenado localmente; o que trafega pela rede; o que relay e rendezvous observam; quando IPs são expostos; o efeito da exportação; os limites da revogação; e que swap e hibernação podem gravar memória do processo.

## 16.4. Operação de relay e rendezvous

- Registros de descoberta expiram automaticamente.
- Logs operacionais com IP: retenção máxima inicial de 7 dias, sujeita a revisão jurídica (LGPD).
- Os operadores não acessam conteúdo nem chaves. Como o tráfego é opaco, a política de abuso se baseia em quotas, bloqueio por IP/peer e cooperação limitada à informação técnica que o serviço de fato possui.
- Termos de uso e política de privacidade definidos antes do lançamento público dos serviços.

---

# 17. Requisitos não funcionais

**Compatibilidade**

- **RNF-001:** Windows e distribuições Linux conforme matriz de suporte formal.
- **RNF-002:** formato de container interoperável entre plataformas.
- **RNF-003:** comportamento criptográfico idêntico entre plataformas, validado por vetores de teste compartilhados.

**Performance**

- **RNF-004:** importação e exportação por streaming.
- **RNF-005:** renomear e mover sem recriptografia.
- **RNF-006:** downloads concorrentes de múltiplas fontes.
- **RNF-007:** interface não bloqueia durante operações longas.
- **RNF-008:** arquivos de pelo menos 1 GiB nos testes do MVP, com pico de memória limitado e independente do tamanho do arquivo (limite numérico definido após benchmark da Fase 0).

**Confiabilidade**

- **RNF-009:** operação interrompida nunca corrompe dados confirmados.
- **RNF-010:** blocos validados antes da confirmação.
- **RNF-011:** downloads retomáveis após reinicialização.
- **RNF-012:** backup de header e recuperação de container.

**Segurança**

- **RNF-013:** conteúdos e metadados privados nunca persistidos em claro pelo fluxo normal.
- **RNF-014:** modo privado impede conexões diretas, inclusive em falha de relay.
- **RNF-015:** erros de autorização resultam em negação.
- **RNF-016:** atualizações com autenticidade verificável.

**Acessibilidade**

- **RNF-017:** operações essenciais por teclado.
- **RNF-018:** progresso, erro e confirmação não dependem somente de cor.

---

# 18. Indicadores de sucesso e método de verificação

| Indicador | Meta | Como é verificado |
| --- | --- | --- |
| Importação íntegra | 100% | Suite automatizada com hash do plaintext antes e depois, em ambas as plataformas |
| Blocos aceitos íntegros | 100% | Teste com bloco adulterado em cada posição: todos rejeitados |
| Retomada sem repetição | Nenhum bloco confirmado rebaixado | Interrupção em pontos aleatórios; contagem de requisições por `block_id` |
| Download com dois seeders | Funcional em rede real | Teste E2E com três máquinas e verificação de bytes recebidos por fonte |
| Queda simulada | Nenhuma perda de dados confirmados | Injeção de falha em todos os pontos de `fsync` (9.5) |
| Exportação não solicitada | Zero | Monitoramento de FS e processos (inotify/ETW) durante a suíte E2E |
| Plaintext em disco | Zero | Varredura do FS, diretório da WebView e dumps por marcador conhecido no arquivo de teste |
| Conexão direta no modo privado | Zero | Captura de tráfego (pcap) em E2E, incluindo relay derrubado |
| Segredos em logs | Zero | Varredura de logs por padrões de chaves e CEKs; injeção de marcadores |
| Multiplataforma | Windows e Linux | CI com matriz e vetores de teste compartilhados |

Benchmarks de velocidade, CPU, memória e latência são definidos após os spikes da Fase 0.

---

# 19. Roadmap

## Fase 0 — Spikes e decisões (gate obrigatório)

Spikes descartáveis, executados antes do TDD:

| Spike | Objetivo | Critério de aprovação |
| --- | --- | --- |
| S1 | Transferência A→B→C via relay real, comparando libp2p e iroh | Throughput sustentado com limites customizados; autorização por Capability implementável; hole punching desativável; decisão ADR-002 |
| S2 | Container: importação de 1 GiB com `kill -9` em todos os pontos | Estado consistente em 100% das execuções; escolha do store (redb ou alternativa) |
| S3 | Auditoria de vazamento da WebView ao exibir imagem | Nenhum plaintext em disco, cache ou dump; define processo auxiliar ou não |
| S4 | Benchmark de tamanho de bloco (256 KiB a 4 MiB) | Define `B` padrão e meta de RNF-008 |
| S5 | Vetores de teste de criptografia entre Windows e Linux | Resultados idênticos |

**Entregáveis:** modelo de ameaças formal; ADR-001 (formato) e ADR-002 (transporte) fechados; TDD com contratos entre crates, formato binário e máquinas de estado.

## Fase 1 — Núcleo criptográfico e containers (M1, parte 1)

Keyslots, recovery key, armazenamento em segmentos, índice cifrado, importação e exportação, VFS, recuperação de falhas, testes de integridade.

## Fase 2 — Aplicativo desktop (M1, parte 2)

Interface React/Tauri, explorador, visualizador de imagens por protocolo seguro, bloqueio por inatividade, configurações e erros. **Gate M1.**

## Fase 3 — Identidade e transferência A→B (M2)

Identidade, contatos com fingerprint, convites HPKE, Capabilities, protocolo de blocos, descoberta privada, relay obrigatório, retomada. **Gate M2.**

## Fase 4 — Distribuição multiponto (M3)

Múltiplos seeders, agendamento, semeadura, controle de banda, revogação e renovação de Capabilities. **Gate M3.**

## Fase 5 — Privacidade e compartilhamento avançado

Links transferíveis, snapshots de pastas, seed-only, relay próprio por grupo, testes de correlação de tráfego e auditoria externa.

## Fase 6 — Evolução

Sincronização de pastas, histórico de versões, backup distribuído de blocos cifrados, rede anônima, streaming de vídeo, mobile, multi-dispositivo.

---

# 20. Casos de teste de ponta a ponta

| ID | Cenário | Resultado esperado |
| --- | --- | --- |
| CT-001 | Importar PNG | Armazenado cifrado, referência no VFS, sem cópia temporária em claro |
| CT-002 | Ler fisicamente um container bloqueado | Nenhum arquivo ou nome recuperável sem chaves |
| CT-003 | Abrir imagem no container desbloqueado | Exibida no app; nenhuma exportação nem plaintext no disco ou cache da WebView |
| CT-004 | A compartilha com B | B conclui o download e possui o objeto cifrado no próprio container |
| CT-005 | A e B online, C inicia download | C recebe blocos de A e B, verifica e reconstrói o arquivo |
| CT-006 | A offline, B semeando, C com convite válido | Download concluído a partir de B; Capability validada sem o owner |
| CT-007 | Conexão interrompida no meio do download | Blocos verificados persistem; retomada sem repetição |
| CT-008 | Modo privado, transferência P2P | Tráfego somente via relay; zero conexões diretas, inclusive com relay indisponível (transferência falha) |
| CT-009 | Bloco adulterado | Rejeitado; transferência não confirmada; fonte penalizada |
| CT-010 | Encerramento abrupto durante escrita | Estado consistente com dados anteriores preservados |
| CT-011 | Capability expirada, revogada, de outro swarm ou sem posse da chave | Conexão encerrada sem resposta de dados |
| CT-012 | Bloco trocado de posição ou de objeto | Falha de autenticação AEAD; rejeitado |
| CT-013 | Parâmetros Argon2id abaixo do piso no header | Abertura recusada |
| CT-014 | Contato com fingerprint não verificado | Aviso exibido antes de emitir convite |
| CT-015 | Dois processos abrem o mesmo container | Segundo recusado pelo lock |

---

# 21. Dependências e riscos

| Risco | Impacto | Mitigação |
| --- | --- | --- |
| Bugs criptográficos | Crítico | Bibliotecas auditadas, vetores de teste, revisão externa |
| Corrupção de container | Crítico | Transações, injeção de falhas, backup de header |
| Perda de chaves | Crítico | Recovery key obrigatória na criação |
| Vazamento de plaintext pela WebView | Alto | S3, protocolo `no-store`, processo auxiliar se necessário |
| Custo e capacidade do relay | Alto | Orçamento de banda, quotas, relay próprio por swarm |
| Relay como ponto de observação | Alto | Documentação, retenção mínima, relay do próprio grupo |
| Disponibilidade dependente de seeders desbloqueados | Alto | Indicadores de disponibilidade; seed-only e armazenamento auxiliar futuros |
| Escolha de transporte incorreta | Médio | `vault-protocol` independente; S1 antes do TDD |
| Links e convites repassados indevidamente | Alto | Validade curta, avisos, revogação de acessos futuros |
| Escopo do MVP | Alto | Marcos M1/M2/M3 com gates |
| Complexidade multiplataforma | Médio | CI em Windows e Linux, vetores compartilhados |

O MVP não é considerado pronto para uso sensível apenas porque criptografia e transferência funcionam. A validação do modelo de ameaças e a revisão externa são obrigatórias para distribuição pública.

---

# 22. Decisões arquiteturais

- **DA-001:** Tauri 2 para a aplicação desktop.
- **DA-002:** toda lógica sensível em Rust; o frontend nunca recebe chaves nem plaintext de arquivos.
- **DA-003:** VFS independente do frontend.
- **DA-004:** containers locais em diretório opaco, sem montagem como disco (ADR-001).
- **DA-005 (revisada):** dois planos de criptografia. O índice é cifrado pelas chaves do container; os blocos são cifrados pela CEK do objeto, com AEAD autenticando posição, objeto e bloco final.
- **DA-006:** blocos cifrados idênticos entre os participantes autorizados do swarm.
- **DA-007 (revisada):** transporte decidido na Fase 0 (ADR-002); protocolo de aplicação próprio e independente do transporte.
- **DA-008:** sem anúncio de arquivos privados em DHT pública global.
- **DA-009:** descoberta por `discovery_id` opaco; autorização por Capability no seeder, antes de qualquer dado.
- **DA-010:** relay como padrão do modo privado, com fail closed.
- **DA-011:** conexão direta somente por escolha explícita por swarm.
- **DA-012:** semear blocos é separado de descriptografar (permissões `seed` e `download`).
- **DA-013:** snapshots antes de sincronização bidirecional.
- **DA-014:** formato versionado, com algoritmos fixos por versão e preparado para migração.
- **DA-015:** segurança como requisito de aceitação, não como melhoria posterior.
- **DA-016:** Capabilities assinadas pelo owner, verificáveis offline, com validade curta e época de revogação.
- **DA-017:** Participation Key por swarm e por destinatário, gerada pelo owner.
- **DA-018:** identidade por container; multi-dispositivo fora da v1.
- **DA-019:** keyslots com recovery key obrigatória.
- **DA-020:** decodificação de mídia sempre em Rust; o frontend recebe apenas pixels ou imagem re-codificada.

---

# 23. Questões da v1.0: situação

| # | Questão | Situação na v1.1 |
| --- | --- | --- |
| 1 | Formato físico | **Decidido:** diretório `.vault` com store transacional e segmentos (ADR-001). Validação do store no S2 |
| 2 | Links transferíveis no MVP | **Decidido:** fora do MVP; entram na Fase 5 como credencial ao portador |
| 3 | Semeadura com container bloqueado | **Decidido:** não na v1; modo seed-only opcional na Fase 5 |
| 4 | Disponibilidade offline | **Adiado:** armazenamento auxiliar cifrado na Fase 6; relay/"super-seeder" do próprio grupo é suportado desde a Fase 5 |
| 5 | Identidade | **Decidido:** por container; multi-dispositivo via certificados na Fase 6 |
| 6 | Recuperação | **Decidido:** keyslots, recovery key e backup do header |
| 7 | Arquivos grandes | **Pendente:** metas numéricas para dezenas ou centenas de GiB após S2 e S4 |
| 8 | Privacidade de rede | **Decidido:** relays próprios, com relay configurável por swarm. Rede anônima só na Fase 6 |

**Questões novas em aberto:**

1. O relay exigirá autenticação de cliente (token do operador)? Aumenta o controle de abuso e reduz a privacidade, pois associa instalações ao operador.
2. Qual a validade padrão de Capabilities e como será a renovação quando o owner permanece offline por longos períodos?
3. Meta de custo de banda por GiB transferido via relay e quem o financia.

Todas as decisões serão registradas em ADRs, com justificativa e alternativas rejeitadas.

---

# 24. Definição de pronto do MVP

O MVP está concluído quando os gates M1, M2 e M3 estiverem aprovados e:

- Containers puderem ser criados, desbloqueados, bloqueados e recuperados via recovery key.
- Arquivos puderem ser importados, organizados e visualizados internamente, sem plaintext em disco (S3 e CT-003 aprovados).
- Dados e metadados privados estiverem protegidos por criptografia autenticada em repouso.
- Dois usuários compartilharem um arquivo por convite com Capability, e um terceiro baixar blocos de dois seeders, com origem offline.
- O modo privado impedir conexões diretas, inclusive com relay indisponível.
- Downloads puderem ser interrompidos e retomados.
- Windows e Linux produzirem e lerem containers compatíveis.
- Falhas de gravação não destruírem dados confirmados.
- Testes de segurança críticos (15.4) estiverem aprovados e não houver vulnerabilidades críticas conhecidas sem mitigação.
- As limitações de privacidade (relay, revogação, swap, destinatários mal-intencionados) estiverem documentadas na interface.

---

# 25. Visão de longo prazo

Evoluir para uma plataforma em que armazenamento, acesso e distribuição sejam funções independentes: possuir conteúdo sem publicá-lo, receber e semear como participante autorizado, e armazenar blocos cifrados sem possuir as chaves. Serviços intermediários facilitam descoberta e transporte sem hospedar conteúdo em claro.

**Princípio central:** o usuário controla suas chaves, arquivos, compartilhamentos e participação na rede, com garantias tecnicamente verificáveis e sem promessas de invisibilidade ou anonimato absoluto.

---

# 26. Referências técnicas

- Tauri 2: https://v2.tauri.app/
- Tauri Deep Linking: https://v2.tauri.app/plugin/deep-linking/
- libp2p: https://libp2p.io/
- libp2p Circuit Relay: https://libp2p.io/docs/circuit-relay/
- iroh: https://www.iroh.computer/
- HPKE, RFC 9180: https://www.rfc-editor.org/rfc/rfc9180
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic\_Storage\_Cheat\_Sheet.html
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password\_Storage\_Cheat\_Sheet.html

**Fim do PRD — versão 1.1**
