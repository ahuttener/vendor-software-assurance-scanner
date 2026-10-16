# Guia em português — Vendor Software Assurance Scanner (VSAS)

> Documento interno (não é para o README público). Explica o projeto em linguagem simples e
> prepara você para defendê-lo numa entrevista de GRC.

## 1. O que é, em uma frase

É um **auditor automático de software de fornecedor**: pega o programa compilado que um
fornecedor te entrega (sem o código-fonte) e, **só lendo o arquivo**, confere se o que está
dentro dele bate com o que o fornecedor jurou no questionário de segurança.

**Analogia:** o fornecedor te manda a "ficha técnica" dizendo que o produto não tem sal,
usa embalagem lacrada e ingredientes dentro da validade. A ferramenta é o inspetor que abre
a lata e confere item por item — sem cozinhar nada, só inspecionando.

## 2. Por que isso é GRC (e não "hacking")

É a peça de **TPRM — Third-Party Risk Management** (gestão de risco de terceiros). Toda
norma exige que você avalie seus fornecedores:
- **SOC 2** CC9.2, **GDPR** Art. 28, **HIPAA** §164.308(b)(1), **PCI DSS** 12.8,
  **DORA** Art. 28-30, **ISO 27001** A.5.19-A.5.23.

A ferramenta transforma essa avaliação em **evidência auditável**: cada achado aponta onde
está no arquivo (offset) e a qual controle de qual norma pertence. Outro auditor consegue
refazer. É o oposto de ofensivo — é defensivo, só leitura, não executa nem ataca nada.

## 3. Como rodar

```bash
pip install -r requirements.txt
bash samples/build.sh                      # compila o alvo de teste (inerte)

python -m vsas samples/bin/demo_vendor_app \
    --attestation samples/vendor_attestation.yaml \
    --out vsas-report
# abra vsas-report/report.html
```

Autoteste (prova que os detectores pegam o que deviam):
```bash
python -m vsas samples/bin/demo_vendor_app --answer-key samples/answer_key.yaml
# SELF-TEST: PASS (8 expectations met)
```

## 4. O que cada teste faz

| Teste | O que procura |
|---|---|
| `hardcoded-secret` | senha/chave/token embutido no binário |
| `weak-crypto` | cripto fraca (MD5, SHA-1, DES, RC4, ECB) |
| `plaintext-transport` | conexão sem TLS (`http://`) |
| `personal-data-marker` | marcadores de dado pessoal / de saúde (revisão de privacidade) |
| `data-egress-endpoint` | para onde o software manda dados (revisão de transferência) |
| `outdated-component` | biblioteca velha / fim de vida → vira SBOM |
| `missing-hardening` | binário sem NX/PIE/RELRO/canário |
| `unsigned-binary` | sem assinatura digital → integridade não verificável |
| `attestation-gap` | o fornecedor jurou X, mas a evidência mostra o contrário |

## 5. A história de 2 minutos (para a entrevista)

> "Montei uma ferramenta de TPRM que fecha um buraco comum: a gente confia no questionário
> que o fornecedor preenche, mas ninguém confere o binário. A minha ferramenta lê o
> executável — estático, só leitura — e procura segredo embutido, cripto fraca, conexão sem
> TLS, dado pessoal, biblioteca fim de vida e falta de hardening. Aí ela **reconcilia** isso
> com o que o fornecedor afirmou: se ele disse 'tudo criptografado em trânsito' e eu acho um
> `http://`, isso vira um *attestation gap*, uma bandeira vermelha de due diligence. Cada
> achado sai mapeado para SOC 2, NIST, GDPR, HIPAA e mais, com risco pontuado pelo NIST
> 800-30, e o relatório termina num veredito: aprovar, aprovar com condições ou recusar.
> Pra provar que funciona, compilei um binário-alvo com falhas plantadas e um gabarito, e a
> ferramenta tem um autoteste que valida os detectores."

**Se perguntarem "mas e a parte de engenharia reversa / isso não é ofensivo?":**
> "É puramente defensivo e estático. Eu não quebro proteção, não descompilo para burlar
> nada — leio cabeçalhos, strings e metadados, que é o que o DMCA permite e o que a Diretiva
> de Software da UE (2009/24/CE) cobre. É o mesmo princípio de ferramentas como o MobSF ou o
> Syft."

## 6. Antes e depois (mostra que o veredito tem lógica)

Mesmo binário, dois builds:
- **Vulnerável:** 11 FAIL / 2 MANUAL → **Reject**.
- **Corrigido** (TLS, sem segredo, cripto moderna, hardening): 1 FAIL / 1 MANUAL / 6 PASS →
  **Approve with conditions**.

Isso mostra que a ferramenta não "reclama de tudo" — ela responde à correção.

## 7. Glossário rápido

- **TPRM**: gestão de risco de fornecedores.
- **SBOM**: lista de ingredientes de software (quais bibliotecas, quais versões).
- **Attestation**: o que o fornecedor declara no questionário.
- **Hardening**: proteções de compilação (NX, PIE, RELRO, canário) que dificultam exploração.
- **OSCAL**: formato do NIST para resultados de auditoria legíveis por máquina.
- **NIST 800-30**: método de pontuar risco = probabilidade × impacto.

## 8. Transparência (importante dizer na entrevista)

- É um projeto **educacional / de portfólio**. Os resultados automáticos são **indícios**,
  não um certificado — todo achado precisa ser confirmado por um analista.
- O único binário analisado é o **fixture inerte** que vem no repo, compilado de um fonte
  que eu escrevi, com valores **sintéticos e não funcionais** (as chaves de exemplo públicas
  da AWS, domínios `.test`). Não ataca nada e não tem software de terceiros.
- Foi construído com **assistência de IA** — o mesmo que você já fez no repo anterior; se
  perguntarem, assuma com naturalidade e mostre que você entende cada parte (este guia é
  justamente para isso).
