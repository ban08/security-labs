JetBrains TeamCity ---> CVE-2023-42793

Identificação:
- Bypass na autenticação com RCE no JetBrains TeamCity, antes da versão 2023.05.4.
- Afeta servidores CI/CD em Windows/Linux; TeamCity Cloud não foi afetado. 
- Falha nos RequestInterceptors permite ignorar auth em caminhos */RPC2. 
- Risco supply-chain: código, chaves, agentes e artefactos comprometidos.

Catalogação:
- Descoberto pela SonarSource; divulgado/corrigida em setembro de 2023 pela JetBrains.
- Severidade CVSS ~9.8 (CRITICAL), adicionada ao catalogo KEV da CISA.
- Exploração ativa observada na prática por vários autores; 
- Atribuída a APT29/SVR e grupos norte-coreanos em campanhas direcionadas.

Exploit:
- Pedido HTTP a caminhos que terminam em /RPC2 contornava auth no TeamCity. 
- Criação de um token admin via POST /app/rest/users/id:1/tokens/RPC2 ( Não necessitando de login).
- Com o token o atacante usa REST/UI para acionar build steps, carregar plugins maliciosos ou plantar webshells.
- Automação ---> templates Nuclei e PoCs publicas permitem exploração end-to-end;

Ataques:
- APT29/SVR explorou em larga escala instâncias expostas, ganhando acesso a repositórios, pipelines e credenciais. 
- Diamond Sleet / Onyx Sleet (RP norte-coreanas) visaram propriedade intelectual e backdoors via pipelines. 
- Intrusões persistiram em hosts não atualizados, afetando maioritariamente developers e empresas tecnológicas.
- Impacto: acesso a repositórios, segredos, agentes e ainda potencial de envenenar artefatos distribuidos.

Correção/Contramedidas: 
- Atualizar para 2023.05.4+ ou aplicar “security patch plugin”; Reiniciar e validar versão.
- Restringe por VPN/IP allow-list; SSO/MFA obrigatório para admins.
- Revogar/rodar tokens, palavras-passes e chaves; remover plugins suspeitos; aplicar RBAC minimo; 
- Verficação ---> 401/403 em */RPC2, Nuclei sem findigs, hunting de tokens id:1 e alterações de pipelines.