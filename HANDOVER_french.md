# UC16 — Tehtris EDR (connector + host posture playbook) — Paquet de transfert (déploiement air-gapped)

Généré le 2026-09-30 19:14 UTC à partir de `tehtris_edr` (environnement source : `soar8`).

Ce paquet est autonome — tout ce qu'il faut pour déployer ce cas d'usage manuellement
dans un environnement sans accès réseau vers ce dépôt ni vers `soar8`.

*(Version anglaise : `HANDOVER.md` dans ce même dossier.)*

## Contenu

| Chemin | Contenu |
|--------|---------|
| `connectors/` | Paquet(s) applicatif(s) connecteur : tehtris-v1.2.1.tgz |
| `connectors/source/` | Même(s) connecteur(s), extrait(s) — pour lecture, pas pour import |
| `playbooks/*.tgz` (PB) | tehtris_host_posture |
| `playbooks/source/` | Mêmes CF/playbooks, extraits — pour lecture, pas pour import |
| `assets/*.json` | Modèles de configuration d'assets (identifiants masqués — voir ci-dessous) |
| `docs/` | Document de plan d'implémentation, pour le contexte de conception complet |

## Ordre d'installation

1. **Installer l'application/les applications connecteur** — Apps > Install App, charger
   chaque fichier de `connectors/`.
   (`connectors/source/` est le même code extrait pour lecture — ne pas importer depuis ce
   dossier, l'interface a besoin du `.tgz`.)
2. **Configurer les assets à partir des modèles dans `assets/`** — Apps > Configure New Asset
   pour chacun. Les champs listés dans le `redacted_fields` d'un modèle sont des espaces
   réservés (`<<SET ME...>>`) — **vous devez les renseigner vous-même** ; ils n'ont jamais
   été exportés avec des valeurs utilisables. Deux raisons distinctes apparaissent dans
   cette liste, et chaque espace réservé précise laquelle s'applique :

   - **Secrets** (mots de passe, clés d'API, certificats/clés) — à reprendre depuis votre
     propre coffre-fort (vault)/CMDB. SOAR chiffre les champs de type `password` au repos,
     le processus d'export ne peut donc pas les relire sous une forme utilisable, même en
     principe.
   - **Identités et adresses** (noms d'utilisateur, client/app id, URL des points de
     terminaison) — non secrètes, mais elles appartenaient à l'environnement source et
     n'ont aucun sens ici. Saisissez les valeurs attendues par *votre* système cible.
     **Une identité doit correspondre au justificatif saisi à côté d'elle** — un vrai mot
     de passe associé à un nom d'utilisateur résiduel de l'environnement source ne
     s'authentifie auprès de rien et renvoie une erreur HTTP 401.

   **Les playbooks sont livrés pointant vers les noms d'assets ci-dessous.** Créez vos
   assets avec ces noms, ou gardez vos propres noms et redirigez les blocs d'action de
   chaque playbook vers vos assets dans le VPE, puis enregistrez : chaque playbook de ce
   paquet est conçu pour résister à un enregistrement. (Un enregistrement rend un playbook
   lancé à la main disponible sur tous les libellés de conteneur ; le réimporter rétablit
   le libellé.)

   | Nom de l'asset | Application | Utilisé par | Modèle |
   |---|---|---|---|
   | `tehtris_mock_8446` | Tehtris EDR | `tehtris_host_posture` | `assets/tehtris_mock_8446.json` |

3. **Importer les playbooks** depuis `playbooks/*.tgz`, via *Import Playbook* sur la page
   Playbooks de l'interface SOAR cible. (`playbooks/source/` est le même code extrait pour lecture —
   ne pas importer depuis ce dossier, l'interface a besoin du `.tgz`.)
4. **Rien à activer.** Tous les playbooks de ce paquet sont des playbooks d'entrée
   (`data`) — il n'y a aucun déclencheur d'automatisation à activer ni d'utilisateur
   **Run As** à définir. Vous les lancez à la main depuis un container : ouvrez le
   container, puis Playbooks > Run Playbook et choisissez celui voulu. Voir le document
   de plan d'implémentation dans `docs/`.

## Vérification

1. **Vérifiez d'abord le connecteur.** Sur l'asset Tehtris EDR, lancez *Test Connectivity*, puis `get host detail` depuis le panneau d'actions de l'asset avec le hostname d'un vrai poste. Un hostname inconnu n'est pas une erreur ici : l'action réussit avec `total_hosts` à 0 et indique que l'hôte est introuvable. Un HTTP 401 signifie une clé ou un utilisateur incorrect ; un 404 sur toutes les actions signifie que `base_url` ne se termine pas par `/api`.

2. **Lancez ensuite `tehtris_host_posture`** depuis n'importe quel container (Playbooks > Run Playbook). Il demande `hostname` (obligatoire) et `lookback_minutes` (facultatif, 60 par défaut). Il écrit une note *Tehtris Posture: <host>* : état d'isolement, OS, processus, connexions en cours, logiciels installés et événements récents. Il ne modifie rien sur le poste. Si l'agent est hors ligne, les sections en direct indiquent « not available » et le playbook réussit quand même (statut `partial`).

3. **Merci de nous transmettre** ce que la note affiche pour un poste qui porte au moins deux tags Tehtris (la ligne *Tags*), ainsi que les noms de colonnes des tableaux *Network connections* et *Installed software*. La référence de l'éditeur ne précise pas ces formats, et la gestion des tags du playbook d'isolement en dépend.

## Ce qui n'a volontairement PAS été exporté

- Les valeurs réelles des identifiants pour tout champ de configuration de type `password`
  (voir l'étape 2 ci-dessus).
- Tout ce qui n'est pas explicitement listé dans Contenu ci-dessus.
