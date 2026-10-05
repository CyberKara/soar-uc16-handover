# UC16 — Tehtris EDR (connector + 5 playbooks) — Paquet de transfert (déploiement air-gapped)

Généré le 2026-10-05 20:11 UTC à partir de `tehtris_edr` (environnement source : `soar8`).

Ce paquet est autonome — tout ce qu'il faut pour déployer ce cas d'usage manuellement
dans un environnement sans accès réseau vers ce dépôt ni vers `soar8`.

*(Version anglaise : `HANDOVER.md` dans ce même dossier.)*

## Contenu

| Chemin | Contenu |
|--------|---------|
| `connectors/` | Paquet(s) applicatif(s) connecteur : tehtris-v1.2.2.tgz |
| `connectors/source/` | Même(s) connecteur(s), extrait(s) — pour lecture, pas pour import |
| `playbooks/*.tgz` (PB) | tehtris_host_posture, tehtris_host_isolate, tehtris_host_unisolate, tehtris_file_quarantine, tehtris_edr_response |
| `playbooks/source/` | Mêmes CF/playbooks, extraits — pour lecture, pas pour import |
| `assets/*.json` | Modèles de configuration d'assets (identifiants masqués — voir ci-dessous) |
| `custom_lists/*.json` | Liste(s) personnalisée(s) — les lignes définies par ce paquet, jamais les lignes de données de la source (voir la section dédiée ci-dessous) |
| `docs/` | Document de plan d'implémentation, pour le contexte de conception complet |

## [!] Mise à niveau d'une installation existante — à lire en premier

Ne concerne que le cas où cette application est déjà installée sur la cible
depuis un paquet précédent. Sur une cible vierge, passez à l'ordre
d'installation.

- **Depuis le premier paquet (connecteur v1.2.1 + `tehtris_host_posture` seul) :** installez le connecteur v1.2.2 par-dessus l'app Tehtris EDR existante, une mise à jour en place normale ; l'asset et sa clé d'API restent tels quels. La v1.2.2 ajoute le champ d'asset facultatif `timeout` (secondes par appel d'API, 1 à 300 ; vide = 30, l'ancienne valeur fixe) et relance une lecture ou une écriture de tag jusqu'à trois fois quand Tehtris répond 429, 500, 502 ou 503 ; une demande d'isolement, de levée d'isolement ou de quarantaine n'est jamais envoyée deux fois. `tehtris_host_posture` est inchangé : gardez-le, importez les quatre nouveaux playbooks et créez la liste personnalisée `tehtris_edr_settings`.

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
   | `tehtris_mock_8446` | Tehtris EDR | `tehtris_file_quarantine`, `tehtris_host_isolate`, `tehtris_host_posture`, `tehtris_host_unisolate` | `assets/tehtris_mock_8446.json` |

3. **Créer la/les liste(s) personnalisée(s)** à partir de `custom_lists/*.json` — chaque
   fichier contient le tableau `content` exact (les lignes définies par ce paquet, jamais les lignes de données de la source) à
   envoyer en POST vers `/rest/decided_list` :
   ```bash
   curl -sk -u '<user>:<password>' -X POST https://<target>:<port>/rest/decided_list \
     -H 'Content-Type: application/json' \
     -d @custom_lists/<list_name>.json
   ```
   (la structure de premier niveau du fichier est `{"name": ..., "content": [...]}` —
   correspond directement au payload REST attendu.)
4. **Importer les playbooks** depuis `playbooks/*.tgz`, via *Import Playbook* sur la page
   Playbooks de l'interface SOAR cible. (`playbooks/source/` est le même code extrait pour lecture —
   ne pas importer depuis ce dossier, l'interface a besoin du `.tgz`.)
5. **Rien à activer.** Tous les playbooks de ce paquet sont des playbooks d'entrée
   (`data`) — il n'y a aucun déclencheur d'automatisation à activer ni d'utilisateur
   **Run As** à définir. Vous les lancez à la main depuis un container : ouvrez le
   container, puis Playbooks > Run Playbook et choisissez celui voulu. Voir le document
   de plan d'implémentation dans `docs/`.

## Listes personnalisées à remplir

Réglages lus par les playbooks. Créez-les (étape ci-dessus), puis remplissez-les comme
l'indique la description de chaque liste ci-dessous, si besoin ; le cas d'usage fonctionne
avec les listes telles que livrées.

- `tehtris_edr_settings` : deux réglages lus par `tehtris_host_isolate` et `tehtris_host_unisolate` quand ils posent un tag sur un poste. Chaque ligne est une clé (colonne 1) et sa valeur (colonne 2) ; il n'y a pas de ligne d'en-tête. `tag_trigram` : le préfixe de tag à trois lettres de votre tenant (par exemple `FIN`), utilisé seulement pour un poste qui n'a encore aucun tag, qui reçoit alors `<trigramme>_soar-isolated` ; laissé vide, un tel poste est isolé mais pas tagué, et la note le dit. `tag_separator` : le caractère entre les tags dans la chaîne de tags ; vide signifie une virgule. Les tags d'un poste forment une seule chaîne de 64 caractères au plus ; les playbooks y ajoutent `soar-isolated` / `soar-released` sans jamais la couper : un résultat de plus de 64 caractères n'est pas écrit.

## Vérification

1. **Vérifiez d'abord le connecteur.** Sur l'asset Tehtris EDR, lancez *Test Connectivity*, puis `get host detail` depuis le panneau d'actions de l'asset avec le hostname d'un vrai poste. Un hostname inconnu n'est pas une erreur ici : l'action réussit avec `total_hosts` à 0 et indique que l'hôte est introuvable. Un HTTP 401 signifie une clé ou un utilisateur incorrect ; un 404 sur toutes les actions signifie que `base_url` ne se termine pas par `/api`.

2. **Lancez ensuite `tehtris_host_posture`** depuis n'importe quel container (Playbooks > Run Playbook). Il demande `hostname` (obligatoire) et `lookback_minutes` (facultatif, 60 par défaut). Il écrit une note *Tehtris Posture: <host>* : état d'isolement, OS, processus, connexions en cours, logiciels installés et événements récents. Il ne modifie rien sur le poste. Si l'agent est hors ligne, les sections en direct indiquent « not available » et le playbook réussit quand même (statut `partial`).

3. **Isolez puis libérez un poste de TEST.** Lancez `tehtris_edr_response` (posture puis isolement) ou `tehtris_host_isolate` avec le `hostname` de ce poste, puis `tehtris_host_unisolate`. Rien n'est envoyé avant la réponse à une demande d'approbation : elle va au propriétaire du container, ou à `soar_local_admin` si le container n'en a pas, et expire après 30 minutes. Chaque exécution écrit une note *Tehtris Isolation: <host>* ou *Tehtris Release: <host>*, vérifie le résultat en relisant l'état d'isolement, et ajoute `soar-isolated` / `soar-released` aux tags du poste. Un agent hors ligne arrête le playbook avec une note, rien n'est envoyé. `tehtris_edr_response` lance les deux autres par leur nom depuis le dépôt `local` ; si le VPE affiche ses deux blocs playbook non configurés, resélectionnez-y les deux playbooks et enregistrez.

4. **Mettez en quarantaine un fichier de TEST** avec `tehtris_file_quarantine` : `hostname`, le chemin complet du fichier sur le poste (Windows : lettre de lecteur et antislashs), et en option `reason` et `notification` (texte affiché à l'utilisateur Windows). La demande d'approbation affiche le SHA-256, le nom d'origine, le produit et les signatures du fichier. La note *Tehtris Quarantine: <host>* liste les chemins de quarantaine du poste : restaurez un fichier depuis la console Tehtris avec ce chemin (le chemin en quarantaine, pas l'original).

5. **Merci de nous transmettre** ce que la note de posture affiche pour un poste qui porte au moins deux tags Tehtris (la ligne *Tags* : elle donne le séparateur et votre trigramme), les noms de colonnes des tableaux *Network connections* et *Installed software*, si les demandes vers un poste hors ligne doivent être mises en file jusqu'à sa reconnexion, si un isolement `hard` est parfois souhaité (les playbooks utilisent le mode par défaut du tenant), et comment vous utilisez la `notification` de quarantaine. La référence de l'éditeur ne précise pas ces points.

## Ce qui n'a volontairement PAS été exporté

- Les valeurs réelles des identifiants pour tout champ de configuration de type `password`
  (voir l'étape 2 ci-dessus).
- Les véritables assets cibles de rotation de l'environnement source — ce sont des assets de
  test spécifiques à ce labo, pas votre infrastructure. Suivez plutôt la section Amorçage
  ci-dessus.
- Tout ce qui n'est pas explicitement listé dans Contenu ci-dessus.
