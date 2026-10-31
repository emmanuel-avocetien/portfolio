# Projet 1 — Active Directory dans Azure + monitoring SOC

**Emmanuel Avocetien** · Montréal · [LinkedIn](https://www.linkedin.com/in/fofoprio) · [Credly](https://www.credly.com/users/emmanuel-avocetien/badges/credly)

> **EN summary:** I built a two-server Active Directory lab in Azure (Windows Server 2022), applied least-privilege access with security groups, then added SOC-style monitoring (Windows Event Viewer, Log Analytics + KQL, VNet flow logs, Microsoft Defender for Cloud). The lab was hit by a real internet brute-force attack (~40,000 failed RDP logons) caused by an open RDP rule; I detected it, investigated it, contained it and documented it in an [incident report](RAPPORT_INCIDENT.md).

## Objectif
Monter un domaine Active Directory dans le cloud, gérer les identités et les accès selon le moindre privilège, puis **détecter, investiguer et documenter** une activité malveillante réelle, comme le ferait un analyste SOC.

## Résultats clés
- Domaine `lab.local` fonctionnel : 1 contrôleur de domaine (`CD-01`) + 1 serveur membre (`SRV01`).
- Accès RDP accordé **par groupe** (`GG-Support-TI`) : `atest` entre sur `SRV01`, mais est **refusé** sur le contrôleur de domaine.
- Journalisation centralisée (Log Analytics) des événements de sécurité Windows (4624, 4625, 4720, 4728, 4732, 4740).
- **Incident réel détecté** : 40 000 échecs de connexion depuis Internet, **0 compromission** (seules mes connexions légitimes ont réussi).
- Remédiation : règle RDP du NSG restreinte à une seule IP ; preuve avant/après par graphique KQL.
- Posture Defender for Cloud évaluée (plan gratuit) ; plans payants volontairement non activés.

## Compétences démontrées
`Active Directory` · `DNS` · `Azure (VNet, NSG, VM)` · `IAM / moindre privilège` · `PowerShell` · `Windows Event Viewer` · `Azure Monitor / Log Analytics` · `KQL` · `VNet Flow Logs` · `Microsoft Defender for Cloud (CSPM)` · `Réponse à incident` · `MITRE ATT&CK` · `Maîtrise des coûts cloud` · `Redaction de rapport d'incident`

## Architecture
| Élément | Valeur |
|---|---|
| Région / groupe de ressources | Canada East / `rg-ad-lab` |
| Réseau virtuel | `vnet-ad-lab`, sous-réseau `default` 10.0.0.0/24 |
| Contrôleur de domaine | `CD-01` — 10.0.0.4 — Windows Server 2022 |
| Serveur membre | `SRV01` — 10.0.0.5 — Windows Server 2022 |
| Domaine | `lab.local` (forêt unique) |
| Journalisation | `law-lab` (Log Analytics), règle `dcr-lab-security`, journal de flux de VNet |

## Étapes

### 1. Mis en place Environnement Azure
Groupe de ressources, réseau virtuel, deux VM, NSG avec RDP, alerte de budget.
![Groupe de ressources](images/environnement/01-groupe-de-resources.png)
![VNet et sous-réseau](images/environnement/02-sous-reseau-vnet.png)
![Liste des VM](images/environnement/04-liste-machines-virtuelles.png)
![Test de connectivité CD-01 vers SRV01](images/environnement/06-test-connectivite.png)

### 2. Domaine Active Directory
Installation du rôle AD DS, promotion de `CD-01` en contrôleur de domaine (nouvelle forêt `lab.local`), DNS du VNet pointé vers `10.0.0.4`, jonction de `SRV01` au domaine. Détail pas à pas : [images/domaine](images/domaine).
![Domaine lab.local](images/environnement/07-domaine-lab-local.png)
![SRV01 joint au domaine](images/environnement/08-srv01-joint-domaine.png)

### 3. Structure, groupes et utilisateurs (PowerShell)
Création des unités d'organisation (`Utilisateurs`, `Groupes`, `Admins`, `Serveurs`), de groupes par rôle (`GG-Support-TI`, `GG-Comptabilite`) et de comptes de test, avec mot de passe saisi de façon sécurisée. Script : [scripts/01-create-ad-structure.ps1](scripts/01-create-ad-structure.ps1).
![Exécution du script](images/environnement/09-ou-script-execution.png)

### 4. Accès par groupe et test de refus (moindre privilège)
`GG-Support-TI` est ajouté au groupe local « Utilisateurs du Bureau à distance » de `SRV01`. Test : `lab\atest` se connecte à `SRV01`, mais est refusé sur le contrôleur de domaine.
![Groupe ajouté](images/environnement/10-ajout-du-groupe-support-ti-au-utilisateurs-bureau-a-distance-de-srv1-ok.png)
![Connexion atest](images/environnement/11-connexion-atest.png)
![Accès refusé au DC](images/environnement/12-acces-refuse-alice-server-vers-dc.png)

### 5. Investigation locale avec l'Observateur d'événements
Génération d'échecs de connexion volontaires, repérage des événements 4625 / 4720, requêtes `Get-WinEvent`.
![Échecs 4625](images/event-viewer/07-identification-de-l-echec-de-connexion-dans-event-viewer.png)
![Requête PowerShell](images/event-viewer/06-script-powershell-log-security-echecs-de-connexions.png)
Galerie complète : [images/event-viewer](images/event-viewer).

### 6. Journalisation cloud (Log Analytics + KQL)
Espace `law-lab`, agent Azure Monitor sur les deux VM, règle de collecte avec filtre XPath limité aux événements utiles (coûts maîtrisés), vérification par la table `Heartbeat`. Requêtes : [scripts/queries.kql](scripts/queries.kql).
![Règle de collecte](images/journalisation/dcr-collecte.png)
![Filtre XPath](images/journalisation/requete-xpath.png)
![Heartbeat](images/journalisation/heartbeats-agents.png)

### 7. Journaux de flux du réseau virtuel
Journal de flux de **VNet** avec Traffic Analytics (les journaux de flux de NSG sont retirés par Microsoft le 30 septembre 2027).
![Journal de flux](images/journalisation/creation-d-un-journal-de-flux.png)

### 8. Incident : attaque par force brute réelle
Règle RDP ouverte à « Any » → ~40 000 tentatives depuis Internet. Détection, investigation, confinement et preuve avant/après : **[RAPPORT_INCIDENT.md](RAPPORT_INCIDENT.md)**.
![Avant et après](images/incident/graphes-avant-et-apres-attaques.png)

### 9. Microsoft Defender for Cloud
Plan gratuit (CSPM fondamental) actif, plans payants désactivés. Score initial 33 %, recommandation « restreindre les ports sur les NSG » identifiée ; réévaluation en attente.
![Plans](images/defender/01-plans-defender.png)
![Posture initiale](images/defender/02-posture-de-securite-initial.png)

## Ce que j'ai appris
- Une règle RDP ouverte à Internet est attaquée en quelques heures : la surface d'exposition doit être réduite dès la création.
- Sans journalisation, l'attaque serait passée inaperçue ; avec elle, on peut prouver **ce qui s'est passé et ce qui ne s'est pas passé**.
- Un nom d'administrateur non standard et le moindre privilège réduisent le risque réel (aucun de mes comptes n'a été ciblé).

## Améliorations proposées (non activées)
Verrouillage de compte (GPO), Azure Bastion ou accès JIT, MFA / accès conditionnel, règle d'alerte Sentinel sur pic de 4625, Defender CSPM (5 $/ressource/mois) et Defender pour serveurs Plan 2 (15 $/serveur/mois) en production.

## Limites et transparence
- Les VM sont restées arrêtées entre deux séances : l'absence d'attaque du 27 au 30 octobre ne prouve pas à elle seule l'effet du NSG (voir le rapport).
- Réévaluation Defender for Cloud : non disponible à la date de publication (VM arrêtées entre les séances) ; la recommandation initiale est documentée dans le rapport.
- Captures nettoyées (adresses courriel et IP publiques masquées). Lab personnel, aucune donnée d'employeur.

## Contenu du dépôt
`README.md` · `RAPPORT_INCIDENT.md` · `scripts/` · `images/`
