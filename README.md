# Prompt

Je souhaite créer un outil Python nommé `phpsecscan` pour analyser un projet PHP complet en mode hybride à froid (
analyse statique + simulation d’attaques sans exécution réelle).

Fonctionnalités principales :

* Parcours récursif du projet pour trouver tous les fichiers PHP
* Parsing du code PHP avec Tree-sitter (via Python) pour obtenir l’AST
* Analyse avancée de flux de données (taint tracking) pour suivre la propagation des entrées utilisateur (`$_GET`,
  `$_POST`, etc.) vers des sinks sensibles (`eval`, `mysqli_query`, `include`, etc.)
* Détection des vulnérabilités majeures : injection SQL, XSS, RCE, inclusion de fichiers, upload non sécurisé, failles
  d’authentification et de session
* Configuration dynamique pour choisir quelles vulnérabilités analyser
* Prise en compte des filtres/désinfections classiques (ex. `htmlspecialchars`) pour éviter les faux positifs
* Génération d’un rapport JSON structuré contenant les détails des vulnérabilités détectées (fichiers, lignes, type,
  traces)
* Architecture modulaire : parsing, suivi de flux, détecteurs par vulnérabilité, génération de rapport, exploration des
  fichiers

Merci de générer un squelette Python fonctionnel, organisé selon ce pipeline : exploration → parsing → analyse de flux →
détection → rapport, prêt à être étendu.
