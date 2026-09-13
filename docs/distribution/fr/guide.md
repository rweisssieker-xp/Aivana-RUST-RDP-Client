# Relayne — guide de distribution et d’exploitation

Brouillon de développement · 2026-09-13 · fr

## État et périmètre
Il s’agit d’une distribution de développement non signée, et non d’une version commerciale approuvée. La récupération à distance et les protocoles disposent de tests locaux, sans validation complète en environnement client. La nouvelle vue de distribution et ce guide sont disponibles en en-US, de, fr et it. Les vues spécialisées et les anciens documents techniques restent partiellement en allemand ; la traduction complète demeure une condition de publication.

## Fournisseur et contact
Aivana GmbH
Paulusstr. 45a - Hinterhaus - LOFT45
33602 Bielefeld, Germany
info@aivana-gmbh.ai · +49 521 92278996
Amtsgericht Bielefeld · HRB 46421 · DE459356027
https://www.aivana-gmbh.ai
https://aivana-gmbh.ai/Imprint

Mentions légales publiques vérifiées le 13/09/2026. Directeur général : Udo Bergmann. Il s’agit du contact commercial général, sans engagement de délai d’assistance ni désignation d’un délégué à la protection des données. La page de confidentialité du site se présente actuellement comme un modèle. Les conditions et la validation de confidentialité propres au produit restent ouvertes.

## Prérequis et installation
Windows x64. Fermer Relayne avant l’installation. Aucun droit administrateur requis. Le paquet n’installe pas Hyper-V, n’active pas l’accès distant, ne configure aucun hôte et ne crée aucun identifiant. Les prérequis des protocoles externes nécessitent une validation distincte.
Extraire tout le paquet dans un nouveau dossier. Vérifier : powershell -File .\Test-Package.ps1 -PackageRoot .
Uniquement pour ce paquet de développement non signé : powershell -File .\Install-Relayne.ps1 -Language fr -AllowUnsignedDev
Seuls les fichiers du manifeste sont copiés dans un nouveau dossier de version sous LOCALAPPDATA\Relayne\versions. Les versions existantes ne sont jamais écrasées. Démarrer manuellement le chemin relayne.exe indiqué. Choisir la langue dans l’application ; certaines vues spécialisées restent non traduites.

## Mises à jour et retour à une version antérieure
Installer chaque paquet à côté de la version précédente. Aucun téléchargement ni mise à jour automatique inclus. Fermer l’application puis lancer l’ancien exécutable. Sauvegarder d’abord les données : revenir à un ancien binaire n’annule pas les changements de base de données ou de configuration. La compatibilité des données n’est pas garantie sans test. Un échec de vérification laisse les installations existantes intactes.

## Désinstallation
Exécuter powershell -File .\Uninstall-Relayne.ps1 -Version VERSION -Language fr depuis un paquet de confiance. Seul le dossier de version vérifié est supprimé. Les profils, identifiants, journaux et données utilisateur sont conservés. La suppression ne résilie aucun abonnement. Aucun abonnement actif n’existe dans cette version de développement.

## Intégrité et limites de sécurité
Test-Package.ps1 vérifie une liste stricte de fichiers et leurs empreintes SHA-256. Cela détecte la corruption, mais un manifeste non signé n’authentifie pas l’éditeur. La signature publique et un canal de distribution fiable restent nécessaires. Install-Relayne.ps1 refuse ce paquet sans AllowUnsignedDev explicite. Aucun compte, tâche planifiée, service, règle de pare-feu ou connexion distante n’est créé.

## Données et confidentialité — brouillon technique
Profils, paramètres, preuves et journaux sont stockés localement. Les magasins d’identifiants et de dossiers protégés utilisent Windows DPAPI lorsque cette protection est implémentée ; tous les fichiers ne sont pas chiffrés. La protection du compte Windows et des fichiers reste importante. Un hôte distant, serveur d’équipe ou fournisseur d’IA facultatif configuré peut recevoir des données via le flux correspondant ; cet installateur et cette vue n’en transmettent pas. Vérifier textes d’incident, captures et exports avant partage ; la suppression automatique des secrets n’est pas garantie. Conservation, bases légales, contrats de traitement, transferts internationaux et suppression exigent une analyse propre au produit. Ce travail n’ajoute ni télémétrie ni envoi automatique de rapports de plantage.

## Assistance et incidents
Communiquer version, version Windows, étapes, résultats attendus/observés et journaux nettoyés au contact général. Ne pas envoyer mots de passe, jetons, captures client ou détails d’hôte sans canal sécurisé convenu. Aucun délai de réponse n’est promis. Signalement de sécurité, responsabilités d’escalade et environnements pris en charge doivent être définis avant la vente.

## Prix, licence et résiliation — aucune offre
9,99 EUR par utilisateur et par mois est une proposition. Fiscalité hors taxes/toutes taxes comprises, facturation, paiement, remboursement, résiliation et assistance ne sont pas finalisés. Paiement et activation commerciale sont désactivés. Ce guide n’accorde aucune licence commerciale et ne constitue ni contrat ni conseil juridique. Les notices des dépendances tierces et leur compatibilité de licence doivent être examinées avant toute distribution externe.

## Preuves de publication
Le manifeste contient version, révision source, état des modifications non validées, canal de développement et empreintes exactes. Les environnements locaux, profils, secrets, journaux de test et données client sont exclus. Pour une future publication, conserver les empreintes des binaires testés et les résultats réels ; des tests de développement réussis ne suffisent pas à autoriser la vente.
