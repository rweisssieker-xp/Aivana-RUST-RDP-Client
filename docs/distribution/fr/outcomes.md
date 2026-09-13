# Résultats mesurés des réparations

Dans Causes et solutions, sélectionner un profil de production puis ouvrir Résultats mesurés dans les recommandations. Le rapport utilise les résultats terminés du journal d’exécution des 90 derniers jours pour cette cible. Aucun appel réseau ou IA.

## Mesures
Production et environnement de test présentent séparément réparations étayées, échecs, restaurations et résultats non vérifiés. Les règles strictes des recommandations s’appliquent : liaison exacte au plan et à la cible, exclusion des doublons, échec initial, réussite HTTP et transition réelle ou redémarrage vérifié. Les résultats exclus sont comptés à part.

L’intervalle médian commence à l’observation initiale enregistrée de la cible et se termine au contrôle réussi. La fin ultérieure d’un lot de cibles ne le prolonge pas. Seuls les succès étayés fournissent des échantillons temporels ; le nombre d’échantillons est affiché avec celui des réparations. Les données manquantes ne deviennent pas zéro. Chaque échantillon indique identifiants d’exécution/cible et dates UTC.

## Limites d’interprétation
Ce n’est ni la durée totale d’incident, ni MTTR, travail humain, disponibilité, perte évitée ou temps gagné. Mesurer uniquement les réussites crée un biais de sélection ; les échecs restent séparés et ne deviennent pas des réparations rapides. Aucune référence manuelle ni coût financier n’est enregistré : économies de travail et ROI sont explicitement non mesurés. Aucune équivalence d’environnement ni efficacité causale n’est supposée.

## Export et confidentialité
Copier le rapport en JSON place dans le presse-papiers l’identifiant du profil sélectionné, la période, les comptes séparés et les preuves temporelles. Aucun identifiant secret ni adresse d’hôte n’est exporté ; le rapport n’autorise aucune exécution. Les identifiants peuvent rester sensibles : vérifier avant partage. Les données sources restent inchangées. Nouvelle interface et documentation en en-US, de, fr et it.

## Vérification — 2026-09-13

Quatre tests ciblés de résultats/interface et 21 tests de régression d’exécution réussis (trois communs). La nouvelle vue a été rendue en quatre langues à 640 et 1440 pixels. Compilation hors ligne et formatage vérifiés. Aucun nouveau test global ni connexion réelle ; avertissements existants conservés.

## Alertes issues de l’historique des réparations

La section dépliable évalue les réparations de production étayées par clé de procédure identique (service, action et contrôle de santé). Répétitions de test, identifiants dupliqués, dates futures/expirées et intervalles incohérents sont exclus. Aucune notification, requête réseau ou action automatique ; le rapport est recalculé lors de l’affichage.

Réparations répétées : au moins trois exécutions distinctes sur au moins deux dates UTC durant les sept derniers jours. Cela indique une activité récurrente, sans prouver une cause commune des incidents.

Intervalles plus longs : comparaison des trois dernières réussites avec les trois précédentes sur 30 jours. Chaque groupe couvre au moins deux dates UTC ; les trois récentes doivent dater de sept jours au plus. Leur médiane doit au moins doubler et augmenter d’au moins 5 000 millisecondes. Une médiane initiale nulle ne déclenche pas cette règle.

Chaque signal fournit les identifiants sources et, pour le ralentissement, les deux médianes. L’export JSON utilise désormais relayne-outcome-impact-v2 avec identités des procédures et signaux. Ce sont des heuristiques rétrospectives, pas des prévisions statistiquement validées. L’absence de seuil atteint ne prouve ni un système sain ni des données suffisantes. Les limites du chronométrage des seules réussites restent applicables.

Vérification des alertes (2026-09-13) : 24 tests d’exécution dont trois nouveaux tests d’alertes, ainsi que le test d’interface en quatre langues, réussis. Compilation hors ligne et formatage validés. Aucun nouveau test global ni connexion réelle.
## Vérification locale des alertes

Une note obligatoire permet de valider une alerte et de la rouvrir manuellement. L’alerte reste visible. La validation concerne exactement le profil, la procédure et les preuves sources. Des preuves modifiées ou un délai de 30 jours rouvrent la vérification ; une simple actualisation ne le fait pas. Cela n’autorise aucune réparation et ne modifie ni les preuves ni le classement.

Stockage local protégé par Windows DPAPI dans `relayne-warning-reviews.dpapi`. Notes limitées à 256 caractères (1 024 octets), avec masquage des secrets au mieux ; ne saisissez pas d’identifiants. Maximum de 256 validations ; supprimez les validations expirées pour libérer de la place. Rechargez après un conflit d’écriture ou une erreur de lecture. Une écriture échouée conserve l’état précédent. Les validations sont absentes de l’export JSON des résultats.
