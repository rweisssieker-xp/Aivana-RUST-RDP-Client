# Recommandations de réparation fondées sur les résultats

La nouvelle section Causes et solutions classe les résultats de récupération des services pour la cible de production sélectionnée. Elle n’entraîne aucun modèle et n’appelle aucun fournisseur d’IA. Le classement est recalculé de façon déterministe à partir du journal d’exécution actuel, sans stockage séparé de preuves apprises.

## Règles de preuve
Seuls les résultats terminés des 90 derniers jours contribuent. Les dates futures ou expirées, identités exécution/cible dupliquées, liaisons de plan invalides et autres cibles sont exclues. Les répétitions sont affichées séparément et n’améliorent jamais le classement de production. Démarrage, redémarrage et contrôles de santé différents restent distincts.

Une réparation étayée exige la validation existante des preuves avant/action/après, un contrôle initial en échec, un contrôle HTTP final réussi et une transition réelle ou un redémarrage vérifié. Un service déjà sain ou un contrôle TCP seul n’établit pas une réparation. Échecs, restaurations et résultats non vérifiés restent visibles.

## Classement et retrait
Chaque catégorie de production est limitée à cinq résultats : +5 par réparation étayée, −8 par échec/restauration combinés, −4 par résultat non vérifié. Ces poids sont explicites, pas des probabilités. Une recommandation exige au moins une réparation de production étayée dont la dernière réussite est postérieure à tout résultat défavorable ou non vérifié. Une égalité reste bloquée. Le tri est déterministe.

## Utilisation et limites
Sélectionner un profil, examiner nombres et références des preuves, puis préparer un nouveau plan de vérification si la recommandation est étayée. La protection des tâches en cours et les nouvelles vérifications/autorisations restent obligatoires. Le classement ne lance aucune action. La copie explicite du rapport inclut noms de services et identifiants de preuves ; vérifier avant partage.

Une même cible ne garantit pas que logiciel, configuration ou droits soient inchangés. Aucun apprentissage entre clients, aucune preuve causale ni promesse de productivité mesurée. Les résultats exclus sont comptés mais ne servent pas de preuve positive. Les vues de solutions précédentes restent disponibles séparément. Les nouveaux textes existent en en-US, de, fr et it.
# Lacunes des preuves
Les lacunes historiques sont explicites : contrôle HTTP absent, échec initial non étayé, transition de service absente ou preuves avant/action/après incomplètes ou contradictoires. Elles expliquent l’incertitude historique, pas l’état actuel de l’hôte.

## Vérification — 2026-09-13

Cinq tests ciblés d’apprentissage/traduction et 18 tests de régression d’exécution réussis (quatre tests communs). Compilation hors ligne et formatage vérifiés. Aucun nouveau test global, accès à un hôte réel ou appel de modèle externe. Les avertissements existants restent présents.
