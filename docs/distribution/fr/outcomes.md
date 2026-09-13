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
