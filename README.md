# Decryptage XOR
 Dechiffrement d'un cryptage XOR à clé tournante.

## Objectif
Le cryptage *XOR a clé tournante* crypte un texte à l'aide d'une clé. Ces deux informations ne sont initiallement connu que par l'utilisateur ayant mis en place le cryptage. Notre objectif est de trouver la clé et ainsi de déchiffrer le texte à partir du texte encrypté seulement.

## Présentation du chiffrement
Chaque caractère de la clé et du texte est codé sur 8 bits (on utilisera le type bytes partout dans le code, je fournis cependant les fonctions convertissant une chaine de caractères en base 64 ou en hexadécimal vers ce type. Les caractères représentables en ASCII sont représentés ainsi, sinon ils sont représentées par \x suivi de leur valeur en hexadécimal. Par exemple le buffer hexadécimal '48656c6c6f20776f726c64' est le message b'Hello world' et '48656c6c6f00776f726c64', le message b'Hello\x00world'). \
Le cryptage mis ici en place viens effectué une disjonction exclusive (XOR) entre le premier caractère du message et de la clé puis entre le deuxième caractère du message et celui de la clé etc... Jusqu'à arriver au dernier caractère de la clé. Le prochain caractère du message est alors encrypté grace à un XOR avec le premier caractère de la clé puis le suivant avec le deuxième caractère etc... D'où le terme de clé *tournante*. \
Chaque caractère étant 8 bits, effectuer un *XOR* (de signe ⊕) entre deux caractères revient à venir regarder si à la même position en écriture binaire (base 2), les deux caractères ont un même bit ou pas, si c'est le cas, le caractère résultant du XOR aura alors à cet emplacement (toujours en base 2), un 0, sinon un 1. Dans un soucis de lisibilité, on exprime ensuite ce caractère en base 256, en type bytes, comme expliqué précedemment.
La fonction repeatingkeyxor effectue un tel cryptage.

## Principe général du dechiffrement
Tout d'abord, il faut remarquer que pour A et B deux chaines de caractères, **A ⊕ B ⊕ B = A**. En effet, soit C = A ⊕ B, et C[i] le bit en i-ème position dans C, si A[i] == B[i] alors C[i] = 0 et C[i] ⊕ B[i] vaut 0 si B[i] vaut 0 et donc A[i] aussi et 1 si B[i] vaut 1 et donc  A[i] aussi. Si A[i] != B[i] alors C[i] vaut 1 et C[i] ⊕ B[i] vaut 1 si C[i] == A[i] et vaut 0 si A[i] != C[i] donc on a encore une fois A[i] = C[i] ⊕ B[i].\
Ainsi, pour vérifier qu'une clé B est la bonne, on regarde si C ⊕ B avec C le message encodé donne un message "cohérent". Pour vérifier qu'un message est cohérent, on compare la présence des caractères en son sein avec la présence moyenne de tels caractères dans la langue souhaité (ici, le tableau de statistique que j'ai mis en place correspond un peu près à la langue anglaise car le programme a été conçu comme solution à un challenge anglais disponible [ici](cryptopals.com)).

## Explications détaillées
Il existe 256 caractères sur 8 bits (2^8). La clé pouvant être d'une longueur importante, il est évident que nous n'allons pas tester toutes les clés possibles. Dans un premier temps nous allons essayer d'établir la longueur de la clé. Pour cela nous utilisons la distance de Hamming: c'est la somme du nombre de bits différents entre deux mots(cf. la fonction distance_hamming(bytes1, bytes2) ). Par exemple la distance de hamming entre b'blur' (en binaire '01100010011011000111010101110010') et b'toto' (en binaire '01110100011011110111010001101111') est 10.\
Sachant cela, pour n entre 1 et taillemax, on va regarder la distance de Hamming entre le premier bloc de taille n et le deuxième, entre le 2-ème et le troisième et entre le troisième et le premier (pour plus de précision on peut prendre plus que 3 blocs, ou seulement 2 pour augmenter taillemax), on vient faire la moyenne de ces valeurs puis on normalise ce résultat en le divisant par n. La taille n de la clé minimise généralement cette valeur, on vient donc garder les 3 tailles donnant le plus petit résultat (dans la liste bestsizes).\
### Pourquoi, la taille de la clé généralise cela ?
Tout d'abord, on remarque que la distance de Hamming entre a et b est la même qu'entre a⊕c et b⊕c (La preuve est similaire à celle précédente en regardant bit par bit et est donc laissé au lecteur). \
Lorsque l'on a choisit la bonne longueur de clé, on vieent regarder la distance entre A[0:n] ⊕ B et A[n:2n] ⊕ B soit entre A[0:n] et A[n:2n]. On fait alors seulement la distance entre deux bout de phrase avec des caractères alpha-numérique, ils ont des valeurs décimales inférieur à 128 et ont donc une distance de Hamming d'au plus 7. On pourrait s'attendre à une moyenne des distances de 3.5 mais elle est en réalité encore plus petite car des lettres se répetent souvent ou plus généralement on remarque que statistiquement, les distances entre deux bouts de phrases anglaises (toujours avec les moyennes d'apparition de lettres discutés plus tôt) ont une distance plus faible. \
Au contraire, lorsque la taille de la clé est mauvaise, on compare deux bouts de messages chiffrés avec une clé différentes (on ne tombe pas tout juste sur B) et on s'attend donc à une moyenne des distances de Hamming de 4. Ainsi la bonne taille de clé minimise la moyenne des distances. Evidemment, plus on prends de "blocs" de texte à comparer, plus la taille de la clé est longue, plus cette minimisation est apparente. On vient ici garder les 3 tailles les plus probables. \
### Détemination de la clé
Maintenant que la taille n de la clé est connu, on vient créer des bouts de phrase consistants des lettres du message codé espacé de n lettres. Ainsi le premier bout de phrase aura la lettre 0, la lettre n, 2n etc... On remarque que dans chaque bloc les lettres ont toutes été encodés grâce à un XOR avec une même lettre. Pour chacun de ces blocs, on test chaque clé de 1 caractères, il y en a 256. Après le XOR avec un tel caractère, on compare le nombre de chaque lettres présentes dans le bout de phrase décodé avec le nombre moyen de chaque lettre dans une chaine de caractère d'une telle taille dans la langue en question (ici l'anglais). Le caractère qui minimise cette différence est surement le caractère ayant encodé ce bout de phrase. En mettant bout à bout chaque caractère encodant chaque bout de phrase, on obtient finalement la clé générale et le message encodé est dechiffré !
