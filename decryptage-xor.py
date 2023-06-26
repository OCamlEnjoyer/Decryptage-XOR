from base64 import b64decode
from math import inf


# Fonctions de conversion en bytes
def FromHexToBytes(string):
    return bytes.fromhex(string)


def FromB64ToBytes(string):
    return b64decode(string)


def FromStringToBytes(string):  # Transforme "Hello world" en b'Hello world'
    return str.encode(string)


def HexToBinary(string):  # Nécessaire pour la distance de Hamming plus tard
    dicohexa, final = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
                       'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15}, ""
    for lettre in reversed(string):
        dec = dicohexa[lettre]
        cont = 0
        while dec != 0:
            final += f"{(dec % 2)}"
            dec = dec // 2
            cont += 1
        for _ in range(cont, 4):
            final += "0"
    return final[::-1]


# Fonction de cryptage
def repeatingkeyxor(buffer, cle):
    i = 0
    res = b''
    n = len(cle)
    for lettre in buffer:
        res += bytes([lettre ^ cle[i]])
        if i == n - 1:
            i = 0
        else:
            i += 1
    return res


# Décryptage d'une clé a un seul caractère
def xoragainst(buffer, character):
    final = b""
    for j in buffer:
        final += bytes([j ^ character[0]])
    return final


def evaluation(phrase):  # A quel point une phrase est-elle anglaise ?
    frequency = {32: 0.20, 97: 0.0834, 98: 0.0154, 99: 0.0273, 100: 0.0414, 101: 0.126, 102: 0.0203, 103: 0.0192,
                 104: 0.0611, 105: 0.0671, 106: 0.0023, 107: 0.0087, 108: 0.0424, 109: 0.0253, 110: 0.068, 111: 0.077,
                 112: 0.0166, 113: 0.0009, 114: 0.0568, 115: 0.0611, 116: 0.0937, 117: 0.0285, 118: 0.0106, 119: 0.0234,
                 120: 0.0020, 121: 0.0204, 122: 0.0006, 'char': 0.08855}  # Proportion des lettres en Anglais
    compte = {}
    for key in frequency:
        compte[key] = 0
    for lettre in phrase:
        if lettre > 255:  # Si on attends une phrase avec que des caractères alphadécimaux on peut mettre 127
            return inf
        if lettre in compte:
            compte[lettre] += 1
        elif ((lettre + 32) in compte) and lettre != 00:
            compte[(lettre + 32)] += 1
        else:
            compte['char'] += 1
    res = 0
    for lettre in compte:
        res += abs((frequency[lettre] * len(phrase)) - compte[lettre])
    return res


def decryptagecle(buffer):
    evalu = inf
    res = "00"
    phrasef = ""
    for i in range(0, 128):
        char = bytes([i])  # Attention, bytes prend un itérable d'où la liste a un élément
        phrase = xoragainst(buffer, char)
        e = evaluation(phrase)
        if e < evalu:
            evalu = e
            res = char
            phrasef = phrase
    return res, phrasef, evalu


# Decryptage d'un texte chiffré avec le codage en XOR a clé tournante
def distance_hamming(bytes1, bytes2):
    b1 = HexToBinary(bytes1.hex())
    b2 = HexToBinary(bytes2.hex())
    res = 0
    for i in range(len(b1)):
        if b1[i] != b2[i]:
            res += 1
    return res


def decryptagexor(buffer, taillemax=40):
    bestsizes = [(-1, inf), (-1, inf), (-1, inf)]  # On va garder les 3 tailles de clé les plus probables
    final = []
    if taillemax > len(buffer) / 3:
        taillemax = int(len(buffer) / 3)
    for keysize in range(1, taillemax):
        d = (distance_hamming(buffer[:keysize], buffer[(2 * keysize):(3 * keysize)]) +
             distance_hamming(buffer[:keysize], buffer[keysize:(2 * keysize)]) +
             distance_hamming(buffer[(2 * keysize):(3 * keysize)], buffer[keysize:(2 * keysize)])) / (3*keysize)
        if d < bestsizes[2][1]:
            bestsizes[2] = (keysize, d)
        if d < bestsizes[1][1]:
            bestsizes[1], bestsizes[2] = bestsizes[2], bestsizes[1]
        if d < bestsizes[0][1]:
            bestsizes[1], bestsizes[0] = bestsizes[0], bestsizes[1]
    for (size, score) in bestsizes:
        a_traiter = []
        for i in range(size):
            incr = i
            temp = b''
            while incr < len(buffer):
                temp += buffer[incr:(incr+1)]
                incr += size
            a_traiter.append(temp)
        res = b''
        for bloc in a_traiter:
            res += decryptagecle(bloc)[0]
        final.append((res, repeatingkeyxor(buffer, res)))
    return final
