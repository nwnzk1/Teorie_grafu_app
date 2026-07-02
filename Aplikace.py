"""

Utocne grafy a vyhodnoceni bezpecnostnich rizik.

Simulace sitovych utoku pomoci Floyd-Marshallova algoritmu.
Kazde spusteni generuje nahodne zmeny CVSS skore a zalat,
cimz modeluje ruzne stavy realne sitove infrastruktury.

"""

import random

INF = float('inf')

# Nazvy uzlu site - index odpovida pozici v maticich
uzly = ["Utocnik", "Firewall", "WebServer", "Database", "Admin"]
n    = len(uzly)

# Zakladni sada exploitu: (zdrojovy uzel, cilovy uzel, CVSS skore, popis)
# CVSS skala 0-10: vyssi = zavaznejsi zranitelnost
hrany_base = [
    (0, 1, 6.5, "HTTP smuggling"),
    (0, 2, 5.0, "Exposed service"),
    (1, 2, 7.2, "SMB relay"),
    (1, 4, 5.2, "Weak Kerberos"),
    (2, 3, 7.8, "SQL injection"),
    (2, 4, 4.5, "Path traversal"),
    (3, 4, 9.1, "DB priv-esc"),
]


def floyd_marshall(hrany_aktivni):
    """

    Spocita nejkratsi utocne cesty mezi vsemi pary uzlu.

    Implementuje Floyd-Marshallův algoritmus s casovou slozitosti O(n^3)
    a prostorovou slozitosti O(n^2). Vaha hrany se odvozuje z CVSS skore
    vzorcem w = 10 - CVSS, takze zavaznejsi zranitelnosti maji nizsi vahu
    (= snazsi prechod pro utocnika).

    """
    # Inicializace matice vzdalenosti: 0 na diagonale, INF vsude jinde
    W = [[0 if i == j else INF for j in range(n)] for i in range(n)]

    # Zapis primych hran - vaha = 10 - CVSS (nizsi = snazsi exploit)
    for (a, b, cvss, _) in hrany_aktivni:
        W[a][b] = round(10 - cvss, 1)

    dist = [row[:] for row in W]
    nxt  = [[-1] * n for _ in range(n)]

    # Inicializace matice predchudcu pro prime hrany
    for i in range(n):
        for j in range(n):
            if dist[i][j] != INF and i != j:
                nxt[i][j] = j

    # Hlavni smycka: k = index mezilehleho uzlu
    # Pro kazdy par (i, j) testujeme, zda cesta pres k je kratsi
    for k in range(n):
        for i in range(n):
            for j in range(n):
                if dist[i][k] != INF and dist[k][j] != INF:
                    nv = round(dist[i][k] + dist[k][j], 2)
                    if nv < dist[i][j]:
                        dist[i][j] = nv
                        nxt[i][j]  = nxt[i][k]  # zapamatuj mezistupen

    return dist, nxt


def get_path(nxt, src, dst):
    """

    Rekonstruuje optimalni utocnou cestu ze zdrojoveho do ciloveho uzlu.

    Zpetne prochazi matici predchudcu a sestavuje seznam uzlu tvořících
    nejkratsi cestu nalezenou Floyd-Marshallovym algoritmem.

    """
    if src == dst:
        return [src]
    if nxt[src][dst] == -1:
        return None  # cesta neexistuje (uzel nedosazitelny)

    path = [src]
    while path[-1] != dst:
        path.append(nxt[path[-1]][dst])

    return path


def simulace(cislo_kola):
    """

    Spusti jedno simulacni kolo s nahodnym stavem site.

    Kazde kolo nahodne upravi CVSS skore vsech zranitelnosti (+-1.8)
    a s pravdepodobnosti 20 % zaplatuje kazdy exploit. Vysledna
    konfigurace se preda Floyd-Marshallovu algoritmu a vypise se
    nejkriticnejsi utocna cesta k uzlu Admin spolu s APB skore uzlu.

    """
    print(f"\n{'=' * 57}")
    print(f"  SIMULACE - KOLO {cislo_kola}")
    print(f"{'=' * 57}")

    hrany_aktivni = []  # hrany, ktere prezily zaplatovani

    print("\n  Stav zranitelnosti:")
    print(f"  {'Exploit':<20} {'Od':>10} -> {'Do':<12} {'CVSS':>6}  {'Zmena':>7}")
    print("  " + "-" * 55)

    for (a, b, cvss, desc) in hrany_base:
        # Nahodna odchylka CVSS simuluje ruzne podminky prostredi
        zmena   = random.uniform(-1.8, 1.8)
        cvss_nw = round(max(1.0, min(9.9, cvss + zmena)), 1)

        # 20% sance, ze administrator stihl zranitelnost zaplatovat
        if random.random() < 0.20:
            print(f"  [PATCH]  {desc:<20} {uzly[a]:>10} -> {uzly[b]:<12} {'':6}  zaplatovano")
            continue

        hrany_aktivni.append((a, b, cvss_nw, desc))
        zn_str = f"+{zmena:.1f}" if zmena >= 0 else f"{zmena:.1f}"
        print(f"  [OK]     {desc:<20} {uzly[a]:>10} -> {uzly[b]:<12} {cvss_nw:>6.1f}  ({zn_str})")

    # Zadna aktivni hrana = utocnik nema kudy jit
    if not hrany_aktivni:
        print("\n  Vsechny zranitelnosti zaplatovany - utocnik nema cestu!\n")
        return

    dist, nxt = floyd_marshall(hrany_aktivni)

    # Vysledek pro cilovy uzel Admin (posledni v seznamu)
    cil   = n - 1
    path  = get_path(nxt, 0, cil)
    score = dist[0][cil]

    print(f"\n  Nejkritictejsi cesta k '{uzly[cil]}':")
    if path is None:
        print("  >> ADMIN je v tomto kole nedosazitelny! <<")
    else:
        risk  = "KRITICKE" if score < 5 else ("VYSOKE" if score < 8 else "STREDNI")
        cesta = " -> ".join(uzly[p] for p in path)
        print(f"  >> {cesta}")
        print(f"     Skore: {score:.1f}  [{risk}]")

    # APB - pocet optimalnich cest prochazejicich kazdym uzlem
    apb = [0] * n
    for i in range(n):
        for j in range(n):
            if i != j:
                p = get_path(nxt, i, j)
                if p:
                    for nd in p[1:-1]:
                        apb[nd] += 1

    top = sorted(range(n), key=lambda x: apb[x], reverse=True)
    print(f"\n  Nejkritictejsi uzel k obrane: {uzly[top[0]]}  (APB={apb[top[0]]})")


# -------------------------------------------------------
#  Vstupni bod programu
# -------------------------------------------------------

print("""
  TOPOLOGIE UTOCNEHO GRAFU
  ========================
  (vaha hrany = 10 - CVSS, nizsi vaha = snazsi exploit)

  [Utocnik]
   |       \\
  3.5      5.0
   |          \\
   v            v
  [Firewall] -2.8-> [WebServer] -2.2-> [Database]
   |                     |                  |
  4.8                   5.5               0.9
   |                     |                  |
   +------------------>[Admin]<------------+
""")

print("  Spoustim 3 simulacni kola (kazde kolo = jiny stav site)...")

for kolo in range(1, 4):
    simulace(kolo)

print(f"\n{'=' * 57}\n")
