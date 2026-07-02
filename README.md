# Útočné grafy a vyhodnocení rizik

Simulace síťových útoků pomocí **Floyd-Marshallova algoritmu**.  
Projekt pro předmět **Teorie grafů**.

---

## Co to dělá

Program modeluje fiktivní firemní síť jako orientovaný vážený graf a hledá nejsnazší útočné cesty pomocí Floyd-Marshallova algoritmu. Každé spuštění generuje jiný výsledek — CVSS skóre zranitelností se náhodně mění a část exploitů je vždy náhodně záplatována, čímž se simuluje reálný dynamický stav infrastruktury.

**Síť má 5 uzlů:**

```
[Utocnik]
 |       \
3.5      5.0
 |          \
 v            v
[Firewall] -2.8-> [WebServer] -2.2-> [Database]
 |                     |                  |
4.8                   5.5               0.9
 |                     |                  |
 +------------------>[Admin]<------------+
```

> Váha hrany = `10 - CVSS` — čím nižší váha, tím snazší exploit.

---

## Požadavky

- Python 3.8+
- žádné externí knihovny (pouze `random` ze standardní knihovny)

---

## Jak to funguje

### Floyd-Marshall

Algoritmus prochází trojitou smyčkou přes všechny uzly a pro každý pár `(i, j)` testuje, zda průchod přes mezilehlý uzel `k` zkrátí cestu:

```
pokud dist[i][k] + dist[k][j] < dist[i][j]:
    dist[i][j] = dist[i][k] + dist[k][j]
```

Výsledkem je matice minimálních vzdáleností a matice předchůdců, ze které lze rekonstruovat konkrétní útočnou cestu.

- **Časová složitost:** O(n³)  
- **Prostorová složitost:** O(n²)

### Váhy hran

Každý exploit má CVSS skóre (0–10). Převod na váhu hrany: `w = 10 - CVSS`.  
Závažnější zranitelnost → nižší váha → snazší průchod pro útočníka.

### Simulace

Každé kolo náhodně:
- upraví CVSS skóre o ±1,8 (jiné podmínky prostředí, verze softwaru)
- záplatuje každý exploit s pravděpodobností 20 %

### APB — kritičnost uzlů

Attack Path Betweenness (APB) počítá, kolikrát leží daný uzel na optimální útočné cestě. Uzel s nejvyšším APB je priorita pro obranná opatření.
