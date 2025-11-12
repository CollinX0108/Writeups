---
title: "Hack The Box - BOX NAME HERE"
author: "Tu Nombre"
date: "YYYY-MM-DD"
subject: "CTF Writeup Template"
keywords: [HTB, CTF, Hack The Box, Security, Penetration Testing]
lang: "es"
titlepage: true
title-page-color: "141d2b"
titlepage-rule-color: "11b925"
titlepage-text-color: "FFFFFF"
toc: true
toc-own-page: true
titlepage-background: "../images/bg.pdf"
---

# Information Gathering

## Nmap

Comenzamos nuestra reconocimiento ejecutando un escaneo de Nmap con scripts por defecto y pruebas de vulnerabilidades.

```console
nmap 
```

Del output anterior podemos ver que los puertos **XX**, **X**, **XX**, y **XX** están abiertos.

![Nmap Scan](./images/)

\ **Figure 1:** Resultado del escaneo Nmap

## Reconocimiento Web

![Web Service](./images/)

\ **Figure 2:** Servicio Web

# Exploitation

## Burpsuit

Para obtener nuestro foothold inicial necesitamos...

```
A
```

## User Flag

Para obtener la flag de usuario, simplemente necesitamos usar `cat`:

```console
cat user.txt
```

![User Flag](./images/)

\ **Figure 3:** user.txt

## Privilege Escalation

La escalada de privilegios para esta máquina fue...

```bash
A
```

## Root Flag

```console
cat /root/root.txt
```

![Root Flag](./images/)

\ **Figure 4:** root.txt

# Conclusion

En esta sección de conclusión escribo un poco sobre cómo me pareció la máquina en general, dónde tuve dificultades y qué aprendí.

# References

1. [Hack The Box](https://www.hackthebox.com/)
2. [Hack The Box Forum](https://forum.hackthebox.com/)
3. [Pandoc LaTeX Template](https://github.com/Wandmalfarbe/pandoc-latex-template)

