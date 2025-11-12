---
title: "Hack The Box - Oopsie"
author: "DiosX0108"
date: "2024-12-19"
subject: "CTF Writeup"
keywords: [HTB, CTF, Hack The Box, Security, Penetration Testing, Oopsie]
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
$ nmap 


```

Del output anterior podemos ver que los puertos **XX** (SSH) y **XX** (HTTP) están abiertos.

![Nmap Scan](./images/)

\ **Figure 1:** Resultado del escaneo Nmap

## Reconocimiento Web

Exploramos el servicio web en el puerto 80.

![Web Service](./images/)

\ **Figure 2:** Servicio Web

# Exploitation

## Burpsuit

## User Flag

Para obtener la flag de usuario:

```console
$ cat 
```

![User Flag](./images/)

\ **Figure 3:** user.txt

## Privilege Escalation

## Root Flag

```console
$ cat 
```

![Root Flag](./images/)

\ **Figure 4:** root.txt

# Conclusion

# References

1. [Hack The Box](https://www.hackthebox.com/)
2. [Hack The Box Forum](https://forum.hackthebox.com/)
3. [Pandoc LaTeX Template](https://github.com/Wandmalfarbe/pandoc-latex-template)

