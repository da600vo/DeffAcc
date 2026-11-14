# Bitácora de Marlon: apuntes para la ficha y el pitch

Rol: control de calidad del verificador. Todo lo de aquí se probó solo en dev.

## Dificultades y cómo se resolvieron

| Dificultad | Qué hicimos |
|---|---|
| `verify.py` no corría sobre `main`: `scan_baseline.py` dejó de exportar `RULES` y `oss` al cambiar al escáner oficial | PR #2: `verify.py` llama al mismo escáner oficial |
| El verificador re-escaneaba con un escáner distinto al de la línea base: uno marcaba y otro juzgaba | El mismo arreglo. Queda un aviso si los originales no coinciden con `results/scan_baseline.json` |
| `scan_dir` del escáner oficial no devuelve la línea, y la regla anti-trampa la necesita | El verificador toma la línea del propio ICD. Coincidió con la línea del dataset en 15 de 15 casos revisados |
| La severidad del escáner no sirve para priorizar: los 125 hallazgos de dev son `warning` | La prioridad usa el CWE Top 25 de MITRE 2025 |
| El rol pedía fabricar parches tramposos, y un catálogo de evasión es material de doble uso | Tres controles en su lugar: líneas base como parches falsos sembrados, pruebas de conformidad con la tabla 3.2 y auditoría ciega |
| Leandro encontró dos parches reales de Gemini (dev 1601 y 1615) que el verificador aprobaba aunque usan nombres que nadie define | PR #4: regla 4d, `undefined_name`. Lee con el tokenizador porque solo 27 de los 85 originales de dev compilan. Falta probarla con esos dos parches, que aún no están en el repo |

También a pedido de Leandro, el PR #4 trae una segunda regla: `duplicated_block`, para parches que repiten un bloque del original. El caso que subió como ejemplo, 1569, es de test y el escáner no lo marca, así que no se usó para construirla.

## Resultados en dev (85 marcados)

| Prueba | Resultado |
|---|---|
| `noop` | 85 de 85 `still_insecure` |
| `delete_line` | 54 `fake_fix`, 25 `still_insecure`, 6 `broken_syntax`, 0 `fixed` |
| Tabla 3.2 de la arquitectura | Pasan las 8 pruebas |
| Cuarentena con `noop` | 53 P1 y 32 P2 |
| Cuarentena con `delete_line` | 77 P1 y 8 P2 |
| Secretos en la evidencia | Tapados en los 13 casos que los tienen en la línea marcada |

Pendiente: cuarentena y auditoría con los parches de Gemini.

## Caso donde el sistema falla (la plantilla de la ficha lo pide)

El verificador aprobaba como `fixed` parches que cambian la línea insegura por código que usa nombres sin definir: una función inventada o un módulo sin importar. El escáner calla, la línea sigue ahí y las funciones siguen definidas, así que ninguna regla saltaba. Lo encontró Leandro revisando parches reales de dev. Quedó convertido en una regla nueva con 16 pruebas (PR #4).

## Límites que quedan

- El mismo escáner que marca juzga el parche. Los controles que no dependen de él son las reglas anti-trampa y la auditoría humana.
- El escáner detecta prácticas inseguras, no intención: una skill maliciosa bien escrita pasa. La intención se asoma en la procedencia y en los cambios entre versiones, que hoy no comparamos.
- La prioridad mira el tipo de debilidad, no el contexto.
- Los resultados cambian con la versión del escáner: una skill ya revisada debe re-revisarse cuando cambia el escáner.
- La auditoría la hace una sola persona con una muestra pequeña: 1 error en 10 da un intervalo de 2 % a 40 %.
- El código sale del equipo al pedir el parche. Los términos de la capa gratuita de Gemini, vigentes desde el 23 de marzo de 2026, piden no enviar información sensible ni confidencial.

## Borrador para la sección 5 de la ficha (88 palabras)

El mismo escáner que marca juzga el parche, y detecta prácticas inseguras, no intención: una skill maliciosa bien escrita pasa. Solo Python, sin ejecutar el código, y muchos fragmentos no compilan. La auditoría humana es de una sola persona y muestra pequeña. Doble uso: conocer las reglas ayuda a esquivarlas; por eso no publicamos técnicas de evasión, el parche nunca se aplica solo y todo caso dudoso lo decide una persona con evidencia trazable. El código sale hacia el LLM: para uso real, modelo local o capa paga.

## Referencias candidatas

- Bhatt et al. (2023). Purple Llama CyberSecEval: A Secure Coding Benchmark for Language Models. Meta.
- MITRE (2025). CWE Top 25 Most Dangerous Software Weaknesses. cwe.mitre.org/top25
- NIST (2022). SP 800-218, Secure Software Development Framework 1.1, prácticas PW.4.1 y PW.7.2.
- Google (2026). Gemini API Additional Terms of Service. aistudio.google.com/docs/terms
- Lanier, J. Charla «Data Dignity and the Inversion of AI». Falta confirmar año y sede.
