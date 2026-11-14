# Borrador de la ficha técnica

> **Documento histórico de trabajo.** Sus cifras no son oficiales y pueden estar obsoletas. Las oficiales están en `docs/FICHA.md` y `results/metrics.json`.

Borrador de Marlon para Adrián. Sigue la plantilla oficial del evento y sus límites de palabras.
Los `[__]` se llenan con `results/*.json` de la parte de prueba. Donde dice "en desarrollo", el número
es de dev y es provisional: en la ficha final va el de prueba.

---

*Hackathon DefAcc 2026 · Ficha técnica*

# CyberElotes: Parche Verificado

*Revisa el código de skills y servidores MCP, propone un parche con un LLM y verifica que el parche arregla de verdad.*

**Equipo:** [nombres] · [universidad u organización]

**Track:** 3. Ciberdefensa automatizada

| Repositorio | Demo | Contacto |
|---|---|---|
| github.com/da600vo/DeffAcc | Flujo n8n: [video corto o enlace] | [correo] |

## Resumen

Un agente que instala una skill ejecuta código que nadie revisó, y un parche automático puede callar al escáner sin arreglar nada. Construimos un flujo que detecta código inseguro, propone un parche con un LLM y verifica que el arreglo sea real. En desarrollo, borrar la línea marcada calló al escáner en 57 de 85 casos y nuestro verificador no dejó pasar ninguno. En prueba, el parcheador arregló de verdad [__] de 163 casos.

*74 palabras; la plantilla pide de 60 a 80. Por cambiar: el dato de desarrollo por el de prueba, y el `[__]`.*

## 1. La amenaza

Las skills y los servidores MCP traen código de terceros que el agente ejecuta. Un escáner encuentra las prácticas inseguras y un LLM puede proponer el arreglo, pero el mismo escáner que marcó el problema es el que lo da por resuelto. Borrar la línea marcada lo calla sin arreglar nada: en desarrollo pasó en 57 de 85 casos. Quien mide parches solo con el escáner reporta arreglos que no existen. El más expuesto es quien adopta agentes sin equipo de seguridad, como una pyme.

*85 palabras; la plantilla pide hasta 90. Por cambiar: 57 de 85 por el dato de prueba.*

## 2. Lo que construimos

Un flujo de cuatro pasos que corre antes de que el agente use la skill. **Detecta:** el escáner de CodeShield marca la práctica insegura, con su CWE y su línea. **Propone:** un LLM reescribe el fragmento. **Verifica:** el parche tiene que compilar, dejar callado al escáner y pasar las reglas anti-trampa, que revisan que no desaparezcan funciones, que la línea marcada no haya sido borrada ni comentada y que el parche no recorte el código. **Enruta:** sin hallazgos, aprobado; arreglo real, parche propuesto; todo lo demás, cuarentena.

Lo distinto es que no le creemos al escáner: medimos cuántos parches son reales y cuántos son trampa. El parche nunca se aplica solo. Cada caso en cuarentena llega a una persona con su prioridad y un paquete de evidencia: debilidad, línea, diferencia, razones y procedencia. Se usa por un webhook de n8n: entra el código y sale un JSON con la decisión.

**Figura 1.** `docs/1_producto_flujo.png`. El flujo: escanear, parchear, verificar y enrutar. Solo el arreglo verificado sale como parche propuesto; todo lo demás llega a una persona.

*150 palabras; la plantilla pide de 120 a 150 y una figura.*

## 3. Cómo lo evaluamos

Usamos CyberSecEval (PurpleLlama, Meta): 351 fragmentos de Python con una línea insegura conocida. Los dividimos por repositorio, con semilla 42: 115 para construir y 236 para reportar. El escáner marca 85 y 163. La parte de prueba se corrió una sola vez. Comparamos nuestro parcheador con dos líneas base: no hacer nada y borrar la línea marcada. La métrica es la corrección real: parches que el verificador da por buenos. Además, una persona revisó [__] parches sin ver el veredicto, para medir los errores del verificador.

*86 palabras; la plantilla pide de 60 a 90. Si la auditoría no alcanza a correr, se quita la última frase.*

## 4. Resultados

| Métrica | Línea base: borrar la línea | Nuestro sistema | Diferencia |
|---|---|---|---|
| Corrección real (`fixed`) | [__] | [__] | [__] |
| Trampa detectada (`fake_fix`) | [__] | [__] | [__] |
| Sigue inseguro (`still_insecure`) | [__] | [__] | [__] |
| Falsas alarmas del verificador | no aplica | [__] de [__] revisados | |

**Tabla 1.** Parches sobre los 163 casos marcados de la parte de prueba, en una sola corrida. La última fila sale de la auditoría ciega.

- **Hallazgo:** borrar la línea marcada calla al escáner en [__] de 163 casos, y el verificador no deja pasar ninguno.
- **Donde falla:** el verificador aprobaba parches que usan nombres que nadie define. Lo encontramos revisando parches reales y lo convertimos en una regla. El benchmark también marca falsos positivos, como una ruta con la palabra password.

*56 palabras; la plantilla pide una tabla y hasta 60. "Lo convertimos en una regla" solo se dice si el PR #4 queda mezclado y probado con los parches de 1601 y 1615.*

Para comparar mientras llegan los datos de prueba, esto es lo que da desarrollo (85 casos marcados) al borrar la línea: 0 `fixed`, 54 `fake_fix`, 25 `still_insecure` y 6 `broken_syntax`. El escáner calla en 57.

## 5. Límites y riesgo de doble uso

El mismo escáner que marca juzga el parche, y detecta prácticas inseguras, no intención: una skill maliciosa bien escrita pasa. Solo Python, sin ejecutar el código, y muchos fragmentos no compilan. La auditoría humana es de una sola persona y muestra pequeña. Doble uso: conocer las reglas ayuda a esquivarlas; por eso no publicamos técnicas de evasión, el parche nunca se aplica solo y todo caso dudoso lo decide una persona con evidencia trazable. El código sale hacia el LLM: para uso real, modelo local o capa paga.

*88 palabras; la plantilla pide de 60 a 90.*

## Referencias

- Bhatt et al. (2023). Purple Llama CyberSecEval: A Secure Coding Benchmark for Language Models. Meta.
- MITRE (2025). CWE Top 25 Most Dangerous Software Weaknesses. cwe.mitre.org/top25
- NIST (2022). SP 800-218, Secure Software Development Framework 1.1.
- Google (2026). Gemini API Additional Terms of Service. aistudio.google.com/docs/terms

*La plantilla pide de 3 a 5, en formato corto.*
