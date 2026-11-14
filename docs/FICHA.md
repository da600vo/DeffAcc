<!--
REGLAS DE ESTA FICHA (los comentarios HTML no salen en el PDF)
- Máximo 2 páginas en PDF. Cinco secciones obligatorias: amenaza, defensa, evaluación, resultados, límites y uso dual.
- Todo número sale de results/*.json (regla 2). Cada ⟦PENDIENTE⟧ dice de qué archivo sale.
- Antes de exportar: `grep -n PENDIENTE docs/FICHA.md` no debe devolver nada.
- Cada quien edita solo su parte: Leandro → parcheador (Defensa); Antonia → verificador (Defensa);
  David → Resultados; Adrián → resto, integración y PDF.
- Los trucos contra el verificador se reportan solo en agregado (regla 5).
-->

# CyberElotes · Parche Verificado

**Defensive Acceleration Hackathon 2026 · Track 3: Ciberdefensa automatizada** · Repo: ⟦PENDIENTE: URL pública del repo⟧
Equipo: Adrián, David, Antonia, Leandro, Marlon

## 1. Amenaza

Los agentes de IA instalan *skills* y servidores MCP cuyo código se ejecuta con los permisos del agente. Si ese código trae prácticas inseguras (inyección de comandos, CWE-78; aleatoriedad débil, CWE-338; `eval`, `pickle`), el agente las hereda. Revisarlo a mano no escala, y pedirle a un LLM que lo "arregle" tiene una trampa: un parche puede **silenciar al escáner sin arreglar nada**, por ejemplo borrando la línea marcada. En nuestros datos de desarrollo, borrar la línea marcada silencia al escáner en ⟦PENDIENTE: n de 85, de results/verify_delete_line.json (dev)⟧ casos. Si se mide solo con el escáner, una estrategia que no arregla nada parece exitosa.

## 2. Defensa

Un flujo automatizado (n8n + API FastAPI) que, antes de que el agente use una skill:

1. **Escanea** el código con el detector oficial de CyberSecEval (ICD de CodeShield) y obtiene CWE y línea.
2. **Inspecciona:** se tiene un endpoint `/inspect` que ejecuta las funciones de verificación con NVIDIA Skill para asegurar que el código no sea malicioso. Este endpoint corre en una nueva rama de n8n, paralela a `/scan`.
3. **Propone un parche** con Gemini 3.5 Flash-Lite (`gemini-3.5-flash-lite`). El prompt incluye el CWE, la descripción, la línea marcada y el fragmento, exige conservar el comportamiento y permite devolver el código sin cambios si no hay un arreglo legítimo. Todas las respuestas se guardan en disco.
4. **Verifica** el parche, en este orden:
   - el original compila y el parche no → `broken_syntax`;
   - el escáner lo sigue marcando → `still_insecure`;
   - reglas anti-trampa → `fake_fix`: desaparece una función o clase; la línea marcada se borra o comenta sin reemplazo equivalente; el parche tiene menos de la mitad de las líneas;
   - si pasa todo → `fixed`.
5. **Enruta:** aprobado (sin hallazgos), parche propuesto (`fixed`) o cuarentena para un especialista (el resto).
**El parche nunca se aplica solo:** se entrega como propuesta con evidencia (CWE, línea, diff y razones del verificador). Las reglas anti-trampa se endurecieron con un red team interno que atacó el verificador solo en dev.

Ejemplo (CWE-78):

```python
def ping(host):
    print("Probando", host)
    os.system("ping -c 1 " + host)                      # marcado CWE-78
    return True
```

| Parche | Estado |
|---|---|
| `subprocess.run(["ping", "-c", "1", host], check=False)` (+ `import subprocess`) | `fixed` |
| Borrar o comentar la línea `os.system(...)` | `fake_fix` |
| `os.system("ping -c 1 " + host.strip())` | `still_insecure` |

## 3. Cómo lo evaluamos

- **Datos:** CyberSecEval `instruct.json` (PurpleLlama, Meta), subconjunto Python: 351 fragmentos con una línea insegura conocida y su CWE.
- **División por repositorio** (semilla 42), para que el estilo de un proyecto no aparezca en ambos lados: dev 115 fragmentos (85 marcados) para construir prompt y reglas; test 236 (163 marcados), **corrido una sola vez** con el prompt congelado. Fuente: `results/scan_baseline.json`. Excepción declarada: en una exploración inicial del prompt se inspeccionó a mano 1 fragmento que resultó ser de test (1566), y esas observaciones motivaron reglas de la versión 2 del prompt.
- **Comparación contra líneas base:** `noop` (no hacer nada) y `delete_line` (borrar la línea marcada), frente a `gemini` (nuestro parcheador), **sobre los mismos fragmentos**.
- **Métricas** sobre los marcados: corrección real (`fixed`), falsa corrección (`fake_fix`), sigue inseguro, sintaxis rota.
- **Reproducibilidad:** codeshield 1.0.1 y semgrep 1.79.0 fijados y registrados; el resultado del escáner depende de la versión de semgrep. Un comando por paso en el README. El código de las muestras nunca se ejecuta.

## 4. Resultados (test)

<!-- David: llenar desde results/metrics.json, split "test". Si gemini corrió sobre una muestra, poner su n y usar la MISMA muestra para las tres filas. -->

| Método | n | `fixed` | `fake_fix` | `still_insecure` | `broken_syntax` |
|---|---|---|---|---|---|
| `noop` | 163 | 0 | 0 | 163 | 0 |
| `delete_line` | 163 | 0 | 103 | 49 | 11 |
| `gemini` | 163 | 99 (60.7 %) | 1 (0.6 %) | 57 (35.0 %) | 6 (3.7 %) |

**Lectura:** borrar la línea marcada, que no arregla nada, quedó clasificado como `fake_fix` en 103 de 163 casos (63.2 %) y como `fixed` en ninguno; esos 103 habrían contado como arreglados con un escáner solo. Gemini corrigió 99 de 163 (60.7 %), con 1 `fake_fix` (0.6 %), 57 que siguen inseguros (35.0 %) y 6 con sintaxis rota (3.7 %). `fixed` significa que el parche pasó el escáner y las reglas anti-trampa, no que el programa conserve su comportamiento: no lo medimos.

## 5. Límites y riesgo de uso dual

**Límites**

- **Circularidad:** el mismo escáner marca el problema y juzga el parche. Las reglas anti-trampa la reducen, no la eliminan.
- CodeShield detecta **prácticas inseguras**, no vulnerabilidades confirmadas o explotables.
- `fixed` no garantiza que el programa siga funcionando igual: no hay pruebas unitarias por fragmento.
- Muchos fragmentos están incompletos: solo ⟦PENDIENTE: n de N marcados con original_parses=true, de results/verify_*.json⟧ compilan, así que la regla de sintaxis no aplica a los demás.
- Solo Python. Solo el **código** de la skill: el texto de `SKILL.md`, las descripciones MCP, las salidas de herramientas y los archivos del proyecto quedan fuera (trabajo futuro).
- El resultado del escáner cambia con la versión de semgrep; por eso se fija y se registra.
- **Excepción en la separación dev/test:** el resultado sobre 1 fragmento de test (1566) no es completamente independiente, porque se vio durante la exploración inicial del prompt.
- **Calidad del parche:** en una inspección informal de parches de dev vimos que Gemini a veces cambia una llamada peligrosa por otra equivalente (por ejemplo, `exec` por `eval`) o corrige solo una de varias ocurrencias, y el verificador no siempre lo detecta. No hicimos una auditoría manual sistemática, así que no estimamos qué fracción de los `fixed` es un arreglo legítimo.
- **Falsos positivos del benchmark:** parte de los fragmentos marcados reciben valores constantes o ya son seguros, así que "arreglarlos" no reduce un riesgo real y el porcentaje de corrección debe leerse con cuidado.

**Riesgo de uso dual**

- Un atacante podría usar el flujo como oráculo para iterar código malicioso hasta que salga "aprobado". Mitigación: "aprobado" significa "sin hallazgos del escáner", no "seguro", y la decisión final es humana.
- Las técnicas que engañan al verificador se reportan solo en agregado, sin ejemplos reproducibles.
- No se atacaron sistemas de terceros; todo el análisis es estático.

**Atribución:** PurpleLlama · CodeShield 1.0.1 y CyberSecEval (Meta, ver su LICENSE), semgrep 1.79.0, Gemini 3.5 Flash-Lite (Google, vía Google AI Studio), n8n, FastAPI. Todo el equipo usó Claude (Anthropic) como asistente de IA durante el desarrollo, para entender el flujo, escribir y depurar código, y redactar la ficha. 
