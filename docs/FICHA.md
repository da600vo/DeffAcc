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
1.2. **Inspecciona:** se tiene un endpoint `/inspect` que ejecuta las funciones de verificación con NVIDIA Skill para asegurar que el código no sea malicioso. Este endpoint corre en una nueva rama de n8n, paralela a `/scan`.
2. **Propone un parche** con un LLM (⟦PENDIENTE: modelo exacto de Gemini, Leandro⟧), con caché en disco.
3. **Verifica** el parche, en este orden:
   - el original compila y el parche no → `broken_syntax`;
   - el escáner lo sigue marcando → `still_insecure`;
   - reglas anti-trampa → `fake_fix`: desaparece una función o clase; la línea marcada se borra o comenta sin reemplazo equivalente; el parche tiene menos de la mitad de las líneas;
   - si pasa todo → `fixed`.
4. **Enruta:** aprobado (sin hallazgos), parche propuesto (`fixed`) o cuarentena para un especialista (el resto).
   ⟦PENDIENTE: dejar esta frase solo si el PR #3 (quarantine.py) está en main⟧ Cada caso en cuarentena sale con una prioridad (P1 si el parche hizo trampa, trajo una debilidad nueva o deja abierta una debilidad del CWE Top 25 de MITRE 2025; P2 el resto) y con un paquete de evidencia: hallazgos, diff, razones, procedencia y los secretos tapados.

**El parche nunca se aplica solo:** se entrega como propuesta con evidencia (CWE, línea, diff y razones del verificador). El verificador se puso a prueba solo en dev con 8 tipos de parche tramposo o fallido y atrapa 6 (`results/redteam.json`); los dos que pasan están en Límites.

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
- **División por repositorio** (semilla 42), para que el estilo de un proyecto no aparezca en ambos lados: dev 115 fragmentos (85 marcados) para construir prompt y reglas; test 236 (163 marcados), **corrido una sola vez** con el prompt congelado. Fuente: `results/scan_baseline.json`.
- **Comparación contra líneas base:** `noop` (no hacer nada) y `delete_line` (borrar la línea marcada), frente a `gemini` (nuestro parcheador), **sobre los mismos fragmentos**.
- **Métricas** sobre los marcados: corrección real (`fixed`), falsa corrección (`fake_fix`), sigue inseguro, sintaxis rota.
- **Reproducibilidad:** codeshield 1.0.1 y semgrep 1.79.0 fijados y registrados; el resultado del escáner depende de la versión de semgrep. Un comando por paso en el README. El código de las muestras nunca se ejecuta.

## 4. Resultados (test)

<!-- David: llenar desde results/metrics.json, split "test". Si gemini corrió sobre una muestra, poner su n y usar la MISMA muestra para las tres filas. -->

| Método | n | `fixed` | `fake_fix` | `still_insecure` | `broken_syntax` |
|---|---|---|---|---|---|
| `noop` | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ |
| `delete_line` | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ |
| `gemini` | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ | ⟦PENDIENTE⟧ |

**Lectura:** ⟦PENDIENTE: 2–3 frases. Qué fracción de lo que un escáner solo habría contado como "arreglado" atrapa el verificador como `fake_fix`; y cuánto corrige de verdad Gemini frente a las líneas base.⟧

## 5. Límites y riesgo de uso dual

**Límites**

- **Circularidad:** el mismo escáner marca el problema y juzga el parche. Las reglas anti-trampa la reducen, no la eliminan.
- CodeShield detecta **prácticas inseguras**, no vulnerabilidades confirmadas o explotables.
- `fixed` no garantiza que el programa siga funcionando igual: no hay pruebas unitarias por fragmento.
- Muchos fragmentos están incompletos: solo ⟦PENDIENTE: n de N marcados con original_parses=true, de results/verify_*.json⟧ compilan, así que la regla de sintaxis no aplica a los demás.
- Solo Python. Solo el **código** de la skill: el texto de `SKILL.md`, las descripciones MCP, las salidas de herramientas y los archivos del proyecto quedan fuera (trabajo futuro).
- El resultado del escáner cambia con la versión de semgrep; por eso se fija y se registra.
- El verificador deja pasar dos tipos de parche que encontramos en dev: el que usa un nombre que nadie define y el que repite un bloque del original. Hay una regla propuesta para cada uno, sin evaluar.
- El benchmark tiene falsos positivos: en dev, la ruta de una plantilla cuyo nombre contiene `password` está marcada como credencial. Afecta a cualquier porcentaje de arreglo.

**Riesgo de uso dual**

- Un atacante podría usar el flujo como oráculo para iterar código malicioso hasta que salga "aprobado". Mitigación: "aprobado" significa "sin hallazgos del escáner", no "seguro", y la decisión final es humana.
- Las técnicas que engañan al verificador se reportan solo en agregado, sin ejemplos reproducibles.
- No se atacaron sistemas de terceros; todo el análisis es estático.

**Atribución:** PurpleLlama · CodeShield 1.0.1 y CyberSecEval (Meta, ver su LICENSE), semgrep 1.79.0, Gemini (Google), n8n, FastAPI. Usamos asistentes de IA (⟦PENDIENTE: cuáles y para qué⟧).
