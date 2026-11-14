# Ficha técnica: mcp-tool-auditor

**Autor:** [tu nombre] · **Track:** 01. Seguridad de agentes y defensa contra inyección de instrucciones · **Repositorio:** [enlace GitHub]

## 1. Vector de riesgo
**Envenenamiento de herramientas MCP (*tool poisoning*).** Un servidor MCP malicioso publica una herramienta cuya *descripción* contiene órdenes ocultas para el agente (leer `~/.ssh/id_rsa`, cambiar los argumentos del usuario, enviar datos a terceros). El agente la trata como contexto confiable; el usuario nunca la ve. En LATAM, agencias y pymes conectan agentes a servidores MCP de terceros sin revisión de seguridad.

## 2. Mecanismo defensivo
Defensa en capas **antes** de registrar las herramientas en el agente:
1. **Reglas (etapa 1):** auditor estático, explicable y de costo cero. Nueve reglas puntuadas: referencia a otra herramienta, *hook* sobre otra herramienta, órdenes al modelo, alteración de parámetros, objetivos sensibles, exfiltración, ocultamiento, caracteres invisibles y longitud anómala. Python estándar, milisegundos por herramienta, evidencia revisable.
2. **Verificador independiente (etapa 2):** un LLM distinto intenta *refutar* cada alerta (confirmada / revisar / rechazada). No tiene herramientas y solo emite una etiqueta, porque también lee texto del atacante.

**Ventaja para quien defiende:** corre una sola vez al instalar el servidor, cuesta cero y bloquea el ataque antes de que el modelo lo lea.

## 3. Validación empírica
- **Datos:** MCPTox, 485 descripciones envenenadas + 362 limpias de 45 servidores MCP reales.
- **Partición por servidor:** reglas ajustadas con 15 servidores; resultados sobre **30 servidores no vistos** (272 envenenadas, 208 limpias).
- **Líneas base:** filtro de palabras clave de *jailbreak* y **NVIDIA SkillSpector** v2.12.0 (modo estático).

| Método | Recall | Precisión | Falsos positivos |
|---|---|---|---|
| Filtro de *jailbreak* | 0,0 % | n/a | 0,0 % |
| SkillSpector estático (`CAUTION` o peor) | 13,2 % | 97,3 % | 0,5 % |
| **Reglas (etapa 1)** | **91,5 %** | **98,8 %** | **1,4 %** |
| Reglas con evasión (nombres indirectos) | 43,8 % | 97,5 % | 1,4 % |
| *Reglas + verificador (etapa 2)* | *por medir* | | |
| *Tras endurecer contra la evasión* | *por medir* | | |

**Hallazgo clave:** el envenenamiento no "parece" un *jailbreak*: los filtros clásicos detectan 0 % y un escáner general de *skills* en modo estático, 13,2 %. La señal más fuerte es estructural: una descripción que habla de *otra* herramienta (sin esa regla, el recall baja a 69 %).

## 4. Límites y riesgo dual
- **Comparación no neutral:** nuestras reglas se ajustaron con datos de desarrollo de MCPTox; SkillSpector no, recibió las descripciones como *skills* (no es su formato nativo) y sin su modo LLM.
- **Evasión:** nombrar la otra herramienta de forma indirecta reduce el recall a 43,8 %; por eso existen las etapas 2 y 3.
- **Datos de plantilla:** MCPTox está generado con plantillas; ataques reales pueden variar más.
- **Español:** reglas incluidas pero aún sin conjunto de prueba (SkillSpector también declara menor cobertura fuera del inglés).
- **Uso dual:** publicar reglas facilita la evasión; lo cuantificamos abiertamente. No se publica ningún corpus nuevo de ataques.
