# Auditoría ciega del verificador

Código: `audit.py`. Pruebas: `tests/test_audit.py`. Responsable: Marlon.

El verificador también se equivoca. Esta auditoría mide cuánto, con parches reales del parcheador y el juicio de una persona que no ve el veredicto.

| Error | Qué es | Dónde queda |
|---|---|---|
| Escape | El verificador aprobó (`fixed`) un parche que no arregla | `escape_rate` |
| Falsa alarma | El verificador mandó a cuarentena un parche que sí arregla | `false_alarm_rate` |

## Pasos

1. Armar la muestra:

       python audit.py sample --verify results/verify_gemini.json --patches cache/patches/gemini --data PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json --split dev --n 10

2. Leer `audit/gemini_dev_hoja.md` y llenar la columna `arregla` de `audit/gemini_dev_etiquetas.csv` con `si`, `no`, `duda` o `fp`. `fp` es un falso positivo del escáner: lo marcado no era un problema. Esos casos se cuentan aparte y no entran en las tasas.
3. Calcular:

       python audit.py score --labels audit/gemini_dev_etiquetas.csv --verify results/verify_gemini.json --reviewer "Nombre"

   Escribe `results/audit_gemini_dev.json` con las dos tasas y su intervalo de Wilson al 95 %.

## Reglas

- Muestreo estratificado con semilla 42: n casos aprobados y n en cuarentena.
- En dev, cada desacuerdo es candidato a una regla nueva del verificador. En test se audita después de su única corrida y solo se reporta: no se ajusta nada.
- La hoja no muestra el estado ni las razones del verificador, y tapa los secretos escritos en el código.
- El archivo de etiquetas no se sobrescribe sin `--force`: es trabajo de una persona.
- Quien revisa queda registrado en el resultado: el juicio humano lleva nombre.

## Límite

Con 10 casos por estrato el intervalo es ancho: 1 error en 10 da entre 2 % y 40 %. Es una medida honesta de un día, no una certificación. Una sola persona revisa, sin segundo revisor.
