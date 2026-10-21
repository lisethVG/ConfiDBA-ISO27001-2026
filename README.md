# ConfiDBA – Controles ISO 27001:2022 para Confidencialidad en DBA

**Universidad Nacional de Costa Rica**  
**Escuela de Informática**  
**Curso:** Administración de Bases de Datos  
**II Ciclo 2026**  
**Profesor:** Johnny Villalobos Murillo  

**Estudiante(s):**  
- Liseth Vallejos Gonzales

---

## Descripción

Artefacto interactivo y scripts de verificación de controles de confidencialidad 
basados en ISO/IEC 27001:2022 e ISO/IEC 27002:2022, aplicados al rol del 
Administrador de Bases de Datos (Oracle).

El proyecto implementa el ciclo PHVA y el principio de mínimo privilegio.

---

## Contenido del repositorio

| Carpeta / Archivo | Descripción |
|-------------------|-------------|
| `artifact/confidba.html` | Panel interactivo (riesgos, tareas, controles ISO, matriz de evaluación, pruebas y segregación de funciones) |
| `scripts/00_laboratorio.sql` | Laboratorio: usuarios separados, clasificación de datos, clon enmascarado, trigger de auditoría y políticas de auditoría unificada |
| `scripts/01_verificacion_controles.sql` | 15 pruebas técnicas observables por un auditor externo |
| `docs/` | Marco teórico y documentación de apoyo |

---

## Cómo ejecutar los scripts

1. Conectarse a la PDB de Oracle (ejemplo: `XEPDB1` o `FREEPDB1`) como `SYS AS SYSDBA` o `SYSTEM`.
2. Ejecutar primero: `@scripts/00_laboratorio.sql`
3. Luego ejecutar: `@scripts/01_verificacion_controles.sql`
4. Revisar el archivo de evidencias generado (`evidencias_confidba.txt`).

**Motor recomendado:** Oracle 19c / 21c XE o Oracle 23ai Free.

---

## Metodología

- Ciclo **PHVA** (Planificar – Hacer – Verificar – Actuar)
- Principio de **mínimo privilegio**
- **Separación de funciones** (SoD)
- Controles del Anexo A de ISO/IEC 27001:2022 / ISO/IEC 27002:2022
