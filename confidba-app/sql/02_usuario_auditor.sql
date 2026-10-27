-- Usuario de solo lectura para que ConfiDBA Studio evalúe la base (mínimo privilegio).
-- Ejecutar como SYS en la PDB (XEPDB1 en XE 21c, FREEPDB1 en 23ai Free).
CREATE USER confi_auditor IDENTIFIED BY "Cambie#Esta_2026";
GRANT CREATE SESSION, SELECT_CATALOG_ROLE, AUDIT_VIEWER TO confi_auditor;
