-- ConfiDBA: scripts de verificación de controles ISO/IEC 27002:2022 (Oracle 19c/21c XE)
-- Ejecutar conectado a la PDB (ej. FREEPDB1) como usuario con SELECT_CATALOG_ROLE o SYSTEM.
-- Algunas vistas dependen de opciones de Oracle (TDE, Redaction, VPD): si falla en XE, documente el error como evidencia.
SET LINESIZE 220 PAGESIZE 100 FEEDBACK ON
COLUMN username FORMAT A25
COLUMN grantee FORMAT A25
SPOOL evidencias_confidba.txt

PROMPT === P-01 | Clasificación de la información | Control A5.12 ===
PROMPT Esperado: Cédula, tarjeta y salario aparecen como CONFIDENCIAL
SELECT table_name, column_name, comments FROM dba_col_comments WHERE owner='CONFI_LAB' AND comments LIKE 'CLASIF:%';

PROMPT === P-02 | Control de acceso | Control A5.15 ===
PROMPT Esperado: 0 filas, o excepción documentada
SELECT table_name, privilege FROM dba_tab_privs WHERE grantee='PUBLIC' AND table_name IN ('UTL_FILE','UTL_HTTP','UTL_TCP','UTL_SMTP');

PROMPT === P-03 | Gestión de identidades | Control A5.16 ===
PROMPT Esperado: Sin cuentas abiertas sin dueño
SELECT username, account_status, last_login FROM dba_users WHERE oracle_maintained='N' ORDER BY last_login;

PROMPT === P-04 | Información de autenticación | Control A5.17 ===
PROMPT Esperado: Ningún perfil de usuario final con UNLIMITED; función de verificación asignada
SELECT profile, resource_name, limit FROM dba_profiles WHERE resource_name IN ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LIFE_TIME','PASSWORD_VERIFY_FUNCTION') ORDER BY 1,2;

PROMPT === P-05 | Derechos de acceso | Control A5.18 ===
PROMPT Esperado: Solo cuentas administrativas, admin_option = NO
SELECT grantee, granted_role, admin_option FROM dba_role_privs WHERE granted_role='DBA';

PROMPT === P-06 | Protección de registros | Control A5.33 ===
PROMPT Esperado: ARCHIVELOG; members >= 2 (en XE puede ser 1: justificar)
SELECT log_mode FROM v$database;
SELECT group#, members, status FROM v$log;

PROMPT === P-07 | Derechos de acceso privilegiado | Control A8.2 ===
PROMPT Esperado: 0 filas para usuarios de aplicación
SELECT grantee, privilege FROM dba_sys_privs WHERE privilege LIKE '%ANY%' AND grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained='Y') AND grantee NOT IN (SELECT role FROM dba_roles WHERE oracle_maintained='Y');

PROMPT === P-08 | Restricción de acceso a la información | Control A8.3 ===
PROMPT Esperado: Política con ENABLE = YES sobre tablas sensibles
SELECT object_owner, object_name, policy_name, enable FROM dba_policies;

PROMPT === P-09 | Autenticación segura | Control A8.5 ===
PROMPT Esperado: 0 filas
SELECT username FROM dba_users_with_defpwd;

PROMPT === P-10 | Eliminación de información | Control A8.10 ===
PROMPT Esperado: Papelera vacía
SELECT owner, object_name, droptime FROM dba_recyclebin;

PROMPT === P-11 | Enmascaramiento de datos | Control A8.11 ===
PROMPT Esperado: Columnas sensibles con función FULL o PARTIAL
SELECT object_owner, object_name, column_name, function_type FROM redaction_columns;

PROMPT === P-12 | Prevención de fuga de datos | Control A8.12 ===
PROMPT Esperado: Wallet OPEN; tablespace de datos sensibles con ENCRYPTED = YES
SELECT wrl_type, status FROM v$encryption_wallet;
SELECT tablespace_name, encrypted FROM dba_tablespaces;

PROMPT === P-13 | Copias de seguridad | Control A8.13 ===
PROMPT Esperado: COMPLETED en las últimas 24 horas
SELECT input_type, status, start_time FROM v$rman_backup_job_details ORDER BY start_time DESC FETCH FIRST 5 ROWS ONLY;

PROMPT === P-14 | Registro de eventos | Control A8.15 ===
PROMPT Esperado: Políticas activas y eventos de login/DDL recientes
SELECT policy_name, enabled_option FROM audit_unified_enabled_policies;
SELECT event_timestamp, dbusername, action_name, object_name FROM unified_audit_trail ORDER BY event_timestamp DESC FETCH FIRST 20 ROWS ONLY;

PROMPT === P-15 | Seguridad de redes | Control A8.20 ===
PROMPT Esperado: Aparece Encryption service o TCPS
SELECT network_service_banner FROM v$session_connect_info WHERE sid=SYS_CONTEXT('USERENV','SID');

SPOOL OFF
