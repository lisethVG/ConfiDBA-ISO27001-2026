"""Controles y riesgos de ConfiDBA Studio.
Este es el archivo que se edita para cambiar QUE se evalua:
- RIES: los 5 riesgos (nombre, impacto x probabilidad y controles que los cubren)
- CH: los 15 controles (consulta SQL, como se puntua, explicacion y sugerencia)
"""
import re, datetime as dt
now = dt.datetime.now

# Riesgos: id, nombre, inherente (impacto x probabilidad), controles ligados
RIES = [("R-CONF-01", "Exceso de privilegios", 16, ["A5.15", "A5.18", "A8.2", "A8.3"]),
        ("R-CONF-02", "Acceso por cuentas débiles", 15, ["A5.16", "A5.17", "A8.5"]),
        ("R-CONF-03", "Fuga en respaldos y clones", 16, ["A5.12", "A8.10", "A8.11", "A8.13"]),
        ("R-CONF-04", "Datos sin cifrar", 15, ["A8.12", "A8.20"]),
        ("R-CONF-05", "Falta de trazabilidad", 12, ["A5.33", "A8.15"])]
P = "'CEDULA|TARJETA|SALARIO|CLAVE|PASSWORD|EMAIL|TELEFONO'"
def ratio(n, t): return n / t if t else None
# id, nombre, consultas, evaluador(resultados)->(puntaje 0..1 o None, hallazgo), qué comprueba, sugerencia
CH = [
("A5.12", "Clasificación de la información", ["SELECT c.column_name, cm.comments FROM dba_tab_columns c LEFT JOIN dba_col_comments cm ON cm.owner=c.owner AND cm.table_name=c.table_name AND cm.column_name=c.column_name WHERE c.owner=:s AND REGEXP_LIKE(c.column_name," + P + ",'i')"],
 lambda r: (ratio(sum(1 for x in r[0] if x[1] and x[1].startswith("CLASIF:")), len(r[0])), f"{sum(1 for x in r[0] if x[1] and x[1].startswith('CLASIF:'))} de {len(r[0])} columnas sensibles están clasificadas."),
 "Que las columnas con datos sensibles estén etiquetadas con su nivel de clasificación.", "Etiquetar con COMMENT ON COLUMN ... IS 'CLASIF: CONFIDENCIAL' y mantener un inventario."),
("A5.15", "Control de acceso (PUBLIC)", ["SELECT table_name FROM dba_tab_privs WHERE grantee='PUBLIC' AND table_name IN ('UTL_FILE','UTL_HTTP','UTL_TCP','UTL_SMTP')"],
 lambda r: (max(0, 1 - len(r[0]) / 4), f"{len(r[0])} de 4 paquetes peligrosos son ejecutables por cualquier usuario."),
 "Que cualquier usuario (PUBLIC) no pueda usar paquetes que leen archivos o salen a la red.", "REVOKE EXECUTE ON UTL_FILE FROM PUBLIC (y los demás) y conceder solo a quien lo necesite."),
("A5.16", "Gestión de identidades", ["SELECT username, account_status, last_login FROM dba_users WHERE oracle_maintained='N'"],
 lambda r: (lambda a, s: (ratio(len(a) - len(s), len(a)), f"{len(s)} de {len(a)} cuentas abiertas llevan más de 90 días sin uso."))([x for x in r[0] if x[1] == "OPEN"], [x for x in r[0] if x[1] == "OPEN" and (x[2] is None or (now() - x[2].replace(tzinfo=None)).days > 90)]),
 "Que no existan cuentas abiertas que nadie usa.", "Bloquear las cuentas inactivas (ALTER USER ... ACCOUNT LOCK) y asignar un responsable a cada cuenta."),
("A5.17", "Política de contraseñas", ["SELECT p.profile, p.resource_name, CASE WHEN p.limit='DEFAULT' THEN (SELECT d.limit FROM dba_profiles d WHERE d.profile='DEFAULT' AND d.resource_name=p.resource_name) ELSE p.limit END FROM dba_profiles p WHERE p.resource_name IN ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LIFE_TIME','PASSWORD_VERIFY_FUNCTION') AND p.profile IN (SELECT profile FROM dba_users WHERE oracle_maintained='N')"],
 lambda r: (ratio(sum(1 for x in r[0] if x[2] not in (None, "UNLIMITED", "NULL")), len(r[0])), f"{sum(1 for x in r[0] if x[2] not in (None, 'UNLIMITED', 'NULL'))} de {len(r[0])} parámetros de contraseña están configurados."),
 "Que los perfiles de los usuarios bloqueen intentos fallidos, venzan claves y validen su complejidad.", "Crear un perfil con FAILED_LOGIN_ATTEMPTS 5, PASSWORD_LIFE_TIME 90 y una función de verificación."),
("A5.18", "Derechos de acceso (rol DBA)", ["SELECT grantee, admin_option FROM dba_role_privs WHERE granted_role='DBA' AND grantee NOT IN ('SYS','SYSTEM')"],
 lambda r: (max(0, 1 - 0.5 * len(r[0])), f"{len(r[0])} cuentas, además de SYS y SYSTEM, tienen el rol DBA."),
 "Que muy pocas cuentas tengan control total de la base.", "Retirar el rol DBA a quien no lo necesite (REVOKE DBA FROM ...) y dar roles específicos."),
("A5.33", "Protección de registros", ["SELECT log_mode FROM v$database", "SELECT members FROM v$log"],
 lambda r: (0.5 * (r[0][0][0] == "ARCHIVELOG") + 0.5 * (min(x[0] for x in r[1]) >= 2), f"Modo {r[0][0][0]}; mínimo {min(x[0] for x in r[1])} copia(s) del redo log."),
 "Que el historial de cambios (redo) se archive y esté duplicado, para poder reconstruir lo ocurrido.", "Activar ARCHIVELOG y multiplexar los grupos de redo log."),
("A8.2", "Acceso privilegiado (ANY)", ["SELECT grantee, privilege FROM dba_sys_privs WHERE privilege LIKE '%ANY%' AND grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained='Y') AND grantee NOT IN (SELECT role FROM dba_roles WHERE oracle_maintained='Y')"],
 lambda r: (max(0, 1 - len(r[0]) / 5), f"{len(r[0])} privilegios ANY concedidos a cuentas o roles no administrativos."),
 "Que las aplicaciones no tengan privilegios que sirvan sobre cualquier esquema.", "Reemplazar los privilegios ANY por permisos concretos sobre los objetos necesarios."),
("A8.3", "Restricción de acceso a la información", ["SELECT policy_name FROM dba_policies WHERE enable='YES' AND object_owner=:s"],
 lambda r: (1.0 if r[0] else 0.0, f"{len(r[0])} política(s) de seguridad por fila activas en el esquema."),
 "Que cada usuario vea solo las filas que le corresponden (VPD).", "Crear políticas con DBMS_RLS.ADD_POLICY sobre las tablas sensibles."),
("A8.5", "Autenticación segura", ["SELECT d.username, u.account_status FROM dba_users_with_defpwd d JOIN dba_users u ON u.username=d.username"],
 lambda r: (lambda o: (0.0 if o else 1.0, f"{len(o)} cuenta(s) abiertas con la contraseña por defecto."))([x for x in r[0] if x[1] == "OPEN"]),
 "Que ninguna cuenta abierta use la contraseña que trae Oracle de fábrica.", "Cambiar la contraseña o bloquear la cuenta."),
("A8.10", "Eliminación de información", ["SELECT COUNT(*) FROM dba_recyclebin"],
 lambda r: (1.0 if r[0][0][0] == 0 else 0.5 if r[0][0][0] <= 10 else 0.0, f"{r[0][0][0]} objeto(s) eliminados siguen recuperables en la papelera."),
 "Que lo que se borra no pueda recuperarse por la papelera de reciclaje.", "Usar DROP TABLE ... PURGE para datos sensibles y ejecutar PURGE DBA_RECYCLEBIN."),
("A8.11", "Enmascaramiento de datos", ["SELECT column_name FROM redaction_columns WHERE object_owner=:s"],
 lambda r: (1.0 if r[0] else 0.0, f"{len(r[0])} columna(s) con redacción activa."),
 "Que los datos sensibles se muestren ocultos a quien no debe verlos.", "Crear políticas con DBMS_REDACT.ADD_POLICY y enmascarar los clones de DEV/TEST."),
("A8.12", "Cifrado en reposo (TDE)", ["SELECT status FROM v$encryption_wallet", "SELECT tablespace_name, encrypted FROM dba_tablespaces WHERE contents='PERMANENT' AND tablespace_name NOT IN ('SYSTEM','SYSAUX')"],
 lambda r: (0.5 * any(x[0] == "OPEN" for x in r[0]) + 0.5 * (ratio(sum(1 for x in r[1] if x[1] == "YES"), len(r[1])) or 0), f"Wallet: {', '.join(str(x[0]) for x in r[0]) or 'ninguno'}; {sum(1 for x in r[1] if x[1] == 'YES')} de {len(r[1])} tablespaces cifrados."),
 "Que los archivos de datos estén cifrados y no sirvan si alguien los roba.", "Configurar el wallet de TDE y cifrar los tablespaces con datos sensibles."),
("A8.13", "Copias de seguridad", ["SELECT status, start_time FROM v$rman_backup_job_details ORDER BY start_time DESC FETCH FIRST 5 ROWS ONLY"],
 lambda r: ((0.0, "No hay respaldos RMAN registrados.") if not r[0] else (lambda a: (1.0 if r[0][0][0] == "COMPLETED" and a <= 1 else 0.5 if r[0][0][0] == "COMPLETED" and a <= 7 else 0.0, f"Último respaldo: {r[0][0][0]}, hace {a} día(s)."))((now() - r[0][0][1]).days)),
 "Que existan respaldos recientes y exitosos.", "Programar respaldos con RMAN, cifrarlos y probar la restauración."),
("A8.15", "Registro de eventos (auditoría)", ["SELECT COUNT(*) FROM audit_unified_enabled_policies", "SELECT COUNT(*) FROM unified_audit_trail WHERE event_timestamp > SYSTIMESTAMP - INTERVAL '7' DAY"],
 lambda r: (0.5 * (r[0][0][0] > 0) + 0.5 * (r[1][0][0] > 0), f"{r[0][0][0]} política(s) de auditoría activas; {r[1][0][0]} evento(s) en 7 días."),
 "Que la base registre quién hizo qué y que haya eventos recientes.", "Activar políticas de auditoría unificada y enviarlas a un SIEM."),
("A8.20", "Seguridad de redes", ["SELECT network_service_banner FROM v$session_connect_info WHERE sid=SYS_CONTEXT('USERENV','SID')"],
 lambda r: (lambda t: (1.0 if re.search(r"AES|3DES|SSL|TLS|TCPS", t, re.I) else 0.0, "La conexión usa cifrado de red." if re.search(r"AES|3DES|SSL|TLS|TCPS", t, re.I) else "La conexión viaja sin cifrar."))(" ".join(str(x[0]) for x in r[0])),
 "Que lo que viaja entre el cliente y la base esté cifrado.", "Configurar SQLNET.ENCRYPTION_SERVER=REQUIRED en sqlnet.ora o usar TCPS."),
]



# --- Catalogo para las pantallas Consultas SQL y Riesgos y tareas ---
EVID = {
 "A5.12": {
  "obs": "Columnas sensibles etiquetadas con su nivel",
  "esp": "Cédula, tarjeta y salario aparecen como CONFIDENCIAL",
  "imp": "Etiquetar columnas con COMMENT 'CLASIF: ...' y mantener un inventario",
  "tool": "SQL Developer"
 },
 "A5.15": {
  "obs": "PUBLIC sin permisos sobre paquetes peligrosos",
  "esp": "0 filas, o excepción documentada",
  "imp": "REVOKE EXECUTE sobre UTL_* FROM PUBLIC y conceder solo a quien lo necesite",
  "tool": "SQL Developer"
 },
 "A5.16": {
  "obs": "Toda cuenta tiene responsable y las inactivas están bloqueadas",
  "esp": "Sin cuentas abiertas sin dueño",
  "imp": "Inventario de cuentas con dueño; ALTER USER ... ACCOUNT LOCK en inactivas",
  "tool": "SQL Developer"
 },
 "A5.17": {
  "obs": "Perfil con política de contraseñas",
  "esp": "Ningún perfil de usuario final con UNLIMITED; función de verificación asignada",
  "imp": "Perfiles con bloqueo tras 5 intentos, vida de clave 90 días y función de verificación",
  "tool": "SQL Developer"
 },
 "A5.18": {
  "obs": "Lista corta y justificada de quién tiene el rol DBA",
  "esp": "Solo cuentas administrativas, admin_option = NO",
  "imp": "Otorgar DBA solo a cuentas nominales y sin ADMIN OPTION",
  "tool": "SQL Developer"
 },
 "A5.33": {
  "obs": "Base en ARCHIVELOG con redo online protegido",
  "esp": "ARCHIVELOG; members >= 2 (en XE puede ser 1: justificar)",
  "imp": "ARCHIVELOG, multiplexar redo y restringir permisos de los archivos en el SO",
  "tool": "SQL Developer"
 },
 "A8.2": {
  "obs": "Sin privilegios ANY en cuentas de aplicación",
  "esp": "0 filas para usuarios de aplicación",
  "imp": "Reemplazar privilegios ANY por roles de mínimo privilegio",
  "tool": "SQL Developer"
 },
 "A8.3": {
  "obs": "Políticas de seguridad por fila activas",
  "esp": "Política con ENABLE = YES sobre tablas sensibles",
  "imp": "VPD con DBMS_RLS sobre tablas sensibles",
  "tool": "SQL Developer"
 },
 "A8.5": {
  "obs": "Ninguna cuenta con contraseña por defecto",
  "esp": "0 filas",
  "imp": "Cambiar la contraseña por defecto o bloquear la cuenta",
  "tool": "SQL Developer"
 },
 "A8.10": {
  "obs": "Sin objetos eliminados que sigan recuperables",
  "esp": "Papelera vacía",
  "imp": "DROP TABLE ... PURGE para datos sensibles y vaciar la papelera",
  "tool": "SQL Developer"
 },
 "A8.11": {
  "obs": "Columnas sensibles con redacción activa",
  "esp": "Columnas sensibles con función FULL o PARTIAL",
  "imp": "DBMS_REDACT.ADD_POLICY sobre cédula y tarjeta; clones DEV/TEST enmascarados",
  "tool": "SQL Developer"
 },
 "A8.12": {
  "obs": "Datos en reposo cifrados con wallet TDE abierto",
  "esp": "Wallet OPEN; tablespace de datos sensibles con ENCRYPTED = YES",
  "imp": "Wallet TDE y tablespaces cifrados; exports y respaldos cifrados",
  "tool": "SQL Developer"
 },
 "A8.13": {
  "obs": "Último respaldo RMAN exitoso y prueba de restauración",
  "esp": "COMPLETED en las últimas 24 horas",
  "imp": "RMAN programado, copia cifrada y restauración probada",
  "tool": "RMAN / SQL Developer"
 },
 "A8.15": {
  "obs": "Auditoría unificada activa con eventos recientes",
  "esp": "Políticas activas y eventos de login/DDL recientes",
  "imp": "Política de auditoría sobre privilegios y tablas sensibles; envío a SIEM",
  "tool": "SQL Developer"
 },
 "A8.20": {
  "obs": "Conexión con cifrado de red o TLS",
  "esp": "Aparece Encryption service o TCPS",
  "imp": "sqlnet.ora con SQLNET.ENCRYPTION_SERVER=REQUIRED, o listener TCPS",
  "tool": "SQL Developer"
 }
}
IP = [[4, 4], [5, 3], [4, 4], [5, 3], [4, 3]]  # (impacto, probabilidad) de cada riesgo
TAREAS = [["T01", "Gestión de usuarios", 0, "A5.16 / A5.18", "SELECT username, account_status FROM dba_users"], ["T02", "Gestión de privilegios y roles", 0, "A8.2", "SELECT * FROM dba_sys_privs; dba_role_privs"], ["T03", "Autenticación y perfiles", 1, "A5.17 / A8.5", "dba_profiles; dba_users_with_defpwd"], ["T04", "Cifrado TDE", 3, "A8.12", "SELECT * FROM v$encryption_wallet"], ["T05", "Masking y Data Redaction", 2, "A8.11", "SELECT * FROM redaction_columns"], ["T06", "Respaldos con RMAN", 2, "A8.13", "v$rman_backup_job_details; RMAN SHOW ALL"], ["T07", "Auditoría de acciones", 4, "A8.15", "SELECT * FROM unified_audit_trail"], ["T08", "Parcheo", 1, "A5.15 (+ A8.8 sugerido)", "SELECT * FROM dba_registry_sqlpatch"], ["T09", "Configuración del listener", 3, "A8.20", "lsnrctl status; sqlnet.ora"], ["T10", "Eliminación segura", 2, "A8.10", "SELECT * FROM dba_recyclebin"], ["T11", "Gestión de logs (redo, archive, LogMiner)", 4, "A5.33", "v$log; v$archived_log; v$logmnr_contents"], ["T12", "Clones DEV/TEST", 2, "A5.12", "Comparar CLIENTES vs CLIENTES_DEV"]]
SOD = [["Administrador de BD", "Crear usuarios, respaldos, parches", "Leer datos de negocio ni borrar su propio rastro", "Revocar SELECT ANY TABLE; auditar sus acciones"], ["Administrador de seguridad", "Privilegios, políticas y wallet", "Operar respaldos ni modificar datos", "Roles separados; clave del wallet en custodia distinta"], ["Auditor", "Leer la pista de auditoría (AUDIT_VIEWER)", "Modificar objetos ni conceder privilegios", "Usuario CONFI_AUD solo con lectura"], ["Desarrollo", "Objetos en DEV", "Acceder a PROD ni a datos reales en clones", "Clones enmascarados (CLIENTES_DEV)"]]
