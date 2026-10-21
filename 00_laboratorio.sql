-- ConfiDBA: laboratorio de confidencialidad y trazabilidad (Oracle 19c/21c XE)
-- Pensado para Oracle 23ai Free (PDB FREEPDB1); en XE 19c/21c la PDB es XEPDB1.
-- Ejecutar como SYS (o SYSTEM) conectado a la PDB, por ejemplo: CONNECT sys@localhost:1521/FREEPDB1 AS SYSDBA
-- Cambie las contraseñas de ejemplo antes de usar.

-- 1. Usuarios con funciones separadas
CREATE USER confi_lab IDENTIFIED BY "Lab#2026_Seg" QUOTA 20M ON users;   -- dueño de los datos
CREATE USER confi_aud IDENTIFIED BY "Aud#2026_Seg" QUOTA 5M ON users;    -- dueño de la pista de auditoría
GRANT CREATE SESSION, CREATE TABLE, CREATE TRIGGER TO confi_lab;
GRANT CREATE SESSION, CREATE TABLE TO confi_aud;
GRANT AUDIT_VIEWER TO confi_aud;

-- 2. Datos de prueba y clasificación (A5.12)
CREATE TABLE confi_lab.clientes (
  id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cedula VARCHAR2(15), nombre VARCHAR2(60), tarjeta VARCHAR2(19), salario NUMBER(10,2));
INSERT INTO confi_lab.clientes (cedula, nombre, tarjeta, salario) VALUES ('1-1111-1111','Ana Mora','4111-1111-1111-1111',850000);
INSERT INTO confi_lab.clientes (cedula, nombre, tarjeta, salario) VALUES ('2-2222-2222','Luis Solano','5500-0000-0000-0004',920000);
INSERT INTO confi_lab.clientes (cedula, nombre, tarjeta, salario) VALUES ('3-3333-3333','Marta Rojas','3400-0000-0000-009',1100000);
COMMIT;
COMMENT ON COLUMN confi_lab.clientes.cedula  IS 'CLASIF: CONFIDENCIAL - dato personal (Ley 8968)';
COMMENT ON COLUMN confi_lab.clientes.tarjeta IS 'CLASIF: CONFIDENCIAL - dato financiero';
COMMENT ON COLUMN confi_lab.clientes.salario IS 'CLASIF: CONFIDENCIAL - dato financiero';

-- 3. Clon para DEV/TEST enmascarado (A8.11, A5.12)
CREATE TABLE confi_lab.clientes_dev AS
SELECT id, 'X-XXXX-' || SUBSTR(cedula,-4) AS cedula, 'Cliente ' || id AS nombre,
       'XXXX-XXXX-XXXX-' || SUBSTR(tarjeta,-4) AS tarjeta, 0 AS salario
FROM confi_lab.clientes;

-- 4. Trazabilidad con trigger y tabla de auditoría fuera del esquema de datos (segregación de funciones)
CREATE TABLE confi_aud.aud_clientes (
  aud_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  fecha TIMESTAMP DEFAULT SYSTIMESTAMP, usuario VARCHAR2(128), operacion VARCHAR2(10),
  id_cliente NUMBER, salario_antes NUMBER, salario_despues NUMBER);
GRANT INSERT ON confi_aud.aud_clientes TO confi_lab;   -- solo inserta; no puede modificar ni borrar su rastro

CREATE OR REPLACE TRIGGER confi_lab.trg_aud_clientes
AFTER INSERT OR UPDATE OR DELETE ON confi_lab.clientes
FOR EACH ROW
BEGIN
  INSERT INTO confi_aud.aud_clientes (usuario, operacion, id_cliente, salario_antes, salario_despues)
  VALUES (SYS_CONTEXT('USERENV','SESSION_USER'),
          CASE WHEN INSERTING THEN 'INSERT' WHEN UPDATING THEN 'UPDATE' ELSE 'DELETE' END,
          COALESCE(:NEW.id, :OLD.id), :OLD.salario, :NEW.salario);
END;
/

-- 5. Auditoría unificada (A8.15)
CREATE AUDIT POLICY confi_pol_datos ACTIONS SELECT ON confi_lab.clientes, UPDATE ON confi_lab.clientes, DELETE ON confi_lab.clientes;
CREATE AUDIT POLICY confi_pol_admin ACTIONS CREATE USER, ALTER USER, DROP USER, GRANT, REVOKE;
AUDIT POLICY confi_pol_datos;
AUDIT POLICY confi_pol_admin;

-- 6. Prueba de trazabilidad: haga un cambio y revise las tres pistas
UPDATE confi_lab.clientes SET salario = salario + 1 WHERE id = 1;
COMMIT;
SELECT * FROM confi_aud.aud_clientes;                                        -- trigger
SELECT event_timestamp, dbusername, action_name, object_name
FROM unified_audit_trail WHERE object_name = 'CLIENTES' ORDER BY event_timestamp DESC;   -- AUDIT

-- 7. Redo log y LogMiner (abrir los redo para ver quién cambió qué)
SELECT member FROM v$logfile;
-- Reemplace la ruta por un miembro del redo actual (v$log con STATUS = 'CURRENT').
-- Si falla dentro de la PDB, repita desde CDB$ROOT.
BEGIN
  DBMS_LOGMNR.ADD_LOGFILE(LOGFILENAME => '&ruta_redo', OPTIONS => DBMS_LOGMNR.NEW);
  DBMS_LOGMNR.START_LOGMNR(OPTIONS => DBMS_LOGMNR.DICT_FROM_ONLINE_CATALOG);
END;
/
SELECT username, operation, sql_redo FROM v$logmnr_contents WHERE seg_owner = 'CONFI_LAB' AND table_name = 'CLIENTES';
EXEC DBMS_LOGMNR.END_LOGMNR;

-- 8. Limpieza (opcional)
-- NOEXECUTE POLICY: NOAUDIT POLICY confi_pol_datos; NOAUDIT POLICY confi_pol_admin; DROP AUDIT POLICY ...;
-- DROP USER confi_lab CASCADE; DROP USER confi_aud CASCADE;
