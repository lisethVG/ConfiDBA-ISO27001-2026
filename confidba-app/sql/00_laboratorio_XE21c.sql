-- ConfiDBA: laboratorio de confidencialidad (Oracle 21c XE - XEPDB1)
-- Ejecutar conectado como SYS AS SYSDBA a la PDB XEPDB1
-- Ejemplo: sqlplus sys/Oracle123@localhost:1521/XEPDB1 as sysdba

SET DEFINE OFF
SET ECHO ON

-- ============================================================
-- 0. Limpieza (si ya se habia corrido antes)
-- ============================================================
BEGIN
  EXECUTE IMMEDIATE 'DROP USER confi_lab CASCADE';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
BEGIN
  EXECUTE IMMEDIATE 'DROP USER confi_aud CASCADE';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
BEGIN
  EXECUTE IMMEDIATE 'NOAUDIT POLICY confi_pol_datos';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
BEGIN
  EXECUTE IMMEDIATE 'NOAUDIT POLICY confi_pol_admin';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
BEGIN
  EXECUTE IMMEDIATE 'DROP AUDIT POLICY confi_pol_datos';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
BEGIN
  EXECUTE IMMEDIATE 'DROP AUDIT POLICY confi_pol_admin';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

-- ============================================================
-- 1. Usuarios con separacion de funciones
-- ============================================================
CREATE USER confi_lab IDENTIFIED BY Lab2026Seg
  DEFAULT TABLESPACE users
  QUOTA 20M ON users;

CREATE USER confi_aud IDENTIFIED BY Aud2026Seg
  DEFAULT TABLESPACE users
  QUOTA 5M ON users;

GRANT CREATE SESSION, CREATE TABLE, CREATE TRIGGER TO confi_lab;
GRANT CREATE SESSION, CREATE TABLE TO confi_aud;

BEGIN
  EXECUTE IMMEDIATE 'GRANT AUDIT_VIEWER TO confi_aud';
EXCEPTION WHEN OTHERS THEN
  DBMS_OUTPUT.PUT_LINE('Nota: AUDIT_VIEWER no disponible o ya otorgado');
END;
/

-- ============================================================
-- 2. Datos de prueba y clasificacion (A5.12)
-- ============================================================
CREATE TABLE confi_lab.clientes (
  id        NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cedula    VARCHAR2(15),
  nombre    VARCHAR2(60),
  tarjeta   VARCHAR2(19),
  salario   NUMBER(10,2)
);

INSERT INTO confi_lab.clientes (cedula, nombre, tarjeta, salario)
VALUES ('1-1111-1111', 'Ana Mora', '4111-1111-1111-1111', 850000);
INSERT INTO confi_lab.clientes (cedula, nombre, tarjeta, salario)
VALUES ('2-2222-2222', 'Luis Solano', '5500-0000-0000-0004', 920000);
INSERT INTO confi_lab.clientes (cedula, nombre, tarjeta, salario)
VALUES ('3-3333-3333', 'Marta Rojas', '3400-0000-0000-009', 1100000);
COMMIT;

COMMENT ON COLUMN confi_lab.clientes.cedula  IS 'CLASIF: CONFIDENCIAL - dato personal (Ley 8968)';
COMMENT ON COLUMN confi_lab.clientes.tarjeta IS 'CLASIF: CONFIDENCIAL - dato financiero';
COMMENT ON COLUMN confi_lab.clientes.salario IS 'CLASIF: CONFIDENCIAL - dato financiero';

-- ============================================================
-- 3. Clon DEV/TEST enmascarado (A8.11, A5.12)
-- ============================================================
CREATE TABLE confi_lab.clientes_dev AS
SELECT id,
       'X-XXXX-' || SUBSTR(cedula, -4) AS cedula,
       'Cliente ' || id AS nombre,
       'XXXX-XXXX-XXXX-' || SUBSTR(tarjeta, -4) AS tarjeta,
       0 AS salario
FROM confi_lab.clientes;

-- ============================================================
-- 4. Auditoria por trigger en otro esquema (segregacion)
-- ============================================================
CREATE TABLE confi_aud.aud_clientes (
  aud_id           NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  fecha            TIMESTAMP DEFAULT SYSTIMESTAMP,
  usuario          VARCHAR2(128),
  operacion        VARCHAR2(10),
  id_cliente       NUMBER,
  salario_antes    NUMBER,
  salario_despues  NUMBER
);

GRANT INSERT ON confi_aud.aud_clientes TO confi_lab;

CREATE OR REPLACE TRIGGER confi_lab.trg_aud_clientes
AFTER INSERT OR UPDATE OR DELETE ON confi_lab.clientes
FOR EACH ROW
BEGIN
  INSERT INTO confi_aud.aud_clientes (usuario, operacion, id_cliente, salario_antes, salario_despues)
  VALUES (
    SYS_CONTEXT('USERENV', 'SESSION_USER'),
    CASE
      WHEN INSERTING THEN 'INSERT'
      WHEN UPDATING  THEN 'UPDATE'
      ELSE 'DELETE'
    END,
    COALESCE(:NEW.id, :OLD.id),
    :OLD.salario,
    :NEW.salario
  );
END;
/

-- ============================================================
-- 5. Auditoria unificada (A8.15)
-- ============================================================
CREATE AUDIT POLICY confi_pol_datos ACTIONS SELECT ON confi_lab.clientes, UPDATE ON confi_lab.clientes, DELETE ON confi_lab.clientes;
CREATE AUDIT POLICY confi_pol_admin ACTIONS CREATE USER, ALTER USER, DROP USER, GRANT, REVOKE;
AUDIT POLICY confi_pol_datos;
AUDIT POLICY confi_pol_admin;

-- ============================================================
-- 6. Prueba de trazabilidad: un cambio y las dos pistas
-- ============================================================
UPDATE confi_lab.clientes SET salario = salario + 1 WHERE id = 1;
COMMIT;
SELECT * FROM confi_aud.aud_clientes;
SELECT event_timestamp, dbusername, action_name, object_name
FROM unified_audit_trail WHERE object_name = 'CLIENTES' ORDER BY event_timestamp DESC;
-- Para LogMiner use la seccion 7 de 00_laboratorio.sql
