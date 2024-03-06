\c mosip_toolkit 

GRANT CONNECT
   ON DATABASE mosip_toolkit
   TO toolkituser;

GRANT USAGE
   ON SCHEMA toolkit
   TO toolkituser;

GRANT SELECT,CREATE,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES
   ON ALL TABLES IN SCHEMA toolkit
   TO toolkituser;

ALTER DEFAULT PRIVILEGES IN SCHEMA toolkit 
	GRANT SELECT,INSERT,UPDATE,DELETE,REFERENCES ON TABLES TO toolkituser;

