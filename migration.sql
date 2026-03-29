-- === WHATWEB ===
ALTER TABLE whatweb_findings ADD COLUMN IF NOT EXISTS title         varchar(512);
ALTER TABLE whatweb_findings ADD COLUMN IF NOT EXISTS plugins_count integer;
ALTER TABLE whatweb_findings ADD COLUMN IF NOT EXISTS powered_by    varchar(256);
CREATE INDEX IF NOT EXISTS idx_whatweb_http_status ON whatweb_findings (http_status);
CREATE INDEX IF NOT EXISTS idx_whatweb_ip          ON whatweb_findings (ip);

-- === NMAP ===
ALTER TABLE nmap_findings ADD COLUMN IF NOT EXISTS ip         varchar(128);
ALTER TABLE nmap_findings ADD COLUMN IF NOT EXISTS port       integer;
ALTER TABLE nmap_findings ADD COLUMN IF NOT EXISTS service    varchar(128);
ALTER TABLE nmap_findings ADD COLUMN IF NOT EXISTS product    varchar(256);
ALTER TABLE nmap_findings ADD COLUMN IF NOT EXISTS version    varchar(128);
ALTER TABLE nmap_findings ADD COLUMN IF NOT EXISTS protocol   varchar(16);
ALTER TABLE nmap_findings ADD COLUMN IF NOT EXISTS open_ports integer;
ALTER TABLE nmap_findings ADD COLUMN IF NOT EXISTS error      text;
CREATE INDEX IF NOT EXISTS idx_nmap_ip      ON nmap_findings (ip);
CREATE INDEX IF NOT EXISTS idx_nmap_port    ON nmap_findings (port);
CREATE INDEX IF NOT EXISTS idx_nmap_service ON nmap_findings (service);

-- === NIKTO ===
ALTER TABLE nikto_findings ADD COLUMN IF NOT EXISTS host           varchar(256);
ALTER TABLE nikto_findings ADD COLUMN IF NOT EXISTS ip             varchar(128);
ALTER TABLE nikto_findings ADD COLUMN IF NOT EXISTS port           integer;
ALTER TABLE nikto_findings ADD COLUMN IF NOT EXISTS findings_count integer;
ALTER TABLE nikto_findings ADD COLUMN IF NOT EXISTS high           integer;
ALTER TABLE nikto_findings ADD COLUMN IF NOT EXISTS medium         integer;
ALTER TABLE nikto_findings ADD COLUMN IF NOT EXISTS low            integer;
ALTER TABLE nikto_findings ADD COLUMN IF NOT EXISTS error          text;
CREATE INDEX IF NOT EXISTS idx_nikto_ip   ON nikto_findings (ip);
CREATE INDEX IF NOT EXISTS idx_nikto_port ON nikto_findings (port);

-- === ZAP ===
ALTER TABLE zap_findings ADD COLUMN IF NOT EXISTS target      varchar(512);
ALTER TABLE zap_findings ADD COLUMN IF NOT EXISTS risk_high   integer;
ALTER TABLE zap_findings ADD COLUMN IF NOT EXISTS risk_medium integer;
ALTER TABLE zap_findings ADD COLUMN IF NOT EXISTS risk_low    integer;
ALTER TABLE zap_findings ADD COLUMN IF NOT EXISTS risk_info   integer;