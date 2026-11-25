-- Each account network is served by its own server-side easytier-core with its own
-- public listener port (the topology validated in spikes/easytier).
ALTER TABLE et_networks ADD COLUMN listen_port SMALLINT UNSIGNED NULL;
ALTER TABLE et_networks ADD UNIQUE KEY uq_et_networks_listen_port (listen_port);
