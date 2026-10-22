package cloudflare_ech

// ECHStats 包含 cloudflare_ech 模块内部各类连接池与缓存的详细指标。
type ECHStats struct {
	RouteCacheCount int               `json:"route_cache_count"`
	Routes          map[string]string `json:"routes,omitempty"`
	IPCacheCount    int               `json:"ip_cache_count"`
	UTLSH2Count     int               `json:"utls_h2_count"`
	UTLSH2Keys      []string          `json:"utls_h2_keys,omitempty"`
	UTLSH1Count     int               `json:"utls_h1_count"`
	UTLSH1Keys      []string          `json:"utls_h1_keys,omitempty"`
	DirectClients   int               `json:"direct_clients"`
	ECHClients      int               `json:"ech_clients"`
	ECHConfigs      int               `json:"ech_configs"`
}

// CollectStats 线程安全地快照 cloudflare_ech 模块各级缓存与连接池状态。
func CollectStats() ECHStats {
	st := ECHStats{
		Routes: make(map[string]string),
	}

	routeMu.RLock()
	st.RouteCacheCount = len(routes)
	for h, e := range routes {
		st.Routes[h] = e.mode
	}
	routeMu.RUnlock()

	ipCacheMu.Lock()
	st.IPCacheCount = len(ipCache)
	ipCacheMu.Unlock()

	utlsTransMu.Lock()
	st.UTLSH2Count = len(utlsH2Trans)
	for k := range utlsH2Trans {
		st.UTLSH2Keys = append(st.UTLSH2Keys, k)
	}
	st.UTLSH1Count = len(utlsH1Clients)
	for k := range utlsH1Clients {
		st.UTLSH1Keys = append(st.UTLSH1Keys, k)
	}
	utlsTransMu.Unlock()

	directClientMu.Lock()
	st.DirectClients = len(directClients)
	directClientMu.Unlock()

	clientsMu.Lock()
	st.ECHClients = len(clients)
	clientsMu.Unlock()

	cacheMu.Lock()
	st.ECHConfigs = len(cache)
	cacheMu.Unlock()

	return st
}
