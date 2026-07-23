package storage

import (
	"net"
	"time"

	"gorm.io/gorm"
)

// ConnectionDetail contains denormalized connection information for display
type ConnectionDetail struct {
	ID               uint
	Timestamp        time.Time
	IPAddress        string
	HASSHFingerprint string
	SSHClientBanner  string
	Blocked          bool
}

// HASSHSummary contains aggregated information about a HASSH fingerprint
type HASSHSummary struct {
	HASSHFingerprint string
	SSHClientBanner  string
	IPCount          int
	LastSeen         time.Time
	FirstSeen        time.Time
	TotalConnections int
	Blocked          bool
}

// IPAddress stores unique IP addresses in binary format
type IPAddress struct {
	ID        uint      `gorm:"primaryKey;column:id"`
	Version   uint8     `gorm:"column:version;not null;index:idx_ip_unique"`
	Address   []byte    `gorm:"column:address;uniqueIndex:idx_ip_unique;size:16;not null"`
	CreatedAt time.Time `gorm:"column:created_at;index;not null"`
}

func (IPAddress) TableName() string {
	return "ip_addresses"
}

// HASSHFingerprint stores unique HASSH fingerprints
//
// size:64 accommodates hex-encoded SHA-256 (64 chars); hex-encoded MD5 (32
// chars, the default used by hassh.Calculate) fits comfortably within it too.
// A 32-char column would silently truncate or fail to insert a SHA-256
// fingerprint produced via hassh.CalculateWithHash(..., hassh.HashSHA256),
// which is part of this package's public API even though the proxy's
// current call site only ever produces MD5 hashes.
type HASSHFingerprint struct {
	ID          uint      `gorm:"primaryKey;column:id"`
	Fingerprint string    `gorm:"column:fingerprint;uniqueIndex;size:64;not null"`
	CreatedAt   time.Time `gorm:"column:created_at;index;not null"`
}

func (HASSHFingerprint) TableName() string {
	return "hassh_fingerprints"
}

// SSHClientBanner stores unique SSH client banners
type SSHClientBanner struct {
	ID        uint      `gorm:"primaryKey;column:id"`
	Banner    string    `gorm:"column:banner;uniqueIndex;size:255;not null"`
	CreatedAt time.Time `gorm:"column:created_at;index;not null"`
}

func (SSHClientBanner) TableName() string {
	return "ssh_client_banners"
}

// BlockedFingerprint tracks which HASSH fingerprints are blocked
type BlockedFingerprint struct {
	ID                 uint             `gorm:"primaryKey;column:id"`
	HASSHFingerprintID uint             `gorm:"column:hassh_fingerprint_id;uniqueIndex;not null"`
	HASSHFingerprint   HASSHFingerprint `gorm:"foreignKey:HASSHFingerprintID;constraint:OnDelete:CASCADE"`
	BlockedAt          time.Time        `gorm:"column:blocked_at;index;not null"`
	Reason             string           `gorm:"column:reason;size:255"`
}

func (BlockedFingerprint) TableName() string {
	return "blocked_fingerprints"
}

// SSHConnection records connection events (fact table)
type SSHConnection struct {
	ID                 uint             `gorm:"primaryKey;column:id"`
	IPAddressID        uint             `gorm:"column:ip_address_id;index:idx_connection_composite;not null"`
	IPAddress          IPAddress        `gorm:"foreignKey:IPAddressID;constraint:OnDelete:RESTRICT"`
	HASSHFingerprintID uint             `gorm:"column:hassh_fingerprint_id;index:idx_connection_composite;not null"`
	HASSHFingerprint   HASSHFingerprint `gorm:"foreignKey:HASSHFingerprintID;constraint:OnDelete:RESTRICT"`
	SSHClientBannerID  uint             `gorm:"column:ssh_client_banner_id;index;not null"`
	SSHClientBanner    SSHClientBanner  `gorm:"foreignKey:SSHClientBannerID;constraint:OnDelete:RESTRICT"`
	Blocked            bool             `gorm:"column:blocked;index:idx_connection_composite;not null"`
	Timestamp          time.Time        `gorm:"column:timestamp;index:idx_connection_composite;not null"`
}

func (SSHConnection) TableName() string {
	return "ssh_connections"
}

// Repository handles database operations
type Repository struct {
	db *gorm.DB
}

// NewRepository initializes the database schema
func NewRepository(db *gorm.DB) (*Repository, error) {
	// Auto-migrate all tables in dependency order
	if err := db.AutoMigrate(
		&IPAddress{},
		&HASSHFingerprint{},
		&SSHClientBanner{},
		&BlockedFingerprint{},
		&SSHConnection{},
	); err != nil {
		return nil, err
	}

	// Create composite index for common query patterns
	db.Exec("CREATE INDEX IF NOT EXISTS idx_connection_lookup ON ssh_connections(hassh_fingerprint_id, ip_address_id, timestamp DESC)")

	return &Repository{db: db}, nil
}

// parseIP converts string IP to binary format and version
func parseIP(ipStr string) (version uint8, address []byte, err error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, nil, gorm.ErrInvalidData
	}

	// Check if IPv4
	if ip4 := ip.To4(); ip4 != nil {
		return 4, []byte(ip4), nil
	}

	// IPv6
	return 6, []byte(ip.To16()), nil
}

// ipToString converts binary IP back to string
func ipToString(version uint8, address []byte) string {
	if version == 4 && len(address) == 4 {
		return net.IP(address).String()
	}
	if version == 6 && len(address) == 16 {
		return net.IP(address).String()
	}
	return ""
}

// getOrCreateIPAddress finds or creates an IP address record
func (r *Repository) getOrCreateIPAddress(ipStr string) (*IPAddress, error) {
	version, address, err := parseIP(ipStr)
	if err != nil {
		return nil, err
	}

	var ipAddr IPAddress
	result := r.db.Where("version = ? AND address = ?", version, address).First(&ipAddr)

	if result.Error == gorm.ErrRecordNotFound {
		ipAddr = IPAddress{
			Version:   version,
			Address:   address,
			CreatedAt: time.Now(),
		}
		if err := r.db.Create(&ipAddr).Error; err != nil {
			return nil, err
		}
		return &ipAddr, nil
	}

	if result.Error != nil {
		return nil, result.Error
	}

	return &ipAddr, nil
}

// getOrCreateHASSH finds or creates a HASSH fingerprint record
func (r *Repository) getOrCreateHASSH(fingerprint string) (*HASSHFingerprint, error) {
	var hassh HASSHFingerprint
	result := r.db.Where("fingerprint = ?", fingerprint).First(&hassh)

	if result.Error == gorm.ErrRecordNotFound {
		hassh = HASSHFingerprint{
			Fingerprint: fingerprint,
			CreatedAt:   time.Now(),
		}
		if err := r.db.Create(&hassh).Error; err != nil {
			return nil, err
		}
		return &hassh, nil
	}

	if result.Error != nil {
		return nil, result.Error
	}

	return &hassh, nil
}

// getOrCreateBanner finds or creates an SSH client banner record
func (r *Repository) getOrCreateBanner(banner string) (*SSHClientBanner, error) {
	var bannerRecord SSHClientBanner
	result := r.db.Where("banner = ?", banner).First(&bannerRecord)

	if result.Error == gorm.ErrRecordNotFound {
		bannerRecord = SSHClientBanner{
			Banner:    banner,
			CreatedAt: time.Now(),
		}
		if err := r.db.Create(&bannerRecord).Error; err != nil {
			return nil, err
		}
		return &bannerRecord, nil
	}

	if result.Error != nil {
		return nil, result.Error
	}

	return &bannerRecord, nil
}

// maxBannerColumnLength mirrors the size:255 constraint on
// SSHClientBanner.Banner. Enforced here too (in addition to the proxy's own
// truncation in CaptureHandshake) so this repository is safe to call with an
// oversized banner from any caller, not just the one that happens to
// truncate today.
const maxBannerColumnLength = 255

// RecordConnection stores connection metadata
func (r *Repository) RecordConnection(ip, hassh, banner string, blocked bool) error {
	if len(banner) > maxBannerColumnLength {
		banner = banner[:maxBannerColumnLength]
	}

	return r.db.Transaction(func(tx *gorm.DB) error {
		// Get or create normalized records
		ipAddr, err := r.getOrCreateIPAddress(ip)
		if err != nil {
			return err
		}

		hasshRecord, err := r.getOrCreateHASSH(hassh)
		if err != nil {
			return err
		}

		bannerRecord, err := r.getOrCreateBanner(banner)
		if err != nil {
			return err
		}

		// Create connection event
		conn := SSHConnection{
			IPAddressID:        ipAddr.ID,
			HASSHFingerprintID: hasshRecord.ID,
			SSHClientBannerID:  bannerRecord.ID,
			Blocked:            blocked,
			Timestamp:          time.Now(),
		}

		return tx.Create(&conn).Error
	})
}

// LoadBlockedHashes retrieves all blocked HASSH fingerprints
func (r *Repository) LoadBlockedHashes() ([]string, error) {
	var fingerprints []string

	err := r.db.Model(&BlockedFingerprint{}).
		Joins("JOIN hassh_fingerprints ON hassh_fingerprints.id = blocked_fingerprints.hassh_fingerprint_id").
		Pluck("hassh_fingerprints.fingerprint", &fingerprints).Error

	return fingerprints, err
}

// ListConnections retrieves connections with filtering and sorting
func (r *Repository) ListConnections(limit int, blocked *bool, sortBy string, reverse bool) ([]ConnectionDetail, error) {
	type queryResult struct {
		ID               uint      `gorm:"column:id"`
		Timestamp        time.Time `gorm:"column:timestamp"`
		IPVersion        uint8     `gorm:"column:ip_version"`
		IPAddressBytes   []byte    `gorm:"column:ip_address_bytes"`
		HASSHFingerprint string    `gorm:"column:hassh_fingerprint"`
		SSHClientBanner  string    `gorm:"column:ssh_client_banner"`
		Blocked          bool      `gorm:"column:blocked"`
	}

	var results []queryResult

	query := r.db.Table("ssh_connections").
		Select(`
			ssh_connections.id as id,
			ssh_connections.timestamp as timestamp,
			ip_addresses.version as ip_version,
			ip_addresses.address as ip_address_bytes,
			hassh_fingerprints.fingerprint as hassh_fingerprint,
			ssh_client_banners.banner as ssh_client_banner,
			ssh_connections.blocked as blocked
		`).
		Joins("JOIN ip_addresses ON ip_addresses.id = ssh_connections.ip_address_id").
		Joins("JOIN hassh_fingerprints ON hassh_fingerprints.id = ssh_connections.hassh_fingerprint_id").
		Joins("JOIN ssh_client_banners ON ssh_client_banners.id = ssh_connections.ssh_client_banner_id")

	if blocked != nil {
		query = query.Where("ssh_connections.blocked = ?", *blocked)
	}

	// Map sortBy to actual column
	var orderColumn string
	switch sortBy {
	case "timestamp":
		orderColumn = "ssh_connections.timestamp"
	case "ip":
		orderColumn = "ip_addresses.address"
	case "hassh":
		orderColumn = "hassh_fingerprints.fingerprint"
	default:
		orderColumn = "ssh_connections.timestamp"
	}

	if reverse {
		orderColumn += " DESC"
	} else {
		orderColumn += " ASC"
	}

	query = query.Order(orderColumn)

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&results).Error; err != nil {
		return nil, err
	}

	details := make([]ConnectionDetail, len(results))
	for i, r := range results {
		details[i] = ConnectionDetail{
			ID:               r.ID,
			Timestamp:        r.Timestamp,
			IPAddress:        ipToString(r.IPVersion, r.IPAddressBytes),
			HASSHFingerprint: r.HASSHFingerprint,
			SSHClientBanner:  r.SSHClientBanner,
			Blocked:          r.Blocked,
		}
	}

	return details, nil
}

// GetConnectionHistory retrieves recent connections for an IP
func (r *Repository) GetConnectionHistory(ipStr string, limit int) ([]ConnectionDetail, error) {
	version, address, err := parseIP(ipStr)
	if err != nil {
		return nil, err
	}

	type queryResult struct {
		ID               uint      `gorm:"column:id"`
		Timestamp        time.Time `gorm:"column:timestamp"`
		IPVersion        uint8     `gorm:"column:ip_version"`
		IPAddressBytes   []byte    `gorm:"column:ip_address_bytes"`
		HASSHFingerprint string    `gorm:"column:hassh_fingerprint"`
		SSHClientBanner  string    `gorm:"column:ssh_client_banner"`
		Blocked          bool      `gorm:"column:blocked"`
	}

	var results []queryResult

	err = r.db.Table("ssh_connections").
		Select(`
			ssh_connections.id as id,
			ssh_connections.timestamp as timestamp,
			ip_addresses.version as ip_version,
			ip_addresses.address as ip_address_bytes,
			hassh_fingerprints.fingerprint as hassh_fingerprint,
			ssh_client_banners.banner as ssh_client_banner,
			ssh_connections.blocked as blocked
		`).
		Joins("JOIN ip_addresses ON ip_addresses.id = ssh_connections.ip_address_id").
		Joins("JOIN hassh_fingerprints ON hassh_fingerprints.id = ssh_connections.hassh_fingerprint_id").
		Joins("JOIN ssh_client_banners ON ssh_client_banners.id = ssh_connections.ssh_client_banner_id").
		Where("ip_addresses.version = ? AND ip_addresses.address = ?", version, address).
		Order("ssh_connections.timestamp DESC").
		Limit(limit).
		Find(&results).Error

	if err != nil {
		return nil, err
	}

	details := make([]ConnectionDetail, len(results))
	for i, r := range results {
		details[i] = ConnectionDetail{
			ID:               r.ID,
			Timestamp:        r.Timestamp,
			IPAddress:        ipToString(r.IPVersion, r.IPAddressBytes),
			HASSHFingerprint: r.HASSHFingerprint,
			SSHClientBanner:  r.SSHClientBanner,
			Blocked:          r.Blocked,
		}
	}

	return details, nil
}

// GetAllConnections retrieves recent connections across all IPs
func (r *Repository) GetAllConnections(limit int) ([]ConnectionDetail, error) {
	return r.ListConnections(limit, nil, "timestamp", true)
}

// SearchConnections searches connections by IP, HASSH, or banner
func (r *Repository) SearchConnections(ip, hassh, banner string, limit int) ([]ConnectionDetail, error) {
	type queryResult struct {
		ID               uint      `gorm:"column:id"`
		Timestamp        time.Time `gorm:"column:timestamp"`
		IPVersion        uint8     `gorm:"column:ip_version"`
		IPAddressBytes   []byte    `gorm:"column:ip_address_bytes"`
		HASSHFingerprint string    `gorm:"column:hassh_fingerprint"`
		SSHClientBanner  string    `gorm:"column:ssh_client_banner"`
		Blocked          bool      `gorm:"column:blocked"`
	}

	var results []queryResult

	query := r.db.Table("ssh_connections").
		Select(`
			ssh_connections.id as id,
			ssh_connections.timestamp as timestamp,
			ip_addresses.version as ip_version,
			ip_addresses.address as ip_address_bytes,
			hassh_fingerprints.fingerprint as hassh_fingerprint,
			ssh_client_banners.banner as ssh_client_banner,
			ssh_connections.blocked as blocked
		`).
		Joins("JOIN ip_addresses ON ip_addresses.id = ssh_connections.ip_address_id").
		Joins("JOIN hassh_fingerprints ON hassh_fingerprints.id = ssh_connections.hassh_fingerprint_id").
		Joins("JOIN ssh_client_banners ON ssh_client_banners.id = ssh_connections.ssh_client_banner_id")

	if ip != "" {
		query = query.Where("ip_addresses.address LIKE ?", "%"+ip+"%")
	}

	if hassh != "" {
		query = query.Where("hassh_fingerprints.fingerprint LIKE ?", "%"+hassh+"%")
	}

	if banner != "" {
		query = query.Where("ssh_client_banners.banner LIKE ?", "%"+banner+"%")
	}

	query = query.Order("ssh_connections.timestamp DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&results).Error; err != nil {
		return nil, err
	}

	details := make([]ConnectionDetail, len(results))
	for i, r := range results {
		details[i] = ConnectionDetail{
			ID:               r.ID,
			Timestamp:        r.Timestamp,
			IPAddress:        ipToString(r.IPVersion, r.IPAddressBytes),
			HASSHFingerprint: r.HASSHFingerprint,
			SSHClientBanner:  r.SSHClientBanner,
			Blocked:          r.Blocked,
		}
	}

	return details, nil
}

// BlockHASH marks a fingerprint as blocked
func (r *Repository) BlockHASH(hassh, reason string) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		// Get or create the HASSH fingerprint
		hasshRecord, err := r.getOrCreateHASSH(hassh)
		if err != nil {
			return err
		}

		// Check if already blocked
		var existing BlockedFingerprint
		result := tx.Where("hassh_fingerprint_id = ?", hasshRecord.ID).First(&existing)

		if result.Error == nil {
			// Already blocked, just return
			return nil
		}

		if result.Error != gorm.ErrRecordNotFound {
			return result.Error
		}

		// Create block record
		blocked := BlockedFingerprint{
			HASSHFingerprintID: hasshRecord.ID,
			BlockedAt:          time.Now(),
			Reason:             reason,
		}

		return tx.Create(&blocked).Error
	})
}

// UnblockHASH removes a fingerprint from the blocklist
func (r *Repository) UnblockHASH(hassh string) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		// Find the HASSH fingerprint
		var hasshRecord HASSHFingerprint
		if err := tx.Where("fingerprint = ?", hassh).First(&hasshRecord).Error; err != nil {
			return err
		}

		// Delete the block record
		return tx.Where("hassh_fingerprint_id = ?", hasshRecord.ID).
			Delete(&BlockedFingerprint{}).Error
	})
}

// GetBlockedFingerprints retrieves all blocked fingerprints with metadata
func (r *Repository) GetBlockedFingerprints() ([]struct {
	Fingerprint string
	BlockedAt   time.Time
	Reason      string
}, error) {
	var results []struct {
		Fingerprint string
		BlockedAt   time.Time
		Reason      string
	}

	err := r.db.Model(&BlockedFingerprint{}).
		Select("hassh_fingerprints.fingerprint, blocked_fingerprints.blocked_at, blocked_fingerprints.reason").
		Joins("JOIN hassh_fingerprints ON hassh_fingerprints.id = blocked_fingerprints.hassh_fingerprint_id").
		Order("blocked_fingerprints.blocked_at DESC").
		Find(&results).Error

	return results, err
}

// GetStatistics retrieves connection statistics
func (r *Repository) GetStatistics() (struct {
	TotalConnections   int64
	BlockedConnections int64
	UniqueIPs          int64
	UniqueFingerprints int64
	UniqueBanners      int64
}, error) {
	var stats struct {
		TotalConnections   int64
		BlockedConnections int64
		UniqueIPs          int64
		UniqueFingerprints int64
		UniqueBanners      int64
	}

	r.db.Model(&SSHConnection{}).Count(&stats.TotalConnections)
	r.db.Model(&SSHConnection{}).Where("blocked = ?", true).Count(&stats.BlockedConnections)
	r.db.Model(&IPAddress{}).Count(&stats.UniqueIPs)
	r.db.Model(&HASSHFingerprint{}).Count(&stats.UniqueFingerprints)
	r.db.Model(&SSHClientBanner{}).Count(&stats.UniqueBanners)

	return stats, nil
}

// ListHASSHSummaries retrieves aggregated HASSH fingerprint information
func (r *Repository) ListHASSHSummaries(limit int, blocked *bool, sortBy string, reverse bool) ([]HASSHSummary, error) {
	type queryResult struct {
		HASSHFingerprint string `gorm:"column:hassh_fingerprint"`
		SSHClientBanner  string `gorm:"column:ssh_client_banner"`
		IPCount          int    `gorm:"column:ip_count"`
		LastSeen         string `gorm:"column:last_seen"`
		FirstSeen        string `gorm:"column:first_seen"`
		TotalConnections int    `gorm:"column:total_connections"`
		IsBlocked        int    `gorm:"column:is_blocked"`
	}

	var results []queryResult

	query := r.db.Table("ssh_connections").
		Select(`
			hassh_fingerprints.fingerprint as hassh_fingerprint,
			ssh_client_banners.banner as ssh_client_banner,
			COUNT(DISTINCT ip_addresses.address) as ip_count,
			MAX(ssh_connections.timestamp) as last_seen,
			MIN(ssh_connections.timestamp) as first_seen,
			COUNT(*) as total_connections,
			CASE WHEN blocked_fingerprints.id IS NOT NULL THEN 1 ELSE 0 END as is_blocked
		`).
		Joins("JOIN ip_addresses ON ip_addresses.id = ssh_connections.ip_address_id").
		Joins("JOIN hassh_fingerprints ON hassh_fingerprints.id = ssh_connections.hassh_fingerprint_id").
		Joins("JOIN ssh_client_banners ON ssh_client_banners.id = ssh_connections.ssh_client_banner_id").
		Joins("LEFT JOIN blocked_fingerprints ON blocked_fingerprints.hassh_fingerprint_id = hassh_fingerprints.id").
		Group("hassh_fingerprints.fingerprint, ssh_client_banners.banner, blocked_fingerprints.id")

	if blocked != nil {
		if *blocked {
			query = query.Having("is_blocked = 1")
		} else {
			query = query.Having("is_blocked = 0")
		}
	}

	// Map sortBy to actual column
	var orderColumn string
	switch sortBy {
	case "last_seen":
		orderColumn = "last_seen"
	case "ip_count":
		orderColumn = "ip_count"
	case "total":
		orderColumn = "total_connections"
	case "hassh":
		orderColumn = "hassh_fingerprint"
	case "banner":
		orderColumn = "ssh_client_banner"
	default:
		orderColumn = "last_seen"
	}

	if reverse {
		orderColumn += " DESC"
	} else {
		orderColumn += " ASC"
	}

	query = query.Order(orderColumn)

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&results).Error; err != nil {
		return nil, err
	}

	// Convert results to HASSHSummary with proper time parsing
	summaries := make([]HASSHSummary, len(results))
	for i, r := range results {
		lastSeen, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", r.LastSeen)
		if err != nil {
			lastSeen, err = time.Parse("2006-01-02 15:04:05", r.LastSeen)
			if err != nil {
				lastSeen = time.Time{}
			}
		}

		firstSeen, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", r.FirstSeen)
		if err != nil {
			firstSeen, err = time.Parse("2006-01-02 15:04:05", r.FirstSeen)
			if err != nil {
				firstSeen = time.Time{}
			}
		}

		summaries[i] = HASSHSummary{
			HASSHFingerprint: r.HASSHFingerprint,
			SSHClientBanner:  r.SSHClientBanner,
			IPCount:          r.IPCount,
			LastSeen:         lastSeen,
			FirstSeen:        firstSeen,
			TotalConnections: r.TotalConnections,
			Blocked:          r.IsBlocked == 1,
		}
	}

	return summaries, nil
}

// SearchHASSHSummaries searches HASSH summaries
func (r *Repository) SearchHASSHSummaries(hassh, banner string, limit int) ([]HASSHSummary, error) {
	type queryResult struct {
		HASSHFingerprint string `gorm:"column:hassh_fingerprint"`
		SSHClientBanner  string `gorm:"column:ssh_client_banner"`
		IPCount          int    `gorm:"column:ip_count"`
		LastSeen         string `gorm:"column:last_seen"`
		FirstSeen        string `gorm:"column:first_seen"`
		TotalConnections int    `gorm:"column:total_connections"`
		IsBlocked        int    `gorm:"column:is_blocked"`
	}

	var results []queryResult

	query := r.db.Table("ssh_connections").
		Select(`
			hassh_fingerprints.fingerprint as hassh_fingerprint,
			ssh_client_banners.banner as ssh_client_banner,
			COUNT(DISTINCT ip_addresses.address) as ip_count,
			MAX(ssh_connections.timestamp) as last_seen,
			MIN(ssh_connections.timestamp) as first_seen,
			COUNT(*) as total_connections,
			CASE WHEN blocked_fingerprints.id IS NOT NULL THEN 1 ELSE 0 END as is_blocked
		`).
		Joins("JOIN ip_addresses ON ip_addresses.id = ssh_connections.ip_address_id").
		Joins("JOIN hassh_fingerprints ON hassh_fingerprints.id = ssh_connections.hassh_fingerprint_id").
		Joins("JOIN ssh_client_banners ON ssh_client_banners.id = ssh_connections.ssh_client_banner_id").
		Joins("LEFT JOIN blocked_fingerprints ON blocked_fingerprints.hassh_fingerprint_id = hassh_fingerprints.id").
		Group("hassh_fingerprints.fingerprint, ssh_client_banners.banner, blocked_fingerprints.id")

	if hassh != "" {
		query = query.Where("hassh_fingerprints.fingerprint LIKE ?", "%"+hassh+"%")
	}

	if banner != "" {
		query = query.Where("ssh_client_banners.banner LIKE ?", "%"+banner+"%")
	}

	query = query.Order("last_seen DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	if err := query.Find(&results).Error; err != nil {
		return nil, err
	}

	// Convert results to HASSHSummary with proper time parsing
	summaries := make([]HASSHSummary, len(results))
	for i, r := range results {
		lastSeen, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", r.LastSeen)
		if err != nil {
			lastSeen, err = time.Parse("2006-01-02 15:04:05", r.LastSeen)
			if err != nil {
				lastSeen = time.Time{}
			}
		}

		firstSeen, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", r.FirstSeen)
		if err != nil {
			firstSeen, err = time.Parse("2006-01-02 15:04:05", r.FirstSeen)
			if err != nil {
				firstSeen = time.Time{}
			}
		}

		summaries[i] = HASSHSummary{
			HASSHFingerprint: r.HASSHFingerprint,
			SSHClientBanner:  r.SSHClientBanner,
			IPCount:          r.IPCount,
			LastSeen:         lastSeen,
			FirstSeen:        firstSeen,
			TotalConnections: r.TotalConnections,
			Blocked:          r.IsBlocked == 1,
		}
	}

	return summaries, nil
}
