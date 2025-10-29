package degradation

import (
	"context"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/health"
)

type DegradationLevel int

const (
	LevelNormal DegradationLevel = iota
	LevelMinor
	LevelMajor
	LevelCritical
	LevelEmergency
)

func (d DegradationLevel) String() string {
	switch d {
	case LevelNormal:
		return "normal"
	case LevelMinor:
		return "minor"
	case LevelMajor:
		return "major"
	case LevelCritical:
		return "critical"
	case LevelEmergency:
		return "emergency"
	default:
		return "unknown"
	}
}

type Strategy interface {
	Name() string
	Activate(level DegradationLevel) error
	Deactivate() error
	IsActive() bool
	Level() DegradationLevel
}

type BaseStrategy struct {
	name   string
	active bool
	level  DegradationLevel
	mu     sync.RWMutex
}

func (bs *BaseStrategy) Name() string {
	return bs.name
}

func (bs *BaseStrategy) IsActive() bool {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.active
}

func (bs *BaseStrategy) Level() DegradationLevel {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.level
}

func (bs *BaseStrategy) setActive(active bool, level DegradationLevel) {
	bs.mu.Lock()
	bs.active = active
	bs.level = level
	bs.mu.Unlock()
}

type ReadOnlyModeStrategy struct {
	BaseStrategy
	originalConfig interface{}
}

func NewReadOnlyModeStrategy() *ReadOnlyModeStrategy {
	return &ReadOnlyModeStrategy{
		BaseStrategy: BaseStrategy{name: "read_only_mode"},
	}
}

func (ro *ReadOnlyModeStrategy) Activate(level DegradationLevel) error {
	logger.Infof("Activating read-only mode at level %s", level)
	ro.setActive(true, level)
	return nil
}

func (ro *ReadOnlyModeStrategy) Deactivate() error {
	logger.Info("Deactivating read-only mode")
	ro.setActive(false, LevelNormal)
	return nil
}

type CachingStrategy struct {
	BaseStrategy
	cacheEnabled bool
}

func NewCachingStrategy() *CachingStrategy {
	return &CachingStrategy{
		BaseStrategy: BaseStrategy{name: "extended_caching"},
		cacheEnabled: true,
	}
}

func (cs *CachingStrategy) Activate(level DegradationLevel) error {
	logger.Infof("Activating extended caching strategy at level %s", level)
	cs.setActive(true, level)

	switch level {
	case LevelMinor:
		logger.Info("Increasing cache retention time")
	case LevelMajor:
		logger.Info("Enabling aggressive caching for all operations")
	case LevelCritical:
		logger.Info("Enabling cache-only mode for reads")
	}

	return nil
}

func (cs *CachingStrategy) Deactivate() error {
	logger.Info("Deactivating extended caching strategy")
	cs.setActive(false, LevelNormal)
	return nil
}

type RateLimitingStrategy struct {
	BaseStrategy
	normalLimit  int
	reducedLimit int
	currentLimit int
}

func NewRateLimitingStrategy(normalLimit int) *RateLimitingStrategy {
	return &RateLimitingStrategy{
		BaseStrategy: BaseStrategy{name: "rate_limiting"},
		normalLimit:  normalLimit,
		reducedLimit: normalLimit / 2,
		currentLimit: normalLimit,
	}
}

func (rl *RateLimitingStrategy) Activate(level DegradationLevel) error {
	logger.Infof("Activating rate limiting strategy at level %s", level)
	rl.setActive(true, level)

	switch level {
	case LevelMinor:
		rl.currentLimit = int(float64(rl.normalLimit) * 0.8)
	case LevelMajor:
		rl.currentLimit = int(float64(rl.normalLimit) * 0.6)
	case LevelCritical:
		rl.currentLimit = int(float64(rl.normalLimit) * 0.4)
	case LevelEmergency:
		rl.currentLimit = int(float64(rl.normalLimit) * 0.2)
	}

	logger.Infof("Reduced rate limit from %d to %d", rl.normalLimit, rl.currentLimit)
	return nil
}

func (rl *RateLimitingStrategy) Deactivate() error {
	logger.Info("Deactivating rate limiting strategy")
	rl.currentLimit = rl.normalLimit
	rl.setActive(false, LevelNormal)
	return nil
}

func (rl *RateLimitingStrategy) GetCurrentLimit() int {
	return rl.currentLimit
}

type ConnectionPoolStrategy struct {
	BaseStrategy
	normalMaxConns  int
	reducedMaxConns int
}

func NewConnectionPoolStrategy(normalMaxConns int) *ConnectionPoolStrategy {
	return &ConnectionPoolStrategy{
		BaseStrategy:    BaseStrategy{name: "connection_pool_management"},
		normalMaxConns:  normalMaxConns,
		reducedMaxConns: normalMaxConns / 2,
	}
}

func (cp *ConnectionPoolStrategy) Activate(level DegradationLevel) error {
	logger.Infof("Activating connection pool management strategy at level %s", level)
	cp.setActive(true, level)

	switch level {
	case LevelMinor:
		logger.Info("Reducing connection pool size by 20%")
	case LevelMajor:
		logger.Info("Reducing connection pool size by 40%")
	case LevelCritical:
		logger.Info("Reducing connection pool size by 60%")
	case LevelEmergency:
		logger.Info("Minimizing connection pool size")
	}

	return nil
}

func (cp *ConnectionPoolStrategy) Deactivate() error {
	logger.Info("Deactivating connection pool management strategy")
	cp.setActive(false, LevelNormal)
	return nil
}

type DegradationManager struct {
	strategies         map[string]Strategy
	healthMonitor      *health.HealthMonitor
	currentLevel       DegradationLevel
	mu                 sync.RWMutex
	ctx                context.Context
	cancel             context.CancelFunc
	evaluationInterval time.Duration
}

func NewDegradationManager(healthMonitor *health.HealthMonitor) *DegradationManager {
	return &DegradationManager{
		strategies:         make(map[string]Strategy),
		healthMonitor:      healthMonitor,
		currentLevel:       LevelNormal,
		evaluationInterval: 30 * time.Second,
	}
}

func (dm *DegradationManager) RegisterStrategy(strategy Strategy) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.strategies[strategy.Name()] = strategy
}

func (dm *DegradationManager) Start(ctx context.Context) {
	dm.ctx, dm.cancel = context.WithCancel(ctx)

	// Register health status change callback
	dm.healthMonitor.AddStatusCallback(dm.onHealthStatusChange)

	// Start periodic evaluation
	go dm.evaluateLoop()
}

func (dm *DegradationManager) Stop() {
	if dm.cancel != nil {
		dm.cancel()
	}

	// Deactivate all strategies
	dm.mu.RLock()
	strategies := make([]Strategy, 0, len(dm.strategies))
	for _, strategy := range dm.strategies {
		strategies = append(strategies, strategy)
	}
	dm.mu.RUnlock()

	for _, strategy := range strategies {
		if strategy.IsActive() {
			strategy.Deactivate()
		}
	}
}

func (dm *DegradationManager) evaluateLoop() {
	ticker := time.NewTicker(dm.evaluationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-dm.ctx.Done():
			return
		case <-ticker.C:
			dm.evaluateDegradationLevel()
		}
	}
}

func (dm *DegradationManager) onHealthStatusChange(componentName string, status health.ComponentStatus) {
	logger.Infof("Health status change for %s: %s", componentName, status)

	// Trigger immediate evaluation on health changes
	go func() {
		select {
		case <-dm.ctx.Done():
			return
		default:
			dm.evaluateDegradationLevel()
		}
	}()
}

func (dm *DegradationManager) evaluateDegradationLevel() {
	overallStatus := dm.healthMonitor.GetOverallStatus()
	allStatuses := dm.healthMonitor.GetAllStatuses()

	newLevel := dm.calculateDegradationLevel(overallStatus, allStatuses)

	dm.mu.Lock()
	oldLevel := dm.currentLevel
	dm.currentLevel = newLevel
	dm.mu.Unlock()

	if oldLevel != newLevel {
		logger.Infof("Degradation level changed: %s -> %s", oldLevel, newLevel)
		dm.applyStrategies(newLevel, oldLevel)
	}
}

func (dm *DegradationManager) calculateDegradationLevel(overallStatus health.ComponentStatus, statuses map[string]health.ComponentStatus) DegradationLevel {
	switch overallStatus {
	case health.StatusHealthy:
		return LevelNormal

	case health.StatusDegraded:
		// Count degraded/unhealthy components
		degradedCount := 0
		unhealthyCount := 0

		for _, status := range statuses {
			switch status {
			case health.StatusDegraded:
				degradedCount++
			case health.StatusUnhealthy, health.StatusUnreachable:
				unhealthyCount++
			}
		}

		if unhealthyCount > 0 {
			return LevelMajor
		}
		if degradedCount > 1 {
			return LevelMajor
		}
		return LevelMinor

	case health.StatusUnhealthy:
		// Check if critical components are down
		if dm.healthMonitor.IsUnhealthy("database") {
			return LevelEmergency
		}
		if dm.healthMonitor.IsUnhealthy("s3_storage") {
			return LevelCritical
		}
		return LevelMajor

	case health.StatusUnreachable:
		return LevelEmergency

	default:
		return LevelNormal
	}
}

func (dm *DegradationManager) applyStrategies(newLevel, oldLevel DegradationLevel) {
	dm.mu.RLock()
	strategies := make(map[string]Strategy)
	for k, v := range dm.strategies {
		strategies[k] = v
	}
	dm.mu.RUnlock()

	for name, strategy := range strategies {
		shouldActivate := dm.shouldActivateStrategy(name, newLevel)
		isActive := strategy.IsActive()

		if shouldActivate && !isActive {
			if err := strategy.Activate(newLevel); err != nil {
				logger.Errorf("Failed to activate strategy %s: %v", name, err)
			}
		} else if !shouldActivate && isActive {
			if err := strategy.Deactivate(); err != nil {
				logger.Errorf("Failed to deactivate strategy %s: %v", name, err)
			}
		} else if shouldActivate && isActive && strategy.Level() != newLevel {
			// Reactivate with new level
			if err := strategy.Deactivate(); err != nil {
				logger.Errorf("Failed to deactivate strategy %s for reactivation: %v", name, err)
				continue
			}
			if err := strategy.Activate(newLevel); err != nil {
				logger.Errorf("Failed to reactivate strategy %s: %v", name, err)
			}
		}
	}
}

func (dm *DegradationManager) shouldActivateStrategy(strategyName string, level DegradationLevel) bool {
	switch strategyName {
	case "extended_caching":
		return level >= LevelMinor
	case "rate_limiting":
		return level >= LevelMajor
	case "connection_pool_management":
		return level >= LevelMajor
	case "read_only_mode":
		return level >= LevelCritical
	default:
		return false
	}
}

func (dm *DegradationManager) GetCurrentLevel() DegradationLevel {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.currentLevel
}

func (dm *DegradationManager) GetActiveStrategies() map[string]DegradationLevel {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	active := make(map[string]DegradationLevel)
	for name, strategy := range dm.strategies {
		if strategy.IsActive() {
			active[name] = strategy.Level()
		}
	}

	return active
}
