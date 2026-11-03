package warp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const DefaultPoolSize = 2

// maxPreload bounds how many exits are registered eagerly at startup. The rest
// of a larger pool still grows on demand, so a 24-exit ceiling does not hammer
// the registration API just to sit idle.
const maxPreload = 12

// egressCooldown keeps a public /64 (or IPv4 /32) that the upstream has
// rejected out of the pool for this long. The free tier scopes its quota to
// that block, so a new tunnel inside it would only repeat the same answer.
const egressCooldown = 24 * time.Hour

// maxEgressCooldown caps an upstream Retry-After. A free-tier window is hours
// long, and honoring an absurd header (or a clock skew) must not park a block
// forever.
const maxEgressCooldown = 24 * time.Hour

// transportCooldown parks an exit whose tunnel died for a local reason. The
// address may well be fine — Cloudflare often reissues the same block — so this
// only lasts long enough to stop a replacement from colliding with the exit
// that was just retired.
const transportCooldown = 90 * time.Second

// rateLimitCooldown parks an exit that answered with an ordinary rate limit
// rather than a spent quota. Rotating is still worthwhile, but the block should
// not be written off for hours.
const rateLimitCooldown = time.Minute

// maxRateLimitCooldown caps Retry-After for an ordinary rate limit, which is
// usually a short burst window rather than a daily free-tier quota.
const maxRateLimitCooldown = 5 * time.Minute

// starvationFloor and starvationRatioPercent keep the blacklist from consuming
// the whole known supply. Once cooled blocks reach 60% of every block this
// process has seen (after at least ten), the soonest-expiring entry is released
// early so the pool still has a block to register.
const (
	starvationFloor        = 10
	starvationRatioPercent = 60
)

// emptyPoolWait bounds how long Acquire blocks on an empty pool. A registration
// normally finishes well inside this; anything longer means WARP is down or the
// supply is exhausted, so the request fails fast instead of hanging until the
// edge timeout.
const emptyPoolWait = 5 * time.Second

// refillRetryDelay spaces out a failed registration attempt. Successful
// registrations run back to back in the background.
const refillRetryDelay = 5 * time.Second

// A pool can only hold as many exits as Cloudflare hands out distinct egress
// blocks. When preload is larger than that supply, every extra registration is
// a duplicate; after a few in a row the pool stops trying for a while instead
// of hammering the registration API forever.
const (
	refillFailureThreshold = 3
	refillBackoffBase      = time.Minute
	refillBackoffMax       = 5 * time.Minute
)

// errDuplicateEgress reports a registration whose public egress block is
// already active or cooling down.
var errDuplicateEgress = errors.New("WARP egress is already active or cooling down")

// scaleDownDelay keeps exits created for a burst hot for a while after the
// burst, so a following burst reuses them instead of paying for new
// registrations.
const scaleDownDelay = 60 * time.Second

// ErrClosed is returned when a pool is used after Close. Callers use it to
// tell a retiring pool apart from a temporary capacity wait.
var ErrClosed = errors.New("WARP pool is closed")

// ErrNoExit is returned when the pool has no exit at all and none came up
// within emptyPoolWait. A caller that keeps waiting only turns a broken WARP
// into a request that hangs until its own deadline, so it fails fast instead.
var ErrNoExit = errors.New("WARP pool has no ready egress")

type logger interface {
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Warnf(string, ...interface{})
	Errorf(string, ...interface{})
}

// slogLogger adapts the structured logger used by the gateway to the short
// diagnostic messages this package emits at its own lifecycle boundaries.
type slogLogger struct {
	log *slog.Logger
}

func (l slogLogger) logf(level slog.Level, format string, args ...interface{}) {
	if l.log == nil {
		return
	}
	l.log.Log(context.Background(), level, fmt.Sprintf(format, args...), "component", "warp")
}

func (l slogLogger) Debugf(format string, args ...interface{}) {
	l.logf(slog.LevelDebug, format, args...)
}

func (l slogLogger) Infof(format string, args ...interface{}) {
	l.logf(slog.LevelInfo, format, args...)
}

func (l slogLogger) Warnf(format string, args ...interface{}) {
	l.logf(slog.LevelWarn, format, args...)
}

func (l slogLogger) Errorf(format string, args ...interface{}) {
	l.logf(slog.LevelError, format, args...)
}

type Pool struct {
	ctx       context.Context
	cancel    context.CancelFunc
	logger    logger
	size      int
	preload   int
	stack     Stack
	statePath string
	newExit   func(context.Context) (*exit, error)

	mu        sync.Mutex
	active    []*exit
	inflight  int
	waiting   int
	next      int
	reserved  map[string]bool
	cooling   map[string]time.Time
	known     map[string]bool
	changed   chan struct{}
	closed    bool
	refilling bool
	scaling   bool
	// refillFailures counts consecutive failed preload registrations;
	// refillPaused keeps every refill trigger quiet until it expires.
	refillFailures int
	refillPaused   time.Time
	wait           sync.WaitGroup
	createMu       sync.Mutex
	stateMu        sync.Mutex
}

type Lease struct {
	pool *Pool
	exit *exit
	once sync.Once
}

// Snapshot is a point-in-time view of a pool for health and admin reporting.
type Snapshot struct {
	Stack string
	Size  int
	// Preload is the number of exits kept hot even when the pool is idle:
	// half of Size (at least one), registered in the background after the
	// first exit so a burst does not wait for a registration.
	Preload int
	// Active is the number of exits currently in the ring. Standby counts the
	// idle part of it: exits not held by a lease and ready to replace a
	// penalized one immediately.
	Active  int
	Standby int
	Cooling int
	Egress  []string
}

// Options configure a WARP pool.
type Options struct {
	// Size is the upper bound on exits. Half of it (at least one) is kept hot
	// as a preload even while the pool is idle; beyond that the pool keeps as
	// many exits hot as the current concurrency needs and never exceeds Size.
	Size int
	// Stack selects the address family inside the tunnel. An IPv6 stack makes
	// the public egress an IPv6 address.
	Stack Stack
	// SourceIPv6, when valid, is the outer IPv6 prefix each exit binds its
	// WireGuard socket to. Every exit draws its own address from it, so a
	// replacement reaches Cloudflare from a new source and receives a new
	// public egress — the only way past an egress-scoped free usage limit.
	SourceIPv6 netip.Prefix
	// StatePath persists the egress blocks the upstream has rejected, so a
	// restart does not register the same spent /64 again. Empty disables
	// persistence.
	StatePath string
}

// NewWithOptions creates a WARP pool whose exits use the selected IP stack and,
// optionally, rotate their outer IPv6 source within a prefix.
func NewWithOptions(ctx context.Context, log *slog.Logger, opts Options) (*Pool, error) {
	normalized, err := ParseStack(string(opts.Stack))
	if err != nil {
		return nil, err
	}
	if opts.SourceIPv6.IsValid() && (!opts.SourceIPv6.Addr().Is6() || opts.SourceIPv6.Bits() > 64) {
		return nil, fmt.Errorf("WARP outer source must be an IPv6 prefix of /64 or shorter, got %s", opts.SourceIPv6)
	}
	size := opts.Size
	if size <= 0 {
		size = DefaultPoolSize
	}
	r := newRegistrar()
	pool, err := newPool(ctx, slogLogger{log: log}, size, opts.StatePath, func(ctx context.Context) (*exit, error) {
		reg, err := r.register(ctx)
		if err != nil {
			return nil, err
		}
		var source netip.Addr
		if opts.SourceIPv6.IsValid() {
			source, err = randomSource(opts.SourceIPv6)
			if err != nil {
				return nil, err
			}
		}
		return newExitWithStack(ctx, reg, normalized, source)
	})
	if err != nil {
		return nil, err
	}
	pool.stack = normalized
	return pool, nil
}

// randomSource draws one host address from prefix. The bits above the prefix
// length are kept, every bit below is random, so two exits practically never
// share an outer source.
func randomSource(prefix netip.Prefix) (netip.Addr, error) {
	address := prefix.Masked().Addr().As16()
	var noise [16]byte
	if _, err := rand.Read(noise[:]); err != nil {
		return netip.Addr{}, fmt.Errorf("draw WARP outer source: %w", err)
	}
	keep := prefix.Bits()
	for index := range address {
		switch bits := keep - index*8; {
		case bits >= 8:
		case bits <= 0:
			address[index] = noise[index]
		default:
			mask := byte(0xFF) << (8 - bits)
			address[index] = address[index]&mask | noise[index]&^mask
		}
	}
	return netip.AddrFrom16(address), nil
}

func newPool(ctx context.Context, log logger, size int, statePath string, create func(context.Context) (*exit, error)) (*Pool, error) {
	if size <= 0 {
		size = DefaultPoolSize
	}
	// Keep the whole pool warm, capped at maxPreload, so a burst finds ready
	// exits instead of paying for registrations while requests queue. The first
	// exit is synchronous and gates readiness; the rest register in the
	// background.
	preload := preloadFor(size)
	// The caller's context bounds the synchronous first registration, not the
	// pool: it is typically an initialization deadline that expires moments
	// after NewWithOptions returns. Deriving the pool lifetime from it would
	// cancel every later refill and replacement with "context canceled",
	// leaving the pool stuck on its first egress forever.
	poolCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	cooling, known := loadPenalties(statePath)
	p := &Pool{
		ctx:       poolCtx,
		cancel:    cancel,
		logger:    log,
		size:      size,
		preload:   preload,
		statePath: statePath,
		newExit:   create,
		reserved:  make(map[string]bool),
		cooling:   cooling,
		known:     known,
		changed:   make(chan struct{}),
	}
	if log != nil && len(p.cooling) > 0 {
		log.Infof("OpenCode WARP inherited %d spent egress block(s) from %s", len(p.cooling), statePath)
	}
	// The first registration gates readiness. Cloudflare can answer it with a
	// rate limit even when this process has just started (the limit follows the
	// source address), so wait out that window inside the caller's deadline
	// instead of failing startup over a pause that is about to end. Any other
	// failure still fails closed.
	first, err := p.createExit(ctx)
	for err != nil {
		pause := registrationPause(err)
		if pause <= 0 {
			cancel()
			return nil, err
		}
		if log != nil {
			log.Infof("OpenCode WARP first registration paused for %s", pause.Round(time.Second))
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			cancel()
			return nil, ctx.Err()
		case <-timer.C:
		}
		first, err = p.createExit(ctx)
	}
	p.active = []*exit{first}
	if log != nil {
		log.Infof("OpenCode WARP/%s pool ready (max %d exits, preloading %d)", first.stack, size, preload)
	}
	p.startRefill()
	return p, nil
}

// preloadFor returns how many exits to register eagerly: the whole pool, capped
// at maxPreload. A larger ceiling still grows on demand.
func preloadFor(size int) int {
	if size <= 0 {
		size = DefaultPoolSize
	}
	if size > maxPreload {
		return maxPreload
	}
	return size
}

// desiredLocked is the number of exits the pool should keep hot: one per
// in-flight lease, one for every request waiting for an exit, plus a spare, so
// a 429 can switch to a ready exit instead of waiting for a registration. The
// preload floor keeps half the ceiling registered while the pool is idle.
// Size is the upper bound; at idle a pool of two or more keeps one spare.
func (p *Pool) desiredLocked() int {
	want := p.inflight + p.waiting + 1
	if want < p.preload {
		want = p.preload
	}
	if want < 2 {
		want = 2
	}
	if want > p.size {
		want = p.size
	}
	return want
}

func (p *Pool) Acquire(ctx context.Context) (*Lease, error) {
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, ErrClosed
		}
		for attempts := 0; attempts < len(p.active); attempts++ {
			index := p.next % len(p.active)
			p.next = (p.next + 1) % len(p.active)
			active := p.active[index]
			if active.addRef() {
				p.inflight++
				p.mu.Unlock()
				// Demand just rose: grow the ring toward it in the background.
				p.startRefill()
				return &Lease{pool: p, exit: active}, nil
			}
		}
		p.waiting++
		changed := p.changed
		needRefill := len(p.active) < p.desiredLocked()
		p.mu.Unlock()
		if needRefill {
			// Queued demand is demand too: start growing before we block.
			p.startRefill()
		}
		var deadline <-chan time.Time
		var timer *time.Timer
		if len(p.active) == 0 && p.inflight == 0 {
			// Waiting on a pool that has nothing at all turns a broken WARP
			// into a request that hangs until its own deadline. Give one
			// registration a chance, then fail fast so the caller can report
			// the failure instead of timing out.
			timer = time.NewTimer(emptyPoolWait)
			deadline = timer.C
		}
		var err error
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-p.ctx.Done():
			err = ErrClosed
		case <-changed:
		case <-deadline:
			err = ErrNoExit
		}
		if timer != nil {
			timer.Stop()
		}
		p.mu.Lock()
		p.waiting--
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
}

func (p *Pool) Report(lease *Lease, status int, body []byte) {
	p.ReportWithRetryAfter(lease, status, body, 0)
}

// ReportWithRetryAfter is Report plus the upstream Retry-After hint. A
// free-tier quota window is usually hours long, so the block is written off for
// a full egressCooldown; an ordinary rate limit is short but can still ask for a
// few minutes.
func (p *Pool) ReportWithRetryAfter(lease *Lease, status int, body []byte, retryAfter time.Duration) {
	if lease == nil || lease.exit == nil {
		return
	}
	rotate, reason := lease.exit.observe(status, body)
	if !rotate {
		return
	}
	p.penalize(lease.exit, reason, retryAfter, classifyPenalty(status, body))
}

// Fail drops an exit that cannot carry traffic even though the upstream never
// produced an HTTP response, such as a broken WARP handshake or a stalled first
// token. Retrying the same user-space tunnel would only repeat the stall.
func (p *Pool) Fail(lease *Lease, reason string) {
	if lease == nil || lease.exit == nil || reason == "" {
		return
	}
	p.penalize(lease.exit, reason, 0, penaltyTransport)
}

func (p *Pool) Size() int { return p.size }

// Snapshot reports the pool's current capacity and the public egress address
// of every active exit. It never exposes keys or device tokens.
func (p *Pool) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	cooling := 0
	for _, until := range p.cooling {
		if until.After(now) {
			cooling++
		}
	}
	snapshot := Snapshot{Stack: string(p.stack), Size: p.size, Preload: p.preload, Active: len(p.active), Cooling: cooling}
	for _, active := range p.active {
		if active.idle() {
			snapshot.Standby++
		}
		if active.egress.IsValid() {
			snapshot.Egress = append(snapshot.Egress, active.egress.String())
		}
	}
	return snapshot
}

// classifyPenalty separates a spent free-tier quota from a short rate limit.
// The free lane usually reports its quota in the body while still answering
// 429, so the status code alone cannot decide the cooldown.
func classifyPenalty(status int, body []byte) penaltyKind {
	if status != 403 && status != 429 {
		return penaltyQuota
	}
	text := strings.ToLower(string(body))
	for _, marker := range []string{"quota", "usage limit", "free usage", "insufficient_quota", "billing", "credit", "额度"} {
		if strings.Contains(text, marker) {
			return penaltyQuota
		}
	}
	for _, marker := range []string{"rate_limit", "rate limit", "rate-limit", "too many requests", "try again"} {
		if strings.Contains(text, marker) {
			return penaltyRateLimit
		}
	}
	return penaltyQuota
}

func quotaCooldownFor(retryAfter time.Duration) time.Duration {
	cooldown := egressCooldown
	if retryAfter > cooldown {
		cooldown = retryAfter
	}
	if cooldown > maxEgressCooldown {
		cooldown = maxEgressCooldown
	}
	return cooldown
}

func rateLimitCooldownFor(retryAfter time.Duration) time.Duration {
	cooldown := rateLimitCooldown
	if retryAfter > cooldown {
		cooldown = retryAfter
	}
	if cooldown > maxRateLimitCooldown {
		cooldown = maxRateLimitCooldown
	}
	return cooldown
}

func (p *Pool) penalize(bad *exit, reason string, retryAfter time.Duration, kind penaltyKind) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	index := p.activeIndexLocked(bad)
	if index < 0 {
		p.mu.Unlock()
		return
	}
	if !bad.markPenalized(kind) {
		p.mu.Unlock()
		return
	}
	cooldown := transportCooldown
	switch kind {
	case penaltyQuota:
		cooldown = quotaCooldownFor(retryAfter)
	case penaltyRateLimit:
		cooldown = rateLimitCooldownFor(retryAfter)
	}
	key := bad.egressKey()
	if key != "" {
		p.known[key] = true
		until := time.Now().Add(cooldown)
		if parked, ok := p.cooling[key]; !ok || until.After(parked) {
			p.cooling[key] = until
		}
		delete(p.reserved, key)
	}
	p.releaseStarvationLocked(key)
	p.active = append(p.active[:index], p.active[index+1:]...)
	if p.next >= len(p.active) {
		p.next = 0
	}
	p.notifyLocked()
	p.wait.Add(1)
	p.mu.Unlock()
	p.saveCooling()

	if p.logger != nil {
		p.logger.Warnf("Rotating OpenCode WARP egress %s (%s, %s)", bad.id, reason, cooldown.Round(time.Second))
	}
	// Re-register immediately: the retired exit is replaced in the background
	// and the retry draws whichever active exit is ready first.
	go func() {
		defer p.wait.Done()
		p.replace(bad, reason)
	}()
}

// releaseStarvationLocked keeps the blacklist from eating the whole known
// supply. The newest entry is never the one released, so a burst of failures
// cannot immediately undo its own penalty.
func (p *Pool) releaseStarvationLocked(keep string) {
	if len(p.known) < starvationFloor || len(p.cooling) == 0 {
		return
	}
	limit := len(p.known) * starvationRatioPercent / 100
	if limit < 1 {
		limit = 1
	}
	now := time.Now()
	for len(p.cooling) > limit {
		var oldestKey string
		var oldest time.Time
		for key, until := range p.cooling {
			if key == keep || !until.After(now) {
				continue
			}
			// Never release a block that is cooling for a spent free-tier
			// quota. It has hours left and would only answer 429 again, so
			// releasing it turns the guard into a registration/429 loop.
			if until.Sub(now) > maxRateLimitCooldown {
				continue
			}
			if oldestKey == "" || until.Before(oldest) {
				oldestKey, oldest = key, until
			}
		}
		if oldestKey == "" {
			return
		}
		delete(p.cooling, oldestKey)
		if p.logger != nil {
			p.logger.Warnf("OpenCode WARP starvation guard released egress %s early (cooling=%d known=%d)", oldestKey, len(p.cooling), len(p.known))
		}
	}
}

func (p *Pool) replace(old *exit, reason string) {
	replacement, err := p.createExit(p.ctx)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		if replacement != nil {
			p.releaseReservation(replacement)
			replacement.close()
		}
		old.retire()
		return
	}
	if err != nil {
		kind := old.penaltyKind()
		restorable := kind == penaltyTransport || kind == penaltyNone
		restored := len(p.active) == 0 && restorable
		if restored {
			old.clearPenalty()
			if key := old.egressKey(); key != "" {
				p.reserved[key] = true
				delete(p.cooling, key)
			}
			p.active = append(p.active, old)
			p.notifyLocked()
		}
		p.mu.Unlock()
		if restored {
			p.saveCooling()
		}
		if !restored {
			old.retire()
		}
		if p.logger != nil {
			if pause := registrationPause(err); pause > 0 {
				p.logger.Infof("OpenCode WARP replacement paused for %s", pause.Round(time.Second))
			} else if restorable {
				p.logger.Errorf("Cannot replace OpenCode WARP egress %s: %v", old.id, err)
			} else {
				p.logger.Warnf("OpenCode WARP egress %s left rotation for a fresh block: %v", old.id, err)
			}
		}
		p.startRefill()
		return
	}
	if p.activeIndexLocked(old) >= 0 {
		p.mu.Unlock()
		p.releaseReservation(replacement)
		replacement.close()
		old.retire()
		return
	}
	placed := false
	if len(p.active) < p.size {
		p.active = append(p.active, replacement)
		placed = true
	}
	p.notifyLocked()
	p.mu.Unlock()
	if !placed {
		p.releaseReservation(replacement)
		replacement.close()
		old.retire()
		return
	}
	if p.logger != nil {
		p.logger.Infof("OpenCode WARP egress %s replaced by %s at %s (%s), active=%d", old.id, replacement.id, replacement.egress, reason, len(p.active))
	}
	old.retire()
	p.startRefill()
}

func (p *Pool) refill() {
	p.mu.Lock()
	if p.closed || p.refilling || time.Now().Before(p.refillPaused) || !p.needsRefillLocked() {
		p.mu.Unlock()
		return
	}
	p.refilling = true
	p.mu.Unlock()

	replacement, err := p.createExit(p.ctx)
	p.mu.Lock()
	p.refilling = false
	placed := false
	if err == nil && !p.closed && len(p.active) < p.size {
		p.active = append(p.active, replacement)
		replacement = nil
		placed = true
	}
	if err == nil {
		p.refillFailures = 0
		p.refillPaused = time.Time{}
	}
	if placed || p.closed {
		p.notifyLocked()
	}
	p.mu.Unlock()

	if replacement != nil {
		p.releaseReservation(replacement)
		replacement.close()
	}
	if err != nil && p.ctx.Err() == nil {
		delay := refillRetryDelay
		if pause := registrationPause(err); pause > 0 {
			// Cloudflare's rate limit is the pacing: wait out the window it
			// asked for instead of retrying into the same answer.
			delay = pause
			if delay < refillRetryDelay {
				delay = refillRetryDelay
			}
			if delay > maxRateLimitPause {
				delay = maxRateLimitPause
			}
			if p.logger != nil {
				p.logger.Infof("OpenCode WARP registration paused for %s", delay.Round(time.Second))
			}
		} else if errors.Is(err, errDuplicateEgress) {
			p.mu.Lock()
			p.refillFailures++
			failures := p.refillFailures
			p.mu.Unlock()
			if failures >= refillFailureThreshold {
				// The egress supply is smaller than the target. Back off
				// exponentially so a saturated colo is not registered into
				// forever.
				shift := failures - refillFailureThreshold
				if shift > 3 {
					shift = 3
				}
				delay = refillBackoffBase << shift
				if delay > refillBackoffMax {
					delay = refillBackoffMax
				}
				if p.logger != nil {
					p.logger.Infof("OpenCode WARP preload paused for %s after %d duplicate egresses", delay.Round(time.Second), failures)
				}
			}
		} else if p.logger != nil {
			p.logger.Warnf("Cannot pre-register OpenCode WARP egress: %v", err)
		}
		p.mu.Lock()
		if paused := time.Now().Add(delay); paused.After(p.refillPaused) {
			p.refillPaused = paused
		}
		p.mu.Unlock()
		p.after(delay, p.retryRefill)
		return
	}
	p.startRefill()
}

// retryRefill is the timer half of a failed refill: it clears the pause that
// kept ordinary triggers quiet and asks for another attempt. Going through
// startRefill (rather than calling refill directly) keeps the single-flight
// guard.
func (p *Pool) retryRefill() {
	p.mu.Lock()
	p.refillPaused = time.Time{}
	p.mu.Unlock()
	p.startRefill()
}

func (p *Pool) startRefill() {
	p.mu.Lock()
	if p.closed || p.refilling || time.Now().Before(p.refillPaused) || !p.needsRefillLocked() {
		p.mu.Unlock()
		return
	}
	p.wait.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.wait.Done()
		p.refill()
	}()
}

// released records that a lease was returned and trims the ring back toward
// the demand of the moment. Freed exits stay hot for scaleDownDelay, so a
// burst that pauses does not immediately pay for re-registering them.
func (p *Pool) released() {
	p.mu.Lock()
	if p.inflight > 0 {
		p.inflight--
	}
	closed := p.closed
	wantRefill := !closed && len(p.active) < p.desiredLocked()
	started := p.scaling
	if !closed && !started && len(p.active) > p.desiredLocked() {
		p.scaling = true
		started = true
	}
	p.mu.Unlock()
	if closed {
		return
	}
	if wantRefill {
		p.startRefill()
	}
	if started {
		p.after(scaleDownDelay, p.scaleDown)
	}
}

// scaleDown retires every idle exit above the current demand. Busy surplus
// exits are left to their release, which arms another pass if the ring is
// still over target then.
func (p *Pool) scaleDown() {
	p.mu.Lock()
	p.scaling = false
	if p.closed {
		p.mu.Unlock()
		return
	}
	want := p.desiredLocked()
	var dropped []*exit
	if surplus := len(p.active) - want; surplus > 0 {
		kept := p.active[:0]
		for _, candidate := range p.active {
			if surplus > 0 && candidate.idle() {
				dropped = append(dropped, candidate)
				surplus--
				continue
			}
			kept = append(kept, candidate)
		}
		p.active = kept
	}
	if p.next >= len(p.active) {
		p.next = 0
	}
	p.mu.Unlock()
	for _, drop := range dropped {
		p.releaseReservation(drop)
		drop.retire()
		if p.logger != nil {
			p.logger.Infof("OpenCode WARP egress %s scaled down at %s", drop.id, drop.egress)
		}
	}
}

// after runs fn once delay has elapsed, unless the pool closes first. The wait
// group is incremented under the pool lock so it cannot race with Close's
// Wait: a timer scheduled after Close is not started at all, and one scheduled
// before it is counted before Close can begin waiting.
func (p *Pool) after(delay time.Duration, fn func()) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.wait.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.wait.Done()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			fn()
		}
	}()
}

type coolingState struct {
	Cooling map[string]time.Time `json:"cooling,omitempty"`
	Known   map[string]bool      `json:"known,omitempty"`
}

// loadPenalties restores the blacklist across restarts. A missing or corrupt
// file is not fatal: a fresh pool simply starts with an empty memory.
func loadPenalties(path string) (map[string]time.Time, map[string]bool) {
	cooling := make(map[string]time.Time)
	known := make(map[string]bool)
	if path == "" {
		return cooling, known
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cooling, known
	}
	var state coolingState
	if err := json.Unmarshal(raw, &state); err != nil {
		return cooling, known
	}
	now := time.Now()
	for key, until := range state.Cooling {
		if key != "" && until.After(now) {
			cooling[key] = until
		}
	}
	for key, seen := range state.Known {
		if key != "" && seen {
			known[key] = true
		}
	}
	for key := range cooling {
		known[key] = true
	}
	return cooling, known
}

// saveCooling snapshots under p.mu and writes outside it, so a slow disk does
// not stall every request that is polling the pool.
func (p *Pool) saveCooling() {
	if p.statePath == "" {
		return
	}
	p.mu.Lock()
	now := time.Now()
	state := coolingState{
		Cooling: make(map[string]time.Time, len(p.cooling)),
		Known:   make(map[string]bool, len(p.known)),
	}
	for key, until := range p.cooling {
		if until.After(now) {
			state.Cooling[key] = until
		}
	}
	for key := range p.known {
		state.Known[key] = true
	}
	p.mu.Unlock()

	raw, err := json.Marshal(state)
	if err != nil {
		return
	}
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	temp := p.statePath + ".tmp"
	if err := os.WriteFile(temp, raw, 0o600); err != nil {
		if p.logger != nil {
			p.logger.Warnf("Cannot write WARP state %s: %v", p.statePath, err)
		}
		return
	}
	if err := os.Rename(temp, p.statePath); err != nil {
		if p.logger != nil {
			p.logger.Warnf("Cannot replace WARP state %s: %v", p.statePath, err)
		}
	}
}

func (p *Pool) createExit(ctx context.Context) (*exit, error) {
	p.createMu.Lock()
	defer p.createMu.Unlock()
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return nil, ErrClosed
		}
		candidate, err := p.newExit(ctx)
		if err != nil {
			return nil, err
		}
		key := candidate.egressKey()
		now := time.Now()
		p.mu.Lock()
		for subnet, until := range p.cooling {
			if !until.After(now) {
				delete(p.cooling, subnet)
			}
		}
		if key != "" {
			p.known[key] = true
		}
		usable := key != "" && !p.reserved[key] && !p.cooling[key].After(now)
		if usable {
			p.reserved[key] = true
		}
		p.mu.Unlock()
		if usable {
			p.saveCooling()
			if p.logger != nil {
				p.logger.Infof("OpenCode WARP/%s egress %s ready at %s", candidate.stack, candidate.id, candidate.egress)
			}
			return candidate, nil
		}
		lastErr = fmt.Errorf("%w: %s", errDuplicateEgress, key)
		if p.logger != nil {
			p.logger.Warnf("Discarding duplicate WARP exit %s: %v", candidate.id, lastErr)
		}
		candidate.close()
	}
	return nil, lastErr
}

func (p *Pool) releaseReservation(e *exit) {
	if e == nil {
		return
	}
	key := e.egressKey()
	if key == "" {
		return
	}
	p.mu.Lock()
	delete(p.reserved, key)
	p.mu.Unlock()
}

func (p *Pool) notifyLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *Pool) activeIndexLocked(target *exit) int {
	for index, candidate := range p.active {
		if candidate == target {
			return index
		}
	}
	return -1
}

func (p *Pool) needsRefillLocked() bool {
	return len(p.active) < p.desiredLocked()
}

func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	active := p.active
	p.active = nil
	p.notifyLocked()
	p.mu.Unlock()

	p.cancel()
	for _, item := range active {
		p.releaseReservation(item)
		item.retire()
	}
	p.wait.Wait()
}

func (l *Lease) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if l == nil || l.exit == nil {
		return nil, errors.New("WARP lease is closed")
	}
	return l.exit.dialContext(ctx, network, address)
}

func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.exit != nil {
			l.exit.release()
		}
		if l.pool != nil {
			l.pool.released()
		}
	})
}

func (l *Lease) EgressKey() string {
	if l == nil || l.exit == nil {
		return ""
	}
	return l.exit.egressKey()
}

// DialNetwork is the explicit TCP address family for this lease. Callers should
// pass it to DialContext instead of assuming IPv6.
func (l *Lease) DialNetwork() string {
	if l == nil || l.exit == nil {
		return ""
	}
	return l.exit.dialNetwork()
}

func (l *Lease) String() string {
	if l == nil || l.exit == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s/%s", l.exit.id, l.exit.egress)
}
