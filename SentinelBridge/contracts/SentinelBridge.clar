;; contract title: ai-bridge-security
;; <description>
;; This contract implements an advanced AI-Guided Cross-Chain Bridge Security system.
;; It serves as a guardian for bridge transfers, utilizing off-chain AI agents to
;; assess risk in real-time. Key features include:
;; 1. Granular Access Control: Contract Owner, AI Agent, and Security Guardians.
;; 2. Bridge Pause Mechanism: Global pause and per-chain pause capabilities.
;; 3. Dynamic Limits: Transfer limits adjust based on global threat levels.
;; 4. Address Blacklisting: Preventing transfers to/from malicious actors.
;; 5. Chain Whitelisting: Only authorized chains are supported.
;; 6. Detailed Analytics: Event emissions for off-chain monitoring.
;; </description>

;; constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-REQUEST (err u101))
(define-constant ERR-TRANSFER-PAUSED (err u102))
(define-constant ERR-RISK-TOO-HIGH (err u103))
(define-constant ERR-CHAIN-NOT-SUPPORTED (err u104))
(define-constant ERR-ADDRESS-BLOCKED (err u105))
(define-constant ERR-LIMIT-EXCEEDED (err u106))

(define-constant STATUS-PENDING u0)
(define-constant STATUS-APPROVED u1)
(define-constant STATUS-REJECTED u2)
(define-constant STATUS-FLAGGED u3)
(define-constant MAX-RISK-SCORE u100)
(define-constant HIGH-RISK-THRESHOLD u80)
(define-constant MEDIUM-RISK-THRESHOLD u50)
(define-constant LOW-RISK-THRESHOLD u20)

;; data maps and vars
(define-map transfer-requests
    uint
    {
        sender: principal,
        amount: uint,
        target-chain: (string-ascii 10),
        target-address: (string-ascii 42),
        status: uint,
        risk-score: uint,
        timestamp: uint
    }
)

(define-map supported-chains
    (string-ascii 10)
    {
        is-active: bool,
        daily-limit: uint,
        current-volume: uint,
        chain-risk-score: uint
    }
)

(define-map blocked-addresses principal bool)
(define-map authorized-guardians principal bool)

(define-data-var request-nonce uint u0)
(define-data-var authorized-ai-agent principal tx-sender)
(define-data-var bridge-paused bool false)
(define-data-var global-risk-level uint u0)
(define-data-var global-transfer-limit uint u10000)
(define-data-var last-limit-update-block uint u0)

;; private functions
(define-private (is-ai-agent)
    (is-eq tx-sender (var-get authorized-ai-agent))
)

(define-private (is-guardian (user principal))
    (default-to false (map-get? authorized-guardians user))
)

(define-private (check-paused)
    (if (var-get bridge-paused)
        ERR-TRANSFER-PAUSED
        (ok true)
    )
)

(define-private (is-address-blocked (addr principal))
    (default-to false (map-get? blocked-addresses addr))
)

(define-private (get-chain-config (chain (string-ascii 10)))
    (ok (unwrap! (map-get? supported-chains chain) ERR-CHAIN-NOT-SUPPORTED))
)

;; public functions

;; @desc Add a guardian for emergency actions
(define-public (add-guardian (guardian principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (map-set authorized-guardians guardian true)
        (ok true)
    )
)

;; @desc Remove a guardian
(define-public (remove-guardian (guardian principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (map-delete authorized-guardians guardian)
        (ok true)
    )
)

;; @desc Block a specific address manually
(define-public (block-address (addr principal))
    (begin
        (asserts! (or (is-eq tx-sender CONTRACT-OWNER) (is-guardian tx-sender)) ERR-NOT-AUTHORIZED)
        (map-set blocked-addresses addr true)
        (ok true)
    )
)

;; @desc Unblock a specific address manually
(define-public (unblock-address (addr principal))
    (begin
        (asserts! (or (is-eq tx-sender CONTRACT-OWNER) (is-guardian tx-sender)) ERR-NOT-AUTHORIZED)
        (map-delete blocked-addresses addr)
        (ok true)
    )
)

;; @desc Add or update a supported chain configuration
(define-public (configure-chain (chain-name (string-ascii 10)) (limit uint) (active bool))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (map-set supported-chains chain-name {
            is-active: active,
            daily-limit: limit,
            current-volume: u0,
            chain-risk-score: u0
        })
        (ok true)
    )
)

;; @desc Initialize a new bridge transfer request
;; @param amount: amount of tokens to bridge
;; @param target-chain: destination chain identifier
;; @param target-address: destination wallet address
(define-public (initiate-transfer (amount uint) (target-chain (string-ascii 10)) (target-address (string-ascii 42)))
    (let
        (
            (request-id (var-get request-nonce))
            (chain-config (try! (get-chain-config target-chain)))
        )
        ;; Check global pause
        (try! (check-paused))
        
        ;; Check address blocking
        (asserts! (not (is-address-blocked tx-sender)) ERR-ADDRESS-BLOCKED)
        
        ;; Check chain active status
        (asserts! (get is-active chain-config) ERR-CHAIN-NOT-SUPPORTED)
        
        ;; Check global limits
        (asserts! (<= amount (var-get global-transfer-limit)) ERR-LIMIT-EXCEEDED)
        
        ;; Check per-chain limits
        (asserts! (<= (+ (get current-volume chain-config) amount) (get daily-limit chain-config)) ERR-LIMIT-EXCEEDED)
        
        ;; Update chain volume
        (map-set supported-chains target-chain 
            (merge chain-config { current-volume: (+ (get current-volume chain-config) amount) })
        )
        
        ;; Create request
        (map-set transfer-requests request-id {
            sender: tx-sender,
            amount: amount,
            target-chain: target-chain,
            target-address: target-address,
            status: STATUS-PENDING,
            risk-score: u0,
            timestamp: block-height
        })
        
        (var-set request-nonce (+ request-id u1))
        (print { event: "transfer-initiated", id: request-id, sender: tx-sender, amount: amount, target: target-chain })
        (ok request-id)
    )
)

;; @desc Update the authorized AI agent address
(define-public (set-ai-agent (new-agent principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (var-set authorized-ai-agent new-agent)
        (ok true)
    )
)

;; @desc Submit a risk assessment for a pending transfer
(define-public (submit-risk-assessment (request-id uint) (risk-score uint) (reason (string-utf8 64)))
    (let
        (
            (request (unwrap! (map-get? transfer-requests request-id) ERR-INVALID-REQUEST))
        )
        (asserts! (is-ai-agent) ERR-NOT-AUTHORIZED)
        (asserts! (<= risk-score MAX-RISK-SCORE) ERR-INVALID-REQUEST)
        
        (let
            (
                (new-status 
                    (if (> risk-score HIGH-RISK-THRESHOLD) 
                        STATUS-REJECTED 
                        (if (> risk-score MEDIUM-RISK-THRESHOLD) 
                            STATUS-FLAGGED 
                            STATUS-APPROVED
                        )
                    )
                )
            )
            ;; If rejected due to high risk, potentially auto-block sender for investigation? 
            ;; For now, we just reject.
            
            (map-set transfer-requests request-id (merge request {
                status: new-status,
                risk-score: risk-score
            }))
            
            (print { event: "risk-assessment-submitted", id: request-id, score: risk-score, status: new-status, reason: reason })
            (ok new-status)
        )
    )
)

;; @desc Comprehensive AI Security audit and incident response function.
;; This function is the cornerstone of the AI-guided security system. It allows the AI
;; agent to submit a detailed report containing multiple boolean flags and integer scores
;; representing different threat vectors (Liquidity drain, Flash loan attack, Latency spikes, etc.).
;; Based on these inputs, the contract autonomously executes a complex decision tree to:
;; 1. Adjust global risk levels.
;; 2. Pause specific components (global bridge or specific chains).
;; 3. Adjust transaction limits dynamically.
;; 4. Emit detailed diagnostic events for off-chain monitoring.
(define-public (analyze-incident-report 
    (threat-vectors {
        liquidity-drain: bool,
        flash-loan-attack: bool,
        latency-spike: bool,
        anomalous-volume: bool,
        mev-bot-activity: bool
    })
    (metrics {
        current-latency: uint,
        pending-tx-count: uint,
        average-gas-price: uint,
        threat-score: uint
    })
)
    (let
        (
            (current-score (get threat-score metrics))
            (is-critical 
                (or 
                    (get liquidity-drain threat-vectors) 
                    (get flash-loan-attack threat-vectors)
                    (> current-score HIGH-RISK-THRESHOLD)
                )
            )
            (is-warning
                (or
                    (get anomalous-volume threat-vectors)
                    (get latency-spike threat-vectors)
                    (> current-score MEDIUM-RISK-THRESHOLD)
                )
            )
        )
        
        (asserts! (or (is-ai-agent) (is-eq tx-sender CONTRACT-OWNER)) ERR-NOT-AUTHORIZED)
        
        ;; ---------------------------------------------------
        ;; EMERGENCY PROTOCOL: CRITICAL LEVEL
        ;; ---------------------------------------------------
        (if is-critical
            (begin
                (var-set bridge-paused true)
                (var-set global-risk-level MAX-RISK-SCORE)
                (var-set global-transfer-limit u0)
                (print { 
                    event: "security-alert", 
                    level: "CRITICAL", 
                    action: "BRIDGE_PAUSED", 
                    vectors: threat-vectors 
                })
                true
            )
            ;; ---------------------------------------------------
            ;; CAUTION PROTOCOL: WARNING LEVEL
            ;; ---------------------------------------------------
            (if is-warning
                (begin
                    ;; Increase global risk level but keep bridge open
                    (var-set global-risk-level current-score)
                    
                    ;; Drastically reduce limits to minimize exposure
                    (var-set global-transfer-limit (/ (var-get global-transfer-limit) u4))
                    
                    ;; Log specifically what triggered the warning
                    (if (get anomalous-volume threat-vectors)
                        (begin (print { event: "security-warning", type: "anomalous-volume", action: "limit-reduced" }) true)
                        true
                    )
                    (if (get latency-spike threat-vectors)
                        (begin (print { event: "security-warning", type: "latency-spike", latency: (get current-latency metrics) }) true)
                        true
                    )
                )
                ;; ---------------------------------------------------
                ;; NORMAL PROTOCOL: SAFE LEVEL
                ;; ---------------------------------------------------
                (begin
                    ;; Slowly recover limits if risk is low and previously restricted
                    ;; We only increase limits if the threat score is very low (< 10)
                    (if (< current-score u10)
                        (var-set global-transfer-limit u10000) ;; Restore to max
                        true
                    )
                    (var-set global-risk-level current-score)
                    (var-set bridge-paused false)
                )
            )
        )
        
        ;; ---------------------------------------------------
        ;; POST-ANALYSIS ACTIONS
        ;; ---------------------------------------------------
        
        ;; Auto-Blocking Logic for MEV bots if detected
        ;; (In a real scenario, we would need the specific principal, but here we can flag the mode)
        (if (get mev-bot-activity threat-vectors)
            (begin (print { event: "mev-activity-detected", action: "monitoring-intensified" }) true)
            true
        )
        
        ;; Update System State Timestamp
        (var-set last-limit-update-block block-height)
        
        (ok {
            new-risk-level: (var-get global-risk-level),
            is-paused: (var-get bridge-paused),
            limit: (var-get global-transfer-limit),
            status: (if is-critical "CRITICAL" (if is-warning "WARNING" "NORMAL"))
        })
    )
)


