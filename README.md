# keyshard

Shamir's Secret Sharing 기반 키 보호/복구 Go 라이브러리.

비밀을 N개 조각으로 분할하고, 그 중 T개만 있으면 원본을 복원할 수 있습니다. AT Protocol DID rotation key 복구, 암호화폐 지갑 시드 보관, 비밀번호 상속 등에 사용할 수 있습니다.

## 패키지 구성

```
keyshard/
├── shamir/    # Shamir Secret Sharing — Split/Combine
├── crypto/    # AES-256-GCM 암호화 + Shamir — Seal/Unseal
└── did/       # AT Protocol DID — Resolve/Verify/Protect/Recover
```

## 사용법

### 기본: 비밀 분할/복원

```go
import "github.com/palmseung/keyshard/shamir"

// 비밀을 5개 조각으로 분할 (3개면 복원 가능)
result, _ := shamir.Split([]byte("my-secret"), 5, 3)

// 아무 3개 조각으로 복원
recovered, _ := shamir.Combine(result.Shares[:3])
// recovered == []byte("my-secret")
```

### 암호화 + 분할

```go
import "github.com/palmseung/keyshard/crypto"

// 비밀을 AES-256-GCM으로 암호화 후 키를 Shamir로 분할
sealed, _ := crypto.Seal([]byte("my-secret"), 5, 3)

// envelope (암호문) + 조각 3개로 복원
recovered, _ := crypto.Unseal(sealed.Envelope, sealed.Shares[:3])
```

### DID 키 보호

```go
import "github.com/palmseung/keyshard/did"

// DID document 조회
doc, _ := did.Resolve("did:plc:abc123...")
handle, _ := did.Handle(doc)       // "user.bsky.social"
pds, _ := did.PDSEndpoint(doc)     // "https://bsky.social"

// DID 소유권 서명 검증
err := did.VerifySignature(doc, challenge, signature)

// rotation key를 가디언에게 분배
guardians := []string{"did:plc:guardian1", "did:plc:guardian2", "did:plc:guardian3"}
protected, _ := did.Protect("did:plc:owner", "rotation", rotationKeyBytes, guardians, 2)
// → 3개 share, 2개면 복구 가능

// 복구
rawShares := did.ExtractShares(submittedShares)
recovered, _ := did.Recover(protected.Envelope, rawShares)
```

## DID 서명 검증

챌린지-응답 방식으로 DID 소유권을 증명합니다.

1. 서버가 랜덤 nonce 발급
2. 클라이언트가 DID signing key로 nonce에 ECDSA 서명
3. 서버가 DID document의 공개키로 서명 검증

지원 키 타입:
- **P-256** (secp256r1) — AT Protocol 기본
- **secp256k1** — 파싱만 지원 (검증은 go-ethereum 커브 필요)

## 설치

```bash
go get github.com/palmseung/keyshard
```

## 테스트

```bash
go test ./...
```
