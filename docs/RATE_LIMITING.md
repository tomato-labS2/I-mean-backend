# Rate Limiting 시스템 사용법

## 📋 개요

이 프로젝트는 **커스텀 Annotation + Caffeine Cache** 방식을 사용하여 API 요청 횟수를 제한합니다.
브루트포스 공격, 서버 과부하, 스팸 요청을 효과적으로 방어합니다.

## 🛡️ 주요 컴포넌트

### 1. @RateLimit 어노테이션
```java
@RateLimit(requests = 5, window = "1m", keyType = RateLimitKeyType.IP, 
           message = "요청이 너무 많습니다. 1분 후 다시 시도해주세요.")
@PostMapping("/login")
```

### 2. RateLimitKeyType (제한 방식)
- **IP**: IP 주소별 제한 (기본값)
- **USER**: 로그인한 사용자별 제한
- **IP_AND_USER**: IP + 사용자 조합 제한
- **GLOBAL**: 전역 제한

### 3. 시간 윈도우 형식
- `"30s"` - 30초
- `"5m"` - 5분
- `"1h"` - 1시간
- `"1d"` - 1일

## 🎯 현재 적용 현황

### 🔴 보안 핵심 API (엄격한 제한)

#### 로그인 API
```java
@RateLimit(requests = 5, window = "1m", keyType = RateLimitKeyType.IP)
@PostMapping("/api/member/login")
```
- **제한**: IP당 1분에 5회
- **목적**: 브루트포스 공격 방어

#### 회원가입 API
```java
@RateLimit(requests = 3, window = "10m", keyType = RateLimitKeyType.IP)
@PostMapping("/api/member/register")
```
- **제한**: IP당 10분에 3회
- **목적**: 스팸 가입 방지

### 🟡 일반 API (적당한 제한)

#### 이메일 중복 체크
```java
@RateLimit(requests = 10, window = "1m", keyType = RateLimitKeyType.IP)
@PostMapping("/api/member/check-email")
```
- **제한**: IP당 1분에 10회
- **목적**: 무차별 요청 방지

#### 토큰 갱신
```java
@RateLimit(requests = 10, window = "1m", keyType = RateLimitKeyType.IP)
@PostMapping("/api/auth/refresh")
```
- **제한**: IP당 1분에 10회
- **목적**: 토큰 남용 방지

## 🔧 사용 방법

### 기본 사용법
```java
@RateLimit(requests = 10, window = "1m")
@PostMapping("/api/some-endpoint")
public ResponseEntity<?> someMethod() {
    // 메서드 구현
}
```

### IP별 제한
```java
@RateLimit(requests = 5, window = "1m", keyType = RateLimitKeyType.IP)
@PostMapping("/api/endpoint")
```

### 사용자별 제한
```java
@RateLimit(requests = 20, window = "1m", keyType = RateLimitKeyType.USER)
@PostMapping("/api/user-endpoint")
```

### 커스텀 메시지
```java
@RateLimit(requests = 3, window = "5m", 
           message = "비밀번호 변경 요청이 너무 많습니다. 5분 후 다시 시도해주세요.")
@PostMapping("/api/change-password")
```

### 개발 환경에서 비활성화
```java
@RateLimit(requests = 5, window = "1m", enabled = false)  // 개발 시 비활성화
@PostMapping("/api/test-endpoint")
```

## 📊 Rate Limit 초과 시 응답

### HTTP 상태 코드
- **429 Too Many Requests**

### 응답 형식
```json
{
  "success": false,
  "message": "로그인 시도가 너무 많습니다. 1분 후 다시 시도해주세요.",
  "data": null
}
```

## 🚨 보안 로깅

Rate Limit 초과 시 자동으로 로그에 기록됩니다:

```
WARN - 🚨 Rate Limit 초과 - 키: rate_limit:/api/member/login:192.168.1.100, 요청 수: 6/5
```

### 로그 항목
- **키**: Rate Limit 식별자
- **현재 요청 수**: 현재 윈도우에서의 요청 횟수
- **제한 횟수**: 허용된 최대 요청 횟수
- **클라이언트 IP**: 요청한 IP 주소

## 💡 실제 사용 예시

### 정상적인 사용 (허용)
```bash
# 1분 내 5번 로그인 시도
POST /api/member/login (1번째) ✅
POST /api/member/login (2번째) ✅
POST /api/member/login (3번째) ✅
POST /api/member/login (4번째) ✅
POST /api/member/login (5번째) ✅
```

### Rate Limit 초과 (차단)
```bash
POST /api/member/login (6번째) ❌ 429 Too Many Requests
Response: {
  "success": false,
  "message": "로그인 시도가 너무 많습니다. 1분 후 다시 시도해주세요."
}
```

## 🔄 새로운 API에 Rate Limit 추가

### 1단계: 어노테이션 추가
```java
@RateLimit(requests = 15, window = "1m", keyType = RateLimitKeyType.USER,
           message = "채팅 전송이 너무 빠릅니다. 잠시 후 다시 시도해주세요.")
@PostMapping("/api/chat/send")
public ResponseEntity<?> sendMessage(@RequestBody ChatRequest request) {
    // 구현
}
```

### 2단계: 자동 적용
- 인터셉터가 자동으로 감지하여 Rate Limit 적용
- 별도 설정 불필요

## ⚙️ 설정 조정

### 캐시 설정 (RateLimitInterceptor.java)
```java
this.requestCounts = Caffeine.newBuilder()
    .maximumSize(10000)  // 최대 저장할 키 개수
    .expireAfterWrite(Duration.ofHours(1))  // 자동 삭제 시간
    .build();
```

### 인터셉터 경로 설정 (WebMvcConfig.java)
```java
registry.addInterceptor(rateLimitInterceptor)
    .addPathPatterns("/api/**")      // 적용 경로
    .excludePathPatterns(
        "/api/public/**",            // 제외 경로
        "/api/health/**"
    );
```

## 🔍 모니터링 및 분석

### Rate Limit 현황 확인
- 로그 파일에서 `🚨 Rate Limit 초과` 검색
- 공격 패턴 분석 가능

### 주요 지표
- **차단된 요청 수**: 보안 위협 수준
- **자주 차단되는 IP**: 잠재적 공격자
- **차단되는 API**: 공격 대상 파악

## 🚀 향후 확장 계획

### Redis 기반 분산 처리 (필요시)
```java
@RateLimit(requests = 100, window = "1h", storage = "REDIS")
@PostMapping("/api/high-traffic-endpoint")
```

### 동적 제한 조정
```java
@RateLimit(requests = 5, window = "1m", 
           dynamicLimit = "#{@securityService.getLoginLimit()}")
```

### 사용자별 차등 제한
```java
@RateLimit(requests = 10, window = "1m", 
           premiumMultiplier = 2)  // 프리미엄 사용자는 2배
```

## 📋 트러블슈팅

### Rate Limit이 작동하지 않는 경우
1. **WebMvcConfig 확인**: 인터셉터가 제대로 등록되었는지
2. **경로 패턴 확인**: excludePathPatterns에 포함되지 않았는지
3. **어노테이션 위치**: @PostMapping 위에 @RateLimit가 있는지

### 개발 환경에서 불편한 경우
```java
@RateLimit(requests = 1000, window = "1m")  // 개발용 높은 제한
// 또는
@RateLimit(enabled = false)  // 완전 비활성화
```

### 성능 이슈가 있는 경우
- Caffeine Cache 크기 조정
- 윈도우 시간 단축
- 제한 횟수 증가 고려

이제 안전하고 효율적인 Rate Limiting 시스템이 구축되었습니다! 🚦✨
