# ALEPH_08 — 내 소개 페이지에 패스키 달기

ALEPH_01의 공개 소개 원본을 유지하고, 패스키로만 인증하는 개인 공간을 추가했습니다. 작전/Defense 과제와는 별개입니다. 비공개 내용은 계정별로 생성하는 가상 학습 자료 3개입니다.

- 결과물: https://yc-aleph-08-passkey.ksyji123.chatgpt.site/
- 공개 소스: https://yc-aleph-08-passkey.ksyji123.chatgpt.site/source
- 설명서: https://yc-aleph-08-passkey.ksyji123.chatgpt.site/submission
- 과제 1 원본: https://github.com/ychanis/ALEPH_01

## 소스 구조

- `public/original/`: 과제 1 원본 HTML·CSS·JS (변경 없이 유지)
- `app/page.tsx`: 공개 소개와 개인 공간의 경계
- `app/private-space.tsx`: 등록·로그인·로그아웃·목록·삭제·검사·기록 다운로드 UI
- `app/api/[...path]/route.ts`: API 진입점, 고정 Origin
- `lib/passkey.ts`: 질문 보관·소비, 실제 WebAuthn 검증, 세션·소유권 검사
- `db/schema.ts`, `drizzle/`: 영속 DB 스키마 및 마이그레이션
- `tests/passkey.test.mjs`: P-256 소프트웨어 인증기를 사용하는 서버 검사
- `docs/IMPLEMENTATION.md`: 인증 구현 설명서 6항목, 확인 방법 4줄, AI와 내 판단 3줄
- `docs/automated-evidence.json`: 자동 검사 요청·응답과 저장 공개키 (운영 비밀값 없음)
- `docs/DEVICE-CHECK.md`: 실제 기기 확인 결과와 미완료 항목

## 인증

SimpleWebAuthn server 14.0.3 / browser 14.0.0, React, Vinext, Cloudflare Workers + D1. 패스키 개인키는 서버에 저장하지 않습니다. 질문은 120초 만료이며 DB에서 원자적으로 한 번만 소비합니다. 로그인 서명·Origin·RP ID·사용자 확인을 검사합니다. 인증 세션은 HttpOnly·Secure·SameSite=Strict 쿠키이고 서버에는 토큰 해시만 저장합니다. 등록 취소는 아무 계정이나 키도 만들지 않습니다. 처음 등록은 항상 새 무작위 계정을 만들고, 예비 키는 인증한 본인 계정에만 추가합니다.

## 검사

Node.js 24 이상 권장. 의존성 설치 후 다음을 실행합니다.

```bash
node --experimental-transform-types tests/passkey.test.mjs
node node_modules/typescript/bin/tsc --noEmit
```

자동 보안 검사 30개가 통과했습니다. 실제 기기에서 Google 패스키 첫 등록·로그아웃·재로그인·질문 재사용 차단·틀린 서명 차단을 확인했습니다. 비로그인 접근 차단 및 등록 취소 안내·잠금 유지는 사용자 확인 보고로 기록했습니다. 두 패스키 등록·삭제 후 로그인과 A/B 양방향 접근 차단은 실제 기기 미완료이며 자동 검사 통과로만 구분합니다. 상세 근거는 docs/DEVICE-CHECK.md를 참고하세요.

배포는 이 프로젝트의 Sites 연결 저장소와 Workers+D1을 사용합니다. Vercel 정적 배포만으로는 이 서버·DB가 동작하지 않습니다. 다른 호스팅으로 옮길 때 API와 DB 어댑터를 함께 이식하고 RP ID·Origin을 새 주소로 맞춰야 하며 기존 패스키를 다른 도메인에서 사용할 수 없습니다.

## 제한

마지막 키를 잃거나 지우면 복구하지 못합니다. 로그인 중인 기기를 타인이 사용하면 세션이 악용될 수 있고 키 삭제 전 재인증·운영 수준 속도 제한은 아직 없습니다. 모든 예시 자료는 가상이며 실제 개인정보나 민감자료를 보관하지 않습니다.
