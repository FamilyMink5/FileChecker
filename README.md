# Discord File Scanner Bot
## 디스코드 파일 검사 봇

### 🔍 Overview | 개요
This Discord bot provides automated file scanning capabilities to ensure the safety of files shared within Discord servers. It scans both direct file uploads and files shared through URLs, utilizing VirusTotal's API for comprehensive malware detection.

이 디스코드 봇은 디스코드 서버 내에서 공유되는 파일의 안전성을 확인하기 위한 자동 파일 검사 기능을 제공합니다. VirusTotal API를 활용하여 직접 업로드된 파일과 URL을 통해 공유된 파일을 포괄적으로 검사합니다.

### ⚙️ Key Features | 주요 기능
1. **File Scanning | 파일 검사**
   - Automatic scanning of uploaded files
   - Support for multiple file formats
   - Real-time safety analysis
   - 업로드된 파일 자동 검사
   - 다양한 파일 형식 지원
   - 실시간 안전성 분석

2. **URL Processing | URL 처리**
   - URL safety verification
   - Automatic file downloading from URLs
   - Safe URL confirmation
   - URL 안전성 검증
   - URL에서 자동 파일 다운로드
   - 안전한 URL 확인

3. **Safety Analysis | 안전성 분석**
   - Integration with VirusTotal API
   - Multiple scanning engines
   - Detailed threat analysis
   - VirusTotal API 연동
   - 다중 검사 엔진
   - 상세 위협 분석

4. **File Management | 파일 관리**
   - Organized file storage structure
   - Automated file organization
   - Historical record maintenance
   - 체계적인 파일 저장 구조
   - 자동화된 파일 정리
   - 이력 기록 유지

### 💾 File Storage Structure | 파일 저장 구조
```
D:/Temp/
├── {Server Name}
│   ├── {Channel Name}
│   │   └── {Timestamp}
│   │       └── {Original File}
```

### 🛡️ Security Features | 보안 기능
- **File Type Verification | 파일 형식 검증**
  - Whitelist-based file extension control
  - Automated file type checking
  - 화이트리스트 기반 파일 확장자 관리
  - 자동 파일 형식 확인

- **Malware Detection | 악성코드 탐지**
  - Multi-engine virus scanning
  - Comprehensive threat detection
  - 다중 엔진 바이러스 검사
  - 종합적인 위협 탐지

- **URL Safety | URL 안전성**
  - URL safety verification
  - Malicious link blocking
  - URL 안전성 검증
  - 악성 링크 차단

### 📊 Reporting | 결과 보고
- **Detailed Analysis Reports | 상세 분석 보고서**
  - Scan results visualization
  - Threat level indication
  - Safety statistics
  - 검사 결과 시각화
  - 위협 수준 표시
  - 안전성 통계

- **Admin Notifications | 관리자 알림**
  - Automatic admin mentions for threats
  - Webhook integration for detailed logs
  - 위협 발견 시 자동 관리자 멘션
  - 상세 로그를 위한 웹훅 연동

### ⚡ Performance | 성능
- **API Rate Limiting | API 속도 제한**
  - Smart API key rotation
  - Request queue management
  - 스마트 API 키 로테이션
  - 요청 대기열 관리

- **Error Handling | 오류 처리**
  - Robust error recovery
  - Automatic retry mechanisms
  - 강력한 오류 복구
  - 자동 재시도 메커니즘

### 📝 Logging | 로깅
- **Comprehensive Logging | 종합적인 로깅**
  - Detailed operation logs
  - Debug information
  - Error tracking
  - 상세 작동 로그
  - 디버그 정보
  - 오류 추적

### 🔧 Configuration | 설정
Required Environment Variables | 필수 환경 변수:
- `DISCORD_TOKEN`: Discord bot token | 디스코드 봇 토큰
- `VT_API_KEY_1` to `VT_API_KEY_8`: VirusTotal API keys | 바이러스토탈 API 키키
- `ADMIN_USER_ID`: Discord admin user ID | 디스코드 어드민의 유저 ID
- `WEBHOOK_URL`: Discord webhook URL for detailed logs | 상세한 정보를 위한 채널의 웹후크크
- `SAFE_BROWSING_API_KEY`: Google Safe Browsing API key | 구글 세이프 브라우징 API 키키

### ⚠️ Limitations | 제한 사항
- Maximum file size: 8MB (Discord limit)
- API rate limits: 4 requests per minute per API key
- 최대 파일 크기: 8MB (부스트가 없는 디스코드 서버의 제한)
- API 속도 제한: API 키당 분당 4개 요청

### 🔄 File Processing Flow | 파일 처리 흐름
1. File Upload/URL Share | 파일 업로드/URL 공유
2. Safety Check | 안전성 확인
3. Virus Scan | 바이러스 검사
4. Result Report | 결과 보고
5. File Storage | 파일 저장