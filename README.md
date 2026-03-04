# ReSource — DLL → Source Recovery Tool

DLL/EXE 바이너리를 읽어서 C/C++ 또는 C# 소스코드로 복원하는 도구입니다.

- **Native DLL** → IDA Pro 헤드리스 분석 → C/C++ 소스 복원
- **.NET DLL** → ilspycmd 디컴파일 → C# 프로젝트 복원

---

## 기능

- **완전 자동화** — UI에서 DLL 선택 한 번으로 전체 파이프라인 실행
- **IDA Pro 헤드리스 모드** — `idat64.exe`를 자동 실행, GUI 없이 분석
- **IDA MCP 플러그인 모드** — 실행 중인 IDA Pro GUI에 연결해서 분석
- **.NET 어셈블리 지원** — PE 헤더로 자동 감지 후 `ilspycmd` 파이프라인 전환
- **참조 어셈블리 지정** — Unity/BepInEx/MelonLoader 등 의존 폴더를 등록하면 타입 해석 품질 향상
- **모듈 분류** — 콜그래프 클러스터링으로 함수를 논리적 모듈로 분류
- **Jinja2 템플릿 출력** — `.c` / `.h` / `README_recovered.md` 자동 생성

## 스크린샷

| 탭 | 설명 |
|----|------|
| Input | DLL 경로·모드·IDA 설정 |
| Analysis | 실시간 로그 + 진행률 |
| Functions | 복원된 함수 목록 (주소·이름·신뢰도) |
| Code Viewer | 디컴파일 소스 뷰어 |
| Export | 출력 파일 목록 |

---

## 요구사항

| 항목 | 버전 |
|------|------|
| Python | 3.10+ |
| PyQt6 | 6.x |
| IDA Pro | 8.x (헤드리스 모드) |
| ilspycmd | 9.x (.NET 모드) |

```bash
# ilspycmd 설치
dotnet tool install -g ilspycmd
```

## 설치

```bash
git clone --recurse-submodules https://github.com/needitem/resource-recover.git
cd resource-recover

pip install -e ".[dev]"

cp settings.json.example settings.json
# settings.json 에서 ida_dir 경로 수정
```

## 설정 (settings.json)

```json
{
  "mcp_mode": "headless",
  "ida_dir": "C:\\Program Files\\IDA Pro",
  "idat_timeout": 600.0,
  "max_workers": 3,
  "decompile_timeout": 30.0,
  "retry_count": 2,
  "artifacts_dir": "artifacts",
  "outputs_dir": "outputs",
  "dotnet_ref_paths": []
}
```

| 키 | 설명 |
|----|------|
| `mcp_mode` | `"headless"` 또는 `"ida_plugin"` |
| `ida_dir` | IDA Pro 설치 폴더 (헤드리스 모드) |
| `idat_timeout` | idat64.exe / ilspycmd 타임아웃 (초) |
| `dotnet_ref_paths` | .NET 참조 어셈블리 폴더 목록 (타입 해석 품질 향상) |

### .NET 참조 경로 예시

**Mono 게임 (BepInEx):**
```json
"dotnet_ref_paths": [
  "C:/Games/MyGame/MyGame_Data/Managed",
  "C:/Games/MyGame/BepInEx/core"
]
```

**Il2Cpp 게임 (MelonLoader):**
```json
"dotnet_ref_paths": [
  "C:/Games/MyGame/MelonLoader/Il2CppAssemblies",
  "C:/Games/MyGame/MelonLoader/net6"
]
```

게임 타입에 맞는 어셈블리 폴더를 등록하면
`//IL_xxxx: Unknown result type` 주석 없이 깔끔하게 디컴파일됩니다.

## 실행

```bash
python -m app.main
```

## 파이프라인 구조

```
DLL 입력
  │
  ├─ .NET 감지 (PE DataDirectory[14])
  │    └─ ilspycmd --project → .cs/.csproj
  │
  └─ Native
       ├─ headless: idat64.exe -A -S collect_artifacts.py
       └─ plugin:   IDA MCP (localhost:13337)
            │
            ▼
       Extractor → FunctionArtifact[]
            │
       TypeRefiner → 타입 정제
            │
       ModuleClassifier → 콜그래프 클러스터링
            │
       Reconstructor → RecoveredProject
            │
       Exporter → .c / .h / README
```

## 서브모듈

- [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp) — IDA Pro MCP 서버 플러그인

## 라이선스

MIT
