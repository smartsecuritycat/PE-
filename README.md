# PE Analyzer

C 언어를 사용해 Windows PE(Portable Executable) 파일의 구조를 직접 읽고 분석하는 학습용 프로젝트입니다.

이 프로젝트는 단순히 PE 파일을 파싱하는 것뿐 아니라, C 언어의 **파일 입출력, 구조체, 포인터, 반복문, 조건문, 비트 연산**을 실제 프로그램에 적용해 익히는 것을 목표로 합니다.

또한 향후 취약점 분석 및 리버싱 학습을 위해 PE 파일의 기본 구조와 보안 관련 속성을 이해하는 것을 목표로 합니다.

---

## 1. 프로젝트 목표

이 프로젝트의 주요 목표는 다음과 같습니다.

- C 언어로 바이너리 파일 읽기
- Windows PE 파일 구조 이해
- DOS Header / PE Header / Optional Header 분석
- Section Table 분석
- x86 / x64 / ARM64 구분
- Entry Point 및 Image Base 출력
- ASLR / DEP / CFG 여부 확인
- Section의 Read / Write / Execute 권한 확인
- 실행 가능 + 쓰기 가능(RWX 계열) Section 탐지

---

## 2. PE 파일이란?

PE는 **Portable Executable**의 약자로, Windows에서 사용하는 실행 파일 형식입니다.

대표적으로 다음 파일들이 PE 형식을 사용합니다.

- `.exe`
- `.dll`
- `.sys`

PE 파일은 대략 다음과 같은 구조를 가집니다.

```text
PE File
│
├── DOS Header
│   ├── e_magic ("MZ")
│   └── e_lfanew
│
├── DOS Stub
│
├── PE Signature ("PE\0\0")
│
├── File Header
│   ├── Machine
│   └── NumberOfSections
│
├── Optional Header
│   ├── AddressOfEntryPoint
│   ├── ImageBase
│   └── DllCharacteristics
│
├── Section Table
│
└── Sections
    ├── .text
    ├── .data
    ├── .rdata
    ├── .rsrc
    └── .reloc
```

---

## 3. 각 PE 영역의 역할

### DOS Header

PE 파일의 가장 앞부분에 존재합니다.

현재 프로그램에서는 주로 다음 값을 확인합니다.

- `e_magic`
  - 정상적인 PE 계열 파일이라면 `MZ` 값을 가집니다.
- `e_lfanew`
  - PE Header가 파일의 어느 위치에서 시작하는지 알려줍니다.

C 코드에서는 다음과 같이 사용합니다.

```c
if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
{
    printf("[-] This is not a valid PE file.\n");
}
```

그리고 `e_lfanew`를 사용해 PE Header 위치로 이동합니다.

```c
fseek(fp, dosHeader.e_lfanew, SEEK_SET);
```

---

### PE Signature

PE Header 시작 위치에는 다음 Signature가 존재합니다.

```text
PE\0\0
```

프로그램에서는 다음 값과 비교합니다.

```c
IMAGE_NT_SIGNATURE
```

---

### File Header

File Header에서는 PE 파일의 기본 정보를 확인할 수 있습니다.

현재 분석하는 주요 정보는 다음과 같습니다.

- CPU Architecture
- Section 개수

예:

```text
Architecture : x64
Sections     : 6
```

지원하는 Architecture:

- x86
- x64
- ARM64

---

### Optional Header

이름은 Optional Header이지만 실행 파일 분석에서 매우 중요한 정보가 들어 있습니다.

현재 프로그램에서는 다음 값을 읽습니다.

- PE32 / PE32+ 구분
- Entry Point
- Image Base
- ASLR
- DEP
- CFG

예:

```text
PE Type      : PE32+ (64-bit)
Entry Point  : 0x00001240
Image Base   : 0x0000000140000000
```

---

### Section Table

Section Table은 각 Section의 위치, 크기, 권한을 설명합니다.

예:

```text
Name      RVA          VirtualSize  RawSize      Perm
----------------------------------------------------------
.text     0x00001000   0x00007200   0x00007400   R-X
.rdata    0x00009000   0x00003200   0x00003400   R--
.data     0x0000D000   0x00000800   0x00000600   RW-
```

권한 의미:

- `R` : Read
- `W` : Write
- `X` : Execute

쓰기와 실행 권한이 동시에 존재하는 Section이 발견되면 다음과 같이 표시합니다.

```text
[!] Writable + Executable
```

---

## 4. 현재 기능

현재 구현된 기능:

- [x] PE 파일 열기
- [x] DOS Header 읽기
- [x] MZ Signature 검사
- [x] PE Signature 검사
- [x] CPU Architecture 확인
- [x] PE32 / PE32+ 구분
- [x] Section 개수 출력
- [x] Entry Point 출력
- [x] Image Base 출력
- [x] ASLR 확인
- [x] DEP 확인
- [x] CFG 확인
- [x] Section 이름 출력
- [x] RVA 출력
- [x] Virtual Size 출력
- [x] Raw Size 출력
- [x] R/W/X 권한 출력
- [x] Writable + Executable Section 경고

---

## 5. C 언어 학습 포인트

이 프로젝트는 PE 파일 분석뿐 아니라 C 언어 학습을 위해 진행합니다.

### FILE 포인터

```c
FILE* fp;
```

파일을 다루기 위한 포인터입니다.

---

### 파일 열기

```c
fopen_s(&fp, argv[1], "rb");
```

`rb`는 Binary Read 모드를 의미합니다.

PE 파일은 텍스트 파일이 아닌 바이너리 파일이므로 Binary 모드로 읽습니다.

---

### 구조체

Windows에서 정의한 PE 구조체를 사용합니다.

예:

```c
IMAGE_DOS_HEADER dosHeader;
IMAGE_FILE_HEADER fileHeader;
IMAGE_SECTION_HEADER section;
```

구조체의 멤버에는 `.` 연산자를 이용해 접근합니다.

```c
dosHeader.e_magic
dosHeader.e_lfanew
fileHeader.NumberOfSections
```

---

### sizeof

```c
sizeof(IMAGE_DOS_HEADER)
```

자료형이나 구조체의 메모리 크기를 구할 때 사용합니다.

---

### fread

```c
fread(
    &dosHeader,
    sizeof(IMAGE_DOS_HEADER),
    1,
    fp
);
```

파일에서 데이터를 읽어 구조체에 저장합니다.

---

### fseek

```c
fseek(fp, dosHeader.e_lfanew, SEEK_SET);
```

파일 내부의 특정 위치로 이동합니다.

---

### 반복문

Section이 여러 개 존재하므로 `for` 반복문을 이용합니다.

```c
for (int i = 0; i < fileHeader.NumberOfSections; i++)
{
    ...
}
```

---

### 비트 연산

PE 파일의 권한과 보안 옵션은 비트 플래그 형태로 저장됩니다.

예:

```c
if (characteristics & IMAGE_SCN_MEM_WRITE)
{
    ...
}
```

이 코드는 Write 권한 비트가 설정되어 있는지 확인합니다.

---

## 6. 개발 환경

- Language: C
- OS: Windows
- IDE: Visual Studio
- API / Header: Windows API (`windows.h`)

---

## 7. 빌드 및 실행

Visual Studio에서 C 콘솔 프로젝트로 빌드할 수 있습니다.

소스 파일:

```text
main.c
```

실행 예시:

```powershell
PEAnalyzer.exe test.exe
```

또는 실행 파일의 전체 경로를 입력할 수 있습니다.

```powershell
PEAnalyzer.exe C:\Windows\System32\notepad.exe
```

---

## 8. 예상 출력 예시

```text
=== PE Analyzer ===

[DOS Header]
MZ Signature : Valid
PE Offset    : 0x00000100

[PE Header]
PE Signature : Valid
Architecture : x64
Sections     : 6
PE Type      : PE32+ (64-bit)
Entry Point  : 0x00001240
Image Base   : 0x0000000140000000

[Security]
ASLR : Enabled
DEP  : Enabled
CFG  : Enabled

[Sections]

Name      RVA          VirtualSize  RawSize      Perm
----------------------------------------------------------
.text     0x00001000   0x00007200   0x00007400   R-X
.rdata    0x00009000   0x00003200   0x00003400   R--
.data     0x0000D000   0x00000800   0x00000600   RW-
```

---

## 9. 향후 추가 예정 기능

앞으로 다음 기능들을 단계적으로 추가할 예정입니다.

- [ ] Import Table 분석
- [ ] DLL 목록 출력
- [ ] Import API 목록 출력
- [ ] Export Table 분석
- [ ] RVA -> File Offset 변환
- [ ] 의심 API 탐지
- [ ] PE Header 상세 출력
- [ ] Section Entropy 계산
- [ ] 패킹 의심 여부 확인
- [ ] 간단한 정적 보안 분석 결과 출력

예를 들어 다음과 같은 API를 사용하는지 확인하는 기능을 추가할 수 있습니다.

```text
VirtualAlloc
VirtualProtect
WriteProcessMemory
CreateRemoteThread
LoadLibrary
GetProcAddress
```

이러한 기능을 추가하면서 PE 구조와 Windows 프로그램의 동작 방식을 더 깊게 학습할 예정입니다.

---

## 10. 프로젝트 진행 목적

본 프로젝트는 학교 C 언어 개인 과제로 시작했습니다.

단순한 문법 연습용 프로그램보다는 C 언어가 실제 시스템 프로그래밍에서 어떻게 사용되는지 경험하기 위해 PE 파일 분석기를 주제로 선택했습니다.

PE 파일을 직접 읽고 분석하는 과정에서 다음 내용을 함께 학습하는 것이 목적입니다.

- C 언어
- 바이너리 파일 구조
- 메모리 구조
- Windows 실행 파일
- 리버싱 기초
- 정적 분석 기초
- 취약점 분석 기초

최종적으로는 단순 PE Viewer에서 시작해 **간단한 정적 PE 보안 분석 도구**로 발전시키는 것을 목표로 합니다.
