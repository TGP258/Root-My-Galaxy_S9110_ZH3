# Root My Galaxy

<img width="108" height="108" alt="sprout_icon_108" src="https://github.com/user-attachments/assets/2ba0e360-0876-489c-b256-f75df7589785" />


Root My Galaxy is a one-click installer for explicitly
supported Samsung model and kernel combinations. The application itself is kept separate
from device offsets, native exploit payloads, and KernelSU build artifacts.


[Latest release](https://github.com/BuSung-dev/Root-My-Galaxy/releases)

The device feed and native payloads are maintained in
[Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads).

## Application


<img width="200" alt="KakaoTalk_20260718_170922353" src="https://github.com/user-attachments/assets/3f562ea4-8c39-4ade-bfd3-93eea1a1cc24" />
<img width="200" alt="KakaoTalk_20260718_171127319" src="https://github.com/user-attachments/assets/8dde0443-12cf-4058-ba76-0337aefb92a0" />
<img width="200" alt="KakaoTalk_20260718_171030202" src="https://github.com/user-attachments/assets/f656e8af-60a6-4fcb-a3db-d4232bede613" />

The app selects a payload whose model list and three-part kernel version match
the phone. For example, `6.6.98-android15-8-...` matches `6.6.98`. Advanced
mode filters the catalog by both values and allows manual selection with model
and kernel-version warnings.

## Build

Requirements:

- Android Studio JBR 21
- Android SDK 37
- Android NDK 28 or newer
- CMake 3.22.1

```powershell
$env:JAVA_HOME='C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat :app:assembleDebug
```

Output:

```text
app/build/outputs/apk/debug/app-debug.apk
```

## Fork changes: SM-S9110 (S9110ZCS8FZH3)

This fork adds app-side support for one device: Galaxy S23 base model
`SM-S9110` (China, `dm1q`) on firmware `BP4A.251205.006.S9110ZCS8FZH3`, kernel
`5.15.189`. The native side stays in
[Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads):
the profile `dm1q-S9110ZCS8FZH3` and its derivation are in
`docs/SM-S9110-S9110ZCS8FZH3.md` there.

Embedded artifacts:

| Asset | Size | SHA-256 |
| --- | --- | --- |
| `app/src/main/assets/payloads/cve-2026-43499-app.so` | 104128 | `d6347f5855e049e23bb23107edd5e81912ae55b40a92c89bd5b7391ed58a82aa` |
| `app/src/main/assets/payloads/ksud-s25u-kdp` | 4879560 | `5da5818d36da2d589496f91016078a43f50489e5c98b319db4eaa5ee475b86bd` |

The file name `ksud-s25u-kdp` is fixed by the root helper, which stages the
loader at `/data/local/tmp/ksud-s25u-kdp`. Its bytes are the
`android13-5.15.189` no-patch-text build, identical to
`kernelsu/ksud-dm2q-S916BXXSAFZG1-kdp` in the payloads repository. Both `size`
fields in `localOverrides` must stay equal to the asset sizes: the app rejects
a payload whose byte count differs.

Code changes:

- `SupportManifest.kt`, `PayloadRepository.kt` - `RemoteArtifact` gained an
  optional `asset` path. A profile that sets it is staged from the APK's own
  assets and no network request is made, so a device that matches an embedded
  profile installs offline.
- `PayloadRepository.kt` - a failed support-manifest fetch no longer discards
  the profiles that are already known. `loadTargets()` merges the embedded
  overrides with whatever the remote feed returned, `resolveTarget()` prefers
  the embedded profile, and embedded artifact URLs are not pinned to a commit
  because they are never downloaded.
- `MainActivity.kt` - a run in `Checking`, `Downloading`, `Exploiting` or
  `LoadingKernelSu` shows `install_preparing` instead of the "tap to start"
  hint, so a slow stage is not read as a dead button.

The payload must stay a bionic shared library: it is `LD_PRELOAD`ed into
`/system/bin/sh` or `dlopen`ed by the root helper, and a glibc-linked ELF fails
with `ld-linux-aarch64.so.1 not found`.

```powershell
Get-FileHash app\src\main\assets\payloads\* -Algorithm SHA256
```

Use only on devices you own or are explicitly authorized to test.
