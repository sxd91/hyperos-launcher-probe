# hyperos-launcher-probe

HyperOS 4 系统桌面（`com.miui.home`）逆向**侦察模块**。基于 libxposed API 102，跑在 LSPosed 上。

## 为什么需要先侦察

目标 APK 的 `AndroidManifest.xml` 里写着：

```xml
<application android:hasCode="false" ...>
```

包里**不存在任何 `classes.dex` / `smali`**（apktool 产物与原始 APK 双向核对，`original/META-INF/MANIFEST.MF` 条目里也没有 `classes.dex`）。但 Manifest 又声明了：

- `com.miui.home.launcher.Launcher`（HOME）
- `com.miui.home.recents.RecentsActivity`
- `com.miui.home.miclaw.LauncherToolService`（AI 工具入口）
- `com.miui.home.model.core.LauncherProvider` 等一堆 Provider
- `com.rust.hyper_launcher.recents.TouchInteractionService`（注意 `com.rust.` 前缀）

并且：

```xml
<uses-library android:name="hyperos.rustruntime.v5" android:required="true" />
```

对应 `/product/etc/permissions/rustruntime_cfg_v3_v5.xml` →

```xml
<library name="hyperos.rustruntime.v5" file="/system_ext/framework/hyperos.rustruntime.jar" />
```

而 `/system_ext/framework/hyperos.rustruntime.jar` **只有 898 字节**，内部仅一个 `classes.dex`（2246 字节），只含 `rust.core.runtime.Empty` 一个空类。

结论：**真正的实现类由 Rust Runtime 在进程运行时动态定义**（JNI DefineClass / RegisterNatives 路线）。

所以 `Class.forName("com.miui.home.miclaw.LauncherToolService")` 在早期必然 `ClassNotFoundException`，必须先把三件事问清楚：

1. 类在什么时机被定义；
2. 挂在哪个 `ClassLoader` 上；
3. `handleSettingsTool` 的真实签名。

## 本模块做什么

**只观测，不改行为。**

| 观测点 | 目的 |
| --- | --- |
| `ClassLoader.loadClass(String)` / `(String, boolean)` | 抓所有类加载，命中 `com.miui.home.` / `com.rust.` / `rust.core.` / `androidx.appfunctions.` 前缀时落日志 |
| `dalvik.system.BaseDexClassLoader.findClass(String)` | 区分 dex 加载来源 |
| `dalvik.system.InMemoryDexClassLoader` 全部构造器 | 判断是否走内存 dex 动态定义 |
| `ActivityThread.handleCreateService` / `handleBindService` | 服务实例创建/绑定瞬间拿到真实 `Class` |
| `Application.attach(Context)` | 拿宿主 `Context` 落日志文件 |
| 定时轮询 `Class.forName` | 0/0.5/1.5/3/6/10/15/20/30/60 秒共 10 轮，跨多个 ClassLoader 探测 14 个候选类 |
| `LauncherToolService.handleSettingsTool` | 一旦类被解析出来，立刻 dump 全量成员并挂进出参打印 |

## 日志位置

- **logcat**：tag = `HyperOSProbe`（用 `adb logcat -s HyperOSProbe` 看）
- `/data/data/com.miui.home/files/hyperos_probe.log`
- `/sdcard/Android/data/com.miui.home/files/hyperos_probe.log`（免 root 直接拉）

## 使用步骤

1. 等 CI 出包，下载 `hyperos-launcher-probe-unsigned` artifact
2. 安装：`adb install -r hyperos-launcher-probe-unsigned.apk`
3. 在 LSPosed 管理器里启用模块，**作用域勾选「系统桌面 / com.miui.home」**
4. 强制停止系统桌面让它重新起进程：`adb shell am force-stop com.miui.home`，然后按 Home 键
5. 抓日志：
   ```bash
   adb logcat -c && adb logcat -s HyperOSProbe
   # 或者
   adb pull /sdcard/Android/data/com.miui.home/files/hyperos_probe.log
   ```
6. 顺手点几下桌面设置（无字模式、锁定布局之类）触发 `LauncherToolService`

## 看什么

重点在这几行：

```
[probe:+Xms] FOUND com.miui.home.miclaw.LauncherToolService via <loader>
[class] com.miui.home.miclaw.LauncherToolService | loader=... | super=...
---- dump com.miui.home.miclaw.LauncherToolService ----
  method   : ...handleSettingsTool(...)
---- end dump ----
[ok] hooked tool_handleSettingsTool -> ...
[tool:in]  args=[0=java.lang.String=get, 1=java.lang.String=screen_grid, 2=null]
[tool:out] result=...
```

拿到 `method` 那一行的完整签名 + `loader` 的值，下一步就能定路线了：

- 类由 `PathClassLoader` 提供 → 纯 Java Hook 可行
- 类由 `InMemoryDexClassLoader` 提供 → 仍可 Java Hook，但必须在定义之后
- 只在 native 侧（Rust）暴露 → 转 native Hook `libapp_launcher.so` / `libresources_frb.so`

## 构建

**不本地构建 APK**，一律走 GitHub Actions。

```bash
git init && git add -A && git commit -m "feat: HyperOS 桌面侦察模块"
git remote add origin git@github.com:<you>/hyperos-launcher-probe.git
git push -u origin main
```

## 技术栈

- AGP 9.3.1 / Kotlin 2.4.10 / JVM 21
- `io.github.libxposed:api:102.0.0`（`compileOnly`，运行时由框架提供）
- minSdk 33 / targetSdk 36 / compileSdk 36
- libxposed 模块描述符：`app/src/main/resources/META-INF/xposed/{module.prop,java_init.list,scope.list}`
