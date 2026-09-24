package cn.nizou.hyperosprobe

import android.app.Application
import android.app.Service
import android.content.Context
import android.util.Log
import io.github.libxposed.api.XposedInterface
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface
import java.io.File
import java.lang.reflect.Constructor
import java.lang.reflect.Executable
import java.lang.reflect.Method
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * HyperOS 4 系统桌面（com.miui.home）逆向侦察模块 —— libxposed API 102 / LSPosed。
 *
 * ## 背景（为什么必须先侦察）
 * 目标 APK 的 AndroidManifest.xml 里写着 `android:hasCode="false"`，包内不存在任何
 * `classes.dex` / `smali`。但 Manifest 又声明了 Launcher、RecentsActivity、
 * LauncherToolService、LauncherProvider 等一大堆 Java 组件，并且 uses-library 引用
 * `hyperos.rustruntime.v5` —— 实体 `/system_ext/framework/hyperos.rustruntime.jar`
 * 只有 898 字节，内部仅一个 `rust.core.runtime.Empty` 空类。
 *
 * 结论：真正的实现类由 Rust Runtime 在进程运行时动态定义。于是必须先问清楚三件事：
 *   1. 类在什么时机被定义；
 *   2. 挂在哪个 ClassLoader 上；
 *   3. `handleSettingsTool` 的真实签名是什么。
 *
 * ## 致命时机问题（本模块最关键的一点）
 * libxposed API 102 的生命周期回调里：
 *   - `onPackageLoaded` / `onPackageReady` 的文档明确写着「a hasCode package is loaded」，
 *     **只有 hasCode=true 的包才会触发**；
 *   - `onModuleLoaded` 是唯一必然触发的回调。
 *
 * com.miui.home 是 hasCode=false，所以任何把 hook 安装写在 onPackageReady 的模块都
 * 完全不会工作。本模块因此把全部安装逻辑放在 `onModuleLoaded`，用 `processName` 判进程。
 *
 * ## 本模块做什么（只观测，不改行为）
 *   - ClassLoader.loadClass(String) / loadClass(String, boolean)
 *   - ClassLoader.defineClass 全部重载（动态定义类的直接路径）
 *   - Class.forName(String, boolean, ClassLoader)
 *   - dalvik.system.BaseDexClassLoader.findClass(String)
 *   - dalvik.system.InMemoryDexClassLoader 全部构造器
 *   - dalvik.system.PathClassLoader 构造器（看加了哪些 dex 路径）
 *   - ActivityThread.handleCreateService / handleBindService / handleLaunchActivity
 *   - AppComponentFactory.instantiate{Activity,Service,Provider,Receiver,Application}
 *   - Application.attach(Context) → 拿 Context 落日志文件
 *   - 后台线程按 0/0.5/1.5/3/6/10/15/20/30/60 秒共 10 轮轮询 Class.forName 探测候选类
 *   - 命中目标类后 dump 全量成员，并挂上 handleSettingsTool 的进出参打印
 *
 * ## 日志位置
 *   - logcat：tag = HyperOSProbe
 *   - /data/data/com.miui.home/files/hyperos_probe.log
 *   - /sdcard/Android/data/com.miui.home/files/hyperos_probe.log（免 root 直接拉）
 */
class ProbeModule : XposedModule() {

    companion object {
        private const val TAG = "HyperOSProbe"

        /** 目标宿主包名。 */
        private const val HOST_PACKAGE = "com.miui.home"

        /** 关注前缀：命中即落日志。 */
        private val WATCH_PREFIXES = listOf(
            "com.miui.home.",
            "com.rust.",
            "rust.core.",
            "androidx.appfunctions.",
            "android.app.appfunctions.",
            "com.hyperos.",
        )

        /** 定时轮询的候选类全名。 */
        private val TARGET_CLASSES = listOf(
            // 本次 Hook 的主目标
            "com.miui.home.miclaw.LauncherToolService",
            // AppFunctions（Android 16 新框架）
            "com.miui.home.settings.GetDeviceStateMetadataCallee",
            "com.miui.home.settings.GetUncategorizedDeviceStateCallee",
            "com.miui.home.settings.SetDeviceStateCallee",
            "androidx.appfunctions.service.PlatformAppFunctionService",
            // 四大组件
            "com.miui.home.launcher.Launcher",
            "com.miui.home.launcher.AddItemActivity",
            "com.miui.home.launcher.SecondaryDisplayLauncher",
            "com.miui.home.recents.RecentsActivity",
            "com.miui.home.recents.settings.NavigationBarTypeActivity",
            "com.miui.home.settings.MiuiHomeSettingActivity",
            "com.miui.home.settings.IconCustomizeActivity",
            "com.miui.home.settings.SearchSettingsActivity",
            "com.miui.home.settings.AllAppsSettingsActivity",
            "com.miui.home.safemode.SafeLauncher",
            "com.rust.hyper_launcher.recents.TouchInteractionService",
            "com.miui.home.launcher.cloudbackup.BackupRestoreHomeService",
            "com.miui.home.isolate.provision.SetupWizardCompletedService",
            // Provider
            "com.miui.home.model.core.LauncherProvider",
            "com.miui.home.model.core.CategoryProvider",
            "com.miui.home.launcher.HideAppProvider",
            "com.miui.home.launcher.bigicon.IconSizeProvider",
            "com.miui.home.actionclient.AIActionProvider",
            "com.miui.home.settings.SettingsSearchProvider",
            "com.miui.home.provider.DumpLogProvider",
            "com.miui.home.recents.WindowVisibilityProvider",
            // Runtime 占位壳
            "rust.core.runtime.Empty",
        )

        private val df = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
        private val logLock = Any()

        @Volatile private var internalLog: File? = null
        @Volatile private var externalLog: File? = null
        @Volatile private var ctxReady = false

        private val seenClasses = ConcurrentHashMap.newKeySet<String>()
        private val dumpedClasses = ConcurrentHashMap.newKeySet<String>()
        private val definedClassNames = ConcurrentHashMap.newKeySet<String>()
        private val toolServiceHooked = newFlag()
        private val probeStarted = newFlag()
        private val hookCount = AtomicInteger(0)

        private fun newFlag() = AtomicBoolean(false)

        // ---------------------------------------------------------------- 日志

        private fun emit(msg: String) {
            Log.e(TAG, msg)
            if (!ctxReady) return
            val line = "${df.format(Date())} $msg\n"
            synchronized(logLock) {
                internalLog?.let { runCatching { it.appendText(line) } }
                externalLog?.let { runCatching { it.appendText(line) } }
            }
        }

        private fun emitBlock(lines: List<String>) {
            lines.forEach { emit(it) }
        }

        private fun initLogFiles(ctx: Context) {
            if (ctxReady) return
            synchronized(logLock) {
                if (ctxReady) return
                runCatching {
                    internalLog = File(ctx.filesDir, "hyperos_probe.log").also {
                        it.parentFile?.mkdirs()
                        it.writeText("")
                    }
                }.onFailure { Log.e(TAG, "init internal log failed: $it") }

                runCatching {
                    val dir = ctx.getExternalFilesDir(null)
                    if (dir != null) {
                        dir.mkdirs()
                        externalLog = File(dir, "hyperos_probe.log").also { it.writeText("") }
                    }
                }.onFailure { Log.e(TAG, "init external log failed: $it") }

                ctxReady = true
            }
        }

        // ---------------------------------------------------------------- 参数/字段工具

        /** 读 Chain 的第 index 个实参。API 102 只有 Chain.getArgs()，没有 HookParam。 */
        private fun argAt(chain: XposedInterface.Chain, index: Int): Any? =
            runCatching { chain.args.getOrNull(index) }.getOrNull()

        private fun describeArgs(chain: XposedInterface.Chain): String =
            runCatching {
                chain.args.withIndex().joinToString(separator = ", ", prefix = "[", postfix = "]") { (i, v) ->
                    val t = v?.javaClass?.name ?: "null"
                    val s = v?.toString() ?: "null"
                    "$i:$t=$s"
                }
            }.getOrElse { "args<?>: $it" }

        private fun fieldOf(target: Any?, name: String): Any? {
            if (target == null) return null
            var c: Class<*>? = target.javaClass
            while (c != null) {
                runCatching {
                    val f = c.getDeclaredField(name)
                    f.isAccessible = true
                    return f.get(target)
                }
                c = c.superclass
            }
            return null
        }

        private fun isWatched(name: String): Boolean =
            WATCH_PREFIXES.any { name.startsWith(it) }

        private fun shortStack(depth: Int = 8): String =
            runCatching {
                Throwable().stackTrace
                    .drop(3)
                    .take(depth)
                    .joinToString(" <- ") { "${it.className.substringAfterLast('.')}.${it.methodName}" }
            }.getOrElse { "stack<?>" }
    }

    // ------------------------------------------------------------------ hook 安装封装

    /**
     * API 102 起支持给 hook 指定 id（同 id 重复 hook 会原子替换，便于热重载）。
     * 低于 102 的运行时退回无 id 写法。
     */
    private fun hookExec(id: String, executable: Executable): XposedInterface.HookBuilder {
        val builder = hook(executable)
        return if (apiVersion >= XposedInterface.API_102) {
            builder.setId(id)
        } else {
            builder
        }
    }

    private fun install(id: String, executable: Executable, body: (XposedInterface.Chain) -> Any?) {
        runCatching {
            executable.isAccessible = true
            hookExec(id, executable).intercept { chain -> body(chain) }
            hookCount.incrementAndGet()
            emit("[ok] #${hookCount.get()} $id -> ${executable.toGenericString()}")
        }.onFailure { emit("[fail] $id (${executable.toGenericString()}): $it") }
    }

    private fun installAll(id: String, executables: Collection<Executable>, body: (XposedInterface.Chain) -> Any?) {
        executables.forEachIndexed { i, e -> install("${id}_$i", e, body) }
    }

    // ------------------------------------------------------------------ 生命周期

    /**
     * 唯一必然触发的回调。所有 hook 都在这里装。
     *
     * 注意：com.miui.home 的 manifest 是 hasCode=false，onPackageLoaded / onPackageReady
     * 永远不会被调用，所以不能把安装逻辑放在那两个回调里。
     */
    override fun onModuleLoaded(param: XposedModuleInterface.ModuleLoadedParam) {
        emit("=== module loaded ===")
        emit("  process     = ${param.processName}")
        emit("  isSystemServer = ${param.isSystemServer}")
        emit("  apiVersion  = $apiVersion")
        emit("  framework   = $frameworkName / $frameworkVersion (code=$frameworkVersionCode)")
        emit("  properties  = 0x${frameworkProperties.toString(16)}")

        val proc = param.processName
        if (!proc.startsWith(HOST_PACKAGE)) {
            emit("  -> 非目标进程，detach 退出")
            runCatching { detach() }
            return
        }
        emit("  -> 命中目标进程，开始安装观测点")

        installCoreHooks()
        startProbeThread()
    }

    private fun installCoreHooks() {
        hookClassLoader()
        hookDefineClass()
        hookClassForName()
        hookDexLoaders()
        hookPathClassLoader()
        hookActivityThread()
        hookAppComponentFactory()
        hookApplicationAttach()
    }

    // ------------------------------------------------------------------ 1. ClassLoader.loadClass

    private fun hookClassLoader() {
        runCatching {
            val one = ClassLoader::class.java.getDeclaredMethod("loadClass", String::class.java)
            install("cl_loadClass_1", one) { chain ->
                val name = argAt(chain, 0) as? String
                val r = chain.proceed()
                if (name != null && isWatched(name)) noteClass(name, r as? Class<*>, "loadClass(String)")
                r
            }
        }

        runCatching {
            val two = ClassLoader::class.java.getDeclaredMethod(
                "loadClass", String::class.java, Boolean::class.javaPrimitiveType
            )
            install("cl_loadClass_2", two) { chain ->
                val name = argAt(chain, 0) as? String
                val r = chain.proceed()
                if (name != null && isWatched(name)) noteClass(name, r as? Class<*>, "loadClass(String,boolean)")
                r
            }
        }
    }

    // ------------------------------------------------------------------ 2. ClassLoader.defineClass

    /**
     * 动态定义类的直接入口。Rust Runtime 若走 JNI DefineClass / 内存 dex，
     * 这里是唯一能在「类还没被用」的时刻抓到它的地方。
     */
    private fun hookDefineClass() {
        val cl = ClassLoader::class.java
        val overloads = mutableListOf<Executable>()

        runCatching {
            overloads += cl.getDeclaredMethod(
                "defineClass", String::class.java, ByteArray::class.java,
                Int::class.javaPrimitiveType, Int::class.javaPrimitiveType
            )
        }
        runCatching {
            overloads += cl.getDeclaredMethod(
                "defineClass", String::class.java, ByteArray::class.java,
                Int::class.javaPrimitiveType, Int::class.javaPrimitiveType,
                java.security.ProtectionDomain::class.java
            )
        }
        runCatching {
            overloads += cl.getDeclaredMethod(
                "defineClass", String::class.java, java.nio.ByteBuffer::class.java,
                java.security.ProtectionDomain::class.java
            )
        }
        runCatching {
            overloads += cl.getDeclaredMethod(
                "defineClass", ByteArray::class.java,
                Int::class.javaPrimitiveType, Int::class.javaPrimitiveType
            )
        }

        if (overloads.isEmpty()) {
            emit("[warn] 未找到任何 ClassLoader.defineClass 重载")
            return
        }

        installAll("cl_defineClass", overloads) { chain ->
            val name = argAt(chain, 0) as? String
            val len = when (val b = argAt(chain, 1)) {
                is ByteArray -> b.size
                is java.nio.ByteBuffer -> b.remaining()
                else -> -1
            }
            if (name != null && isWatched(name) && definedClassNames.add(name)) {
                emit("[define] $name | bytes=$len | loader=${chain.thisObject}")
                emit("[define]   stack: ${shortStack(10)}")
            }
            chain.proceed()
        }
    }

    // ------------------------------------------------------------------ 3. Class.forName

    private fun hookClassForName() {
        runCatching {
            val m = Class::class.java.getDeclaredMethod(
                "forName", String::class.java, Boolean::class.javaPrimitiveType, ClassLoader::class.java
            )
            install("class_forName", m) { chain ->
                val name = argAt(chain, 0) as? String
                val r = chain.proceed()
                if (name != null && isWatched(name)) noteClass(name, r as? Class<*>, "Class.forName")
                r
            }
        }.onFailure { emit("[fail] hook Class.forName: $it") }
    }

    // ------------------------------------------------------------------ 4. Dex 加载器

    private fun hookDexLoaders() {
        // 4.1 BaseDexClassLoader.findClass —— dex 内查找的落点
        runCatching {
            val base = Class.forName("dalvik.system.BaseDexClassLoader")
            val findClass = base.getDeclaredMethod("findClass", String::class.java)
            install("dex_findClass", findClass) { chain ->
                val name = argAt(chain, 0) as? String
                val r = chain.proceed()
                if (name != null && isWatched(name)) noteClass(name, r as? Class<*>, "BaseDexClassLoader.findClass")
                r
            }
        }.onFailure { emit("[fail] hook BaseDexClassLoader.findClass: $it") }

        // 4.2 InMemoryDexClassLoader 构造器 —— 判断是否走内存 dex 动态定义
        runCatching {
            val im = Class.forName("dalvik.system.InMemoryDexClassLoader")
            val ctors = im.declaredConstructors
            // declaredConstructors 是 Array<Constructor<*>>，installAll 收 Collection<Executable>，
            // 这里必须显式 toList() 走一次型变，否则 Kotlin 报 Argument type mismatch。
            installAll("imdex_ctor", ctors.toList()) { chain ->
                emit("[dex] InMemoryDexClassLoader.ctor this=${chain.thisObject?.javaClass?.name}")
                emit("[dex]   args=${describeArgs(chain)}")
                emit("[dex]   parent=${fieldOf(chain.thisObject, "parent")}")
                emit("[dex]   stack: ${shortStack(8)}")
                chain.proceed()
            }
            emit("[info] InMemoryDexClassLoader 构造器数量 = ${ctors.size}")
        }.onFailure { emit("[fail] hook InMemoryDexClassLoader: $it") }
    }

    // ------------------------------------------------------------------ 5. PathClassLoader

    private fun hookPathClassLoader() {
        runCatching {
            val p = Class.forName("dalvik.system.PathClassLoader")
            val ctors = p.declaredConstructors
            installAll("pathcl_ctor", ctors.toList()) { chain ->
                emit("[dex] PathClassLoader.ctor args=${describeArgs(chain)}")
                chain.proceed()
            }
            emit("[info] PathClassLoader 构造器数量 = ${ctors.size}")
        }.onFailure { emit("[fail] hook PathClassLoader: $it") }
    }

    // ------------------------------------------------------------------ 6. ActivityThread

    private fun hookActivityThread() {
        val at = runCatching { Class.forName("android.app.ActivityThread") }.getOrNull()
        if (at == null) {
            emit("[fail] ActivityThread 不可用")
            return
        }

        // 6.1 handleCreateService
        runCatching {
            val dataCls = Class.forName("android.app.ActivityThread\$CreateServiceData")
            val m = at.getDeclaredMethod("handleCreateService", dataCls)
            install("at_handleCreateService", m) { chain ->
                val r = chain.proceed()
                val data = argAt(chain, 0)
                val info = fieldOf(data, "info")
                val name = fieldOf(info, "name") as? String
                val svc = fieldOf(data, "service") as? Service
                emit("[svc:create] declared=$name instance=${svc?.javaClass?.name}")
                emit("[svc:create]   loader=${svc?.javaClass?.classLoader}")
                svc?.let { noteClass(it.javaClass.name, it.javaClass, "handleCreateService") }
                r
            }
        }.onFailure { emit("[fail] hook handleCreateService: $it") }

        // 6.2 handleBindService
        runCatching {
            val dataCls = Class.forName("android.app.ActivityThread\$BindServiceData")
            val m = at.getDeclaredMethod("handleBindService", dataCls)
            install("at_handleBindService", m) { chain ->
                val r = chain.proceed()
                val data = argAt(chain, 0)
                val info = fieldOf(data, "info")
                val name = fieldOf(info, "name") as? String
                val svc = fieldOf(data, "service") as? Service
                emit("[svc:bind] declared=$name instance=${svc?.javaClass?.name}")
                svc?.let { noteClass(it.javaClass.name, it.javaClass, "handleBindService") }
                r
            }
        }.onFailure { emit("[fail] hook handleBindService: $it") }

        // 6.3 handleLaunchActivity —— 拿 Activity 真实 Class
        runCatching {
            val m = at.declaredMethods.firstOrNull { it.name == "handleLaunchActivity" }
                ?: throw NoSuchMethodException("handleLaunchActivity")
            install("at_handleLaunchActivity", m) { chain ->
                val r = chain.proceed()
                runCatching {
                    // 遍历实参找 Activity 实例
                    chain.args.forEach { a ->
                        val act = when {
                            a == null -> null
                            a.javaClass.name == "android.app.ActivityThread\$ActivityClientRecord" ->
                                fieldOf(a, "activity")
                            else -> null
                        }
                        if (act != null) {
                            val c = act.javaClass
                            if (isWatched(c.name)) noteClass(c.name, c, "handleLaunchActivity")
                        }
                    }
                }
                r
            }
        }.onFailure { emit("[fail] hook handleLaunchActivity: $it") }

        // 6.4 handleBindApplication —— 拿 LoadedApk / app 信息
        runCatching {
            val m = at.declaredMethods.firstOrNull { it.name == "handleBindApplication" }
                ?: throw NoSuchMethodException("handleBindApplication")
            install("at_handleBindApplication", m) { chain ->
                val r = chain.proceed()
                runCatching {
                    val data = argAt(chain, 0)
                    emit("[app] handleBindApplication data=${data?.javaClass?.name}")
                    val app = fieldOf(data, "appInfo")
                    emit("[app]   appInfo=$app")
                }
                r
            }
        }.onFailure { emit("[fail] hook handleBindApplication: $it") }
    }

    // ------------------------------------------------------------------ 7. AppComponentFactory

    /**
     * 动态定义的类最终要被实例化，AppComponentFactory.instantiateXxx 是必经之路，
     * 实参里的 String className 已经由框架解析过，能直接反查真实 Class。
     */
    private fun hookAppComponentFactory() {
        val fac = runCatching { Class.forName("android.app.AppComponentFactory") }.getOrNull()
        if (fac == null) {
            emit("[fail] AppComponentFactory 不可用")
            return
        }
        for (name in listOf(
            "instantiateApplication",
            "instantiateActivity",
            "instantiateService",
            "instantiateProvider",
            "instantiateReceiver",
        )) {
            runCatching {
                val m = fac.declaredMethods.firstOrNull { it.name == name }
                    ?: throw NoSuchMethodException(name)
                install("acf_$name", m) { chain ->
                    val cl = chain.args.firstOrNull { it is ClassLoader } as? ClassLoader
                    val cn = chain.args.filterIsInstance<String>().firstOrNull()
                    emit("[acf] $name className=$cn loader=$cl")
                    if (cn != null) {
                        val c = runCatching { Class.forName(cn, false, cl) }.getOrNull()
                        if (c != null) noteClass(cn, c, "AppComponentFactory.$name")
                    }
                    chain.proceed()
                }
            }.onFailure { emit("[fail] hook AppComponentFactory.$name: $it") }
        }
    }

    // ------------------------------------------------------------------ 8. Application.attach

    private fun hookApplicationAttach() {
        runCatching {
            val m = Application::class.java.getDeclaredMethod("attach", Context::class.java)
            install("app_attach", m) { chain ->
                val r = chain.proceed()
                val ctx = chain.thisObject as? Context
                if (ctx != null) {
                    initLogFiles(ctx)
                    emit("[ctx] Application attached")
                    emit("[ctx]   packageName = ${ctx.packageName}")
                    emit("[ctx]   filesDir    = ${ctx.filesDir}")
                    emit("[ctx]   codePath    = ${ctx.applicationInfo?.sourceDir}")
                    emit("[ctx]   nativeLib   = ${ctx.applicationInfo?.nativeLibraryDir}")
                    emit("[ctx]   classLoader = ${ctx.classLoader}")
                }
                r
            }
        }.onFailure { emit("[fail] hook Application.attach: $it") }
    }

    // ------------------------------------------------------------------ 后台探测线程

    /**
     * 用普通后台线程而不是 Handler —— onModuleLoaded 的时机可能早于 main looper 就绪，
     * 直接拿 Looper.getMainLooper() 有风险。
     */
    private fun startProbeThread() {
        if (!probeStarted.compareAndSet(false, true)) return
        val t = Thread({
            emit("[probe] thread start")
            var last = 0L
            val marks = longArrayOf(0L, 500L, 1_500L, 3_000L, 6_000L, 10_000L, 15_000L, 20_000L, 30_000L, 60_000L)
            for (m in marks) {
                val sleep = m - last
                if (sleep > 0) runCatching { Thread.sleep(sleep) }
                last = m
                runCatching { runProbe(m) }
            }
            emit("[probe] thread done | seen=${seenClasses.size} defined=${definedClassNames.size}")
        }, "HyperOSProbe-Probe")
        t.isDaemon = true
        t.start()
    }

    private fun runProbe(atMs: Long) {
        val loaders = collectLoaders()
        emit("[probe:+${atMs}ms] loaders=${loaders.size}")
        for (l in loaders) {
            for (name in TARGET_CLASSES) {
                val c = runCatching { Class.forName(name, false, l) }.getOrNull() ?: continue
                if (seenClasses.contains(name)) continue
                emit("[probe:+${atMs}ms] FOUND $name via $l")
                noteClass(name, c, "probe@${atMs}ms")
            }
        }
        if (atMs == 60_000L) {
            emit("[probe] final | seen=${seenClasses.size} classes:")
            seenClasses.sorted().forEach { emit("[probe]   $it") }
        }
    }

    private fun collectLoaders(): List<ClassLoader> {
        val out = LinkedHashSet<ClassLoader>()

        runCatching { Thread.currentThread().contextClassLoader }.getOrNull()?.let { out.add(it) }
        runCatching { ClassLoader.getSystemClassLoader() }.getOrNull()?.let { out.add(it) }
        out.add(ProbeModule::class.java.classLoader)

        // 从 ActivityThread 里挖所有 ClassLoader / Context 字段
        runCatching {
            val at = Class.forName("android.app.ActivityThread")
            val cur = at.getDeclaredMethod("currentActivityThread").apply { isAccessible = true }
                .invoke(null) ?: return@runCatching
            var c: Class<*>? = at
            while (c != null) {
                for (f in c.declaredFields) {
                    runCatching {
                        f.isAccessible = true
                        when (val v = f.get(cur)) {
                            is ClassLoader -> out.add(v)
                            is Context -> v.classLoader?.let { out.add(it) }
                        }
                    }
                }
                c = c.superclass
            }
        }

        // 从 Application 拿 classLoader
        runCatching {
            val at = Class.forName("android.app.ActivityThread")
            val cur = at.getDeclaredMethod("currentActivityThread").apply { isAccessible = true }
                .invoke(null)
            val app = fieldOf(cur, "mInitialApplication") as? Application
            app?.classLoader?.let { out.add(it) }
        }

        return out.filterNotNull()
    }

    // ------------------------------------------------------------------ 类命中处理

    private fun noteClass(name: String, c: Class<*>?, from: String) {
        if (c == null) return
        if (!seenClasses.add(name)) return
        emit("[class] $name  (via $from)")
        emit("[class]   loader = ${c.classLoader}")
        emit("[class]   super  = ${c.superclass?.name}")
        emit("[class]   ifaces = ${c.interfaces.joinToString { it.name }}")
        emit("[class]   mods   = 0x${Integer.toHexString(c.modifiers)}")
        dumpClass(c)
        if (name == "com.miui.home.miclaw.LauncherToolService") hookLauncherToolService(c)
    }

    private fun dumpClass(c: Class<*>) {
        if (!dumpedClasses.add(c.name)) return
        val lines = mutableListOf<String>()
        lines += "---- dump ${c.name} ----"
        lines += "  loader = ${c.classLoader}"
        lines += "  super  = ${c.superclass?.name}"
        lines += "  ifaces = ${c.interfaces.joinToString { it.name }}"
        runCatching {
            val ann = c.annotations.joinToString { it.annotationClass.java.name }
            if (ann.isNotEmpty()) lines += "  annots = $ann"
        }
        for (f in c.declaredFields) {
            runCatching {
                lines += "  field  : ${java.lang.reflect.Modifier.toString(f.modifiers)} " +
                    "${f.type.name} ${f.name}"
            }
        }
        for (ctor in c.declaredConstructors) {
            runCatching { lines += "  ctor   : ${ctor.toGenericString()}" }
        }
        for (m in c.declaredMethods) {
            runCatching { lines += "  method : ${m.toGenericString()}" }
        }
        lines += "---- end dump ${c.name} ----"
        emitBlock(lines)
    }

    /**
     * 找到 LauncherToolService 后，定位 handleSettingsTool 并打印进出参。
     * 若本类没声明，就往父类链上找（动态定义的类常把实现放在父类）。
     */
    private fun hookLauncherToolService(c: Class<*>) {
        if (!toolServiceHooked.compareAndSet(false, true)) return
        emit("[tool] LauncherToolService resolved -> $c")

        var owner: Class<*>? = c
        while (owner != null) {
            val m = owner.declaredMethods.firstOrNull { it.name == "handleSettingsTool" }
            if (m != null) {
                emit("[tool] handleSettingsTool declared on ${owner.name}")
                hookMethod("tool_handleSettingsTool", m)
                return
            }
            owner = owner.superclass
        }
        emit("[warn] handleSettingsTool 在整条父类链上都未找到，列出本类全部方法名：")
        c.declaredMethods.forEach { emit("[warn]   ${it.name}${it.parameterTypes.joinToString(",", "(", ")") { p -> p.name }}") }
    }

    private fun hookMethod(id: String, m: Method) {
        install(id, m) { chain ->
            emit("[tool:in ] this=${chain.thisObject?.javaClass?.name}@${System.identityHashCode(chain.thisObject)}")
            emit("[tool:in ] args=${describeArgs(chain)}")
            emit("[tool:in ] exec=${chain.executable.toGenericString()}")
            val r = chain.proceed()
            emit("[tool:out] ret=${r?.javaClass?.name ?: "null"} = $r")
            r
        }
    }
}
