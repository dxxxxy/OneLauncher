package org.polyfrost.oneclient.agent.boot;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public final class Main {
    public static final String VERSION = "1";
    static final String HANDLER_PACKAGE = "org.polyfrost.oneclient.agent.protocol";

    private static Instrumentation instrumentation;

    private Main() {}

    public static void start(Instrumentation inst) {
        instrumentation = inst;
        Hooks.sandboxed = Boolean.getBoolean("oneclient.sandboxed");
        String discord = System.getProperty("oneclient.discord");
        if (discord != null && !discord.isEmpty()) Hooks.discordRelay = discord;

        openModules(inst);

        String existing = System.getProperty("java.protocol.handler.pkgs");
        if (existing == null || existing.isEmpty()) {
            System.setProperty("java.protocol.handler.pkgs", HANDLER_PACKAGE);
        } else if (!existing.contains(HANDLER_PACKAGE)) {
            System.setProperty("java.protocol.handler.pkgs", HANDLER_PACKAGE + "|" + existing);
        }

        inst.addTransformer(new Transformer(), true);
        if (Hooks.sandboxed) {
            retransformLoaded(inst, "java.lang.ProcessBuilder", "java.awt.Desktop", "javax.swing.JFileChooser",
                    "java.io.RandomAccessFile", "java.io.File", "sun.nio.fs.WindowsPath");
            Transformer.startModuleFixer();
        }

        Bridge.INSTANCE.connectInBackground();
    }

    private static void retransformLoaded(Instrumentation inst, String... names) {
        for (Class<?> loaded : inst.getAllLoadedClasses()) {
            for (String name : names) {
                if (loaded.getName().equals(name) && inst.isModifiableClass(loaded)) {
                    try {
                        inst.retransformClasses(loaded);
                    } catch (Throwable t) {
                        log("could not patch " + name + ": " + t);
                    }
                }
            }
        }
    }

    /**
     * Java 9+: let java.base and java.desktop call into our (unnamed) module and
     * let us reach the JDK's built-in HTTP handlers. Java 8 has no modules.
     */
    private static void openModules(Instrumentation inst) {
        try {
            Method getModule = Class.class.getMethod("getModule");
            Object ours = getModule.invoke(Main.class);
            Object base = getModule.invoke(Object.class);
            Map<String, Set<Object>> exports = new HashMap<String, Set<Object>>();
            exports.put("sun.net.www.protocol.http", Collections.singleton(ours));
            exports.put("sun.net.www.protocol.https", Collections.singleton(ours));
            redefine(inst, base, ours, exports);
            // java.net.http belongs to the platform loader, not the boot one
            ClassLoader platform = ClassLoader.getSystemClassLoader();
            for (String name : new String[] {"java.awt.Desktop", "javax.swing.JFileChooser", "java.net.http.HttpClient"}) {
                try {
                    redefine(inst, getModule.invoke(Class.forName(name, false, platform)), ours,
                            Collections.<String, Set<Object>>emptyMap());
                } catch (Throwable ignored) {
                    // headless or stripped runtime
                }
            }
        } catch (NoSuchMethodException java8) {
            // nothing to open
        } catch (Throwable t) {
            log("could not open modules: " + t);
        }
    }

    static void letRead(Class<?> patched) {
        try {
            Method getModule = Class.class.getMethod("getModule");
            Object module = getModule.invoke(patched);
            Object ours = getModule.invoke(Main.class);
            Method canRead = module.getClass().getMethod("canRead", Class.forName("java.lang.Module"));
            if (!(Boolean) canRead.invoke(module, ours)) {
                redefine(instrumentation, module, ours, Collections.<String, Set<Object>>emptyMap());
            }
        } catch (NoSuchMethodException java8) {
            // nothing to do
        } catch (Throwable t) {
            log("could not let " + patched.getName() + " reach OneClient: " + t);
        }
    }

    private static void redefine(Instrumentation inst, Object module, Object reader, Map<String, Set<Object>> exports)
            throws Exception {
        Class<?> moduleClass = Class.forName("java.lang.Module");
        Method redefine = Instrumentation.class.getMethod(
                "redefineModule", moduleClass, Set.class, Map.class, Map.class, Set.class, Map.class);
        redefine.invoke(inst, module, Collections.singleton(reader), exports,
                Collections.emptyMap(), Collections.emptySet(), Collections.emptyMap());
    }

    static void log(String message) {
        System.err.println("[OneClient agent] " + message);
    }
}
