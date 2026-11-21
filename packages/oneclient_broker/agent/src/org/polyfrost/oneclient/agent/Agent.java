package org.polyfrost.oneclient.agent;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.util.jar.JarFile;

/**
 * Entry point. Everything else in this jar is loaded by the bootstrap class
 * loader so JDK classes (java.base, java.desktop) and every mod loader's class
 * loaders can all see the same hook classes.
 *
 * <p>This agent is a compatibility layer, not a security boundary: a mod can
 * bypass it. The launcher's broker and the OS sandbox enforce the rules.
 */
public final class Agent {
    private Agent() {}

    public static void premain(String args, Instrumentation inst) {
        try {
            File self = new File(Agent.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            inst.appendToBootstrapClassLoaderSearch(new JarFile(self));
            exposeToFabric(self);
            Class.forName("org.polyfrost.oneclient.agent.boot.Main", true, null)
                    .getMethod("start", Instrumentation.class)
                    .invoke(null, inst);
        } catch (Throwable t) {
            // never take the game down with us
            System.err.println("[OneClient agent] failed to start: " + t);
        }
    }

    /**
     * Fabric's class loader only lets game code reach classes from jars on
     * the class path it was started with, and this jar isn't on it: a patched
     * mod or library class calling into the hooks would fail to link. Fabric
     * reads this property when it starts, after every agent has run.
     */
    private static void exposeToFabric(File self) {
        String key = "fabric.systemLibraries";
        String jar;
        try {
            jar = self.getCanonicalPath();
        } catch (Exception e) {
            jar = self.getAbsolutePath();
        }
        String before = System.getProperty(key);
        System.setProperty(key, before == null || before.isEmpty() ? jar : before + File.pathSeparator + jar);
    }

    public static void agentmain(String args, Instrumentation inst) {
        premain(args, inst);
    }
}
