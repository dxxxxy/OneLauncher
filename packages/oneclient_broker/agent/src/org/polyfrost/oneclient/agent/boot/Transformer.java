package org.polyfrost.oneclient.agent.boot;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.polyfrost.oneclient.agent.boot.Patcher.Kind;
import org.polyfrost.oneclient.agent.boot.Patcher.Target;

/** Patches the handful of methods that need the launcher when sandboxed. */
final class Transformer implements ClassFileTransformer {
    private static final List<Target> PROCESS_BUILDER = Arrays.asList(
            new Target("start", "()Ljava/lang/Process;", false, 1, "start", Kind.OBJECT, "java/lang/Process"));

    private static final List<Target> DESKTOP = Arrays.asList(
            new Target("browse", "(Ljava/net/URI;)V", false, 2, "browse", Kind.VOID_BOOL, null),
            new Target("open", "(Ljava/io/File;)V", false, 2, "openFile", Kind.VOID_BOOL, null));

    private static final List<Target> CHOOSER = Arrays.asList(
            new Target("showOpenDialog", "(Ljava/awt/Component;)I", false, 1, "chooserOpen", Kind.INT, null),
            new Target("showSaveDialog", "(Ljava/awt/Component;)I", false, 1, "chooserSave", Kind.INT, null),
            new Target("showDialog", "(Ljava/awt/Component;Ljava/lang/String;)I", false, 1, "chooserShow",
                    Kind.INT, null));

    private static final List<Target> TINYFD = Arrays.asList(
            new Target("tinyfd_openFileDialog", ")Ljava/lang/String;", true, 1, "tinyOpen", Kind.OBJECT,
                    "java/lang/String"),
            new Target("tinyfd_saveFileDialog", ")Ljava/lang/String;", true, 1, "tinySave", Kind.OBJECT,
                    "java/lang/String"),
            new Target("tinyfd_selectFolderDialog", ")Ljava/lang/String;", true, 1, "tinyFolder", Kind.OBJECT,
                    "java/lang/String"));

    /** Patched classes outside the JDK that may live in a named module. */
    private static final ConcurrentLinkedQueue<Object[]> toFix = new ConcurrentLinkedQueue<Object[]>();

    public byte[] transform(ClassLoader loader, String name, Class<?> redefined, ProtectionDomain domain,
            byte[] bytes) {
        if (name == null) return null;
        try {
            List<Target> targets;
            if (name.equals("java/lang/ProcessBuilder")) targets = PROCESS_BUILDER;
            else if (name.equals("java/awt/Desktop")) targets = DESKTOP;
            else if (name.equals("javax/swing/JFileChooser")) targets = CHOOSER;
            else if (name.equals("org/lwjgl/util/tinyfd/TinyFileDialogs")) targets = TINYFD;
            else return null;

            byte[] patched = Patcher.patch(bytes, targets);
            if (patched != null && loader != null) {
                toFix.add(new Object[] {loader, name.replace('/', '.')});
            }
            return patched;
        } catch (Throwable t) {
            Main.log("left " + name + " unpatched: " + t);
            return null;
        }
    }

    /**
     * LWJGL can sit in a named module that doesn't read ours; grant that as
     * soon as the patched class exists (pickers are only used much later).
     */
    static void startModuleFixer() {
        Thread fixer = new Thread(new Runnable() {
            public void run() {
                List<Object[]> waiting = new ArrayList<Object[]>();
                while (true) {
                    Object[] next;
                    while ((next = toFix.poll()) != null) waiting.add(next);
                    for (java.util.Iterator<Object[]> it = waiting.iterator(); it.hasNext(); ) {
                        Object[] entry = it.next();
                        try {
                            Class<?> c = Class.forName((String) entry[1], false, (ClassLoader) entry[0]);
                            Main.letRead(c);
                            it.remove();
                        } catch (Throwable notYet) {
                            // defined a moment later
                        }
                    }
                    try {
                        Thread.sleep(250);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            }
        }, "OneClient module fixer");
        fixer.setDaemon(true);
        fixer.start();
    }
}
