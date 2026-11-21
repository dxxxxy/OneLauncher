package org.polyfrost.oneclient.agent.boot;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Loads one package of this jar under a JDK loader other than the boot one.
 * The rest of the agent lives in the boot loader, which can't see modules
 * such as {@code java.net.http} (they belong to the platform loader), so
 * code that uses them is defined here instead. Everything outside the
 * package still resolves to the boot loader's copy.
 */
final class ModuleLoader extends ClassLoader {
    private final String prefix;

    ModuleLoader(ClassLoader parent, String packageName) {
        super(parent);
        this.prefix = packageName + ".";
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        if (!name.startsWith(prefix)) return super.loadClass(name, resolve);
        synchronized (getClassLoadingLock(name)) {
            Class<?> loaded = findLoadedClass(name);
            if (loaded == null) loaded = define(name);
            if (resolve) resolveClass(loaded);
            return loaded;
        }
    }

    private Class<?> define(String name) throws ClassNotFoundException {
        String resource = name.replace('.', '/') + ".class";
        InputStream in = ClassLoader.getSystemResourceAsStream(resource);
        if (in == null) throw new ClassNotFoundException(name);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) > 0) out.write(buffer, 0, n);
            byte[] bytes = out.toByteArray();
            return defineClass(name, bytes, 0, bytes.length);
        } catch (IOException e) {
            throw new ClassNotFoundException(name, e);
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {
                // read already
            }
        }
    }
}
