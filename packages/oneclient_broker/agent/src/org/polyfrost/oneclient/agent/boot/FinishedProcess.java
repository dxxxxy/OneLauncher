package org.polyfrost.oneclient.agent.boot;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;

/** Stands in for an opener program (rundll32, xdg-open) the launcher ran instead. */
final class FinishedProcess extends Process {
    @Override
    public OutputStream getOutputStream() {
        return new OutputStream() {
            @Override
            public void write(int b) {}
        };
    }

    @Override
    public InputStream getInputStream() {
        return new ByteArrayInputStream(new byte[0]);
    }

    @Override
    public InputStream getErrorStream() {
        return new ByteArrayInputStream(new byte[0]);
    }

    @Override
    public int waitFor() {
        return 0;
    }

    @Override
    public int exitValue() {
        return 0;
    }

    @Override
    public void destroy() {}
}
