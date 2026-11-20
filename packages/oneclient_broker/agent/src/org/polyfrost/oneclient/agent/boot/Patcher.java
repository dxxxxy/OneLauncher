package org.polyfrost.oneclient.agent.boot;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A minimal class-file rewriter that inserts a call to a static hook at the
 * start of a method. No ASM: mod loaders ship their own, often older, copies
 * on the same class path, and a clash would break the game.
 *
 * <p>The inserted prologue loads the first {@code loads} reference locals,
 * calls the hook, and either returns its result or falls through to the
 * original code:
 *
 * <pre>
 * VOID_BOOL: load*; invokestatic hook(..)Z; ifeq L; return;            L: nop*
 * OBJECT:    load*; invokestatic hook(..)Object; dup; getstatic PASS;
 *            if_acmpeq L; checkcast T; areturn;                         L: pop; nop*
 * INT:       ... if_acmpeq L; checkcast Integer; invokevirtual intValue; ireturn; L: pop; nop*
 * </pre>
 *
 * The prologue is padded to a multiple of 4 bytes so tableswitch and
 * lookupswitch alignment in the original code is unchanged. Branch offsets in
 * the original are relative and need no change; the exception table, line
 * and local-variable tables shift by the prologue length, and one stack map
 * frame is inserted for {@code L}.
 */
final class Patcher {
    enum Kind { VOID_BOOL, OBJECT, INT }

    static final class Target {
        final String name;
        /** Exact descriptor, or a suffix when {@code suffix} is set. */
        final String desc;
        final boolean suffix;
        final int loads;
        final String hook;
        final String hookDesc;
        final Kind kind;
        final String cast;

        Target(String name, String desc, boolean suffix, int loads, String hook, Kind kind, String cast) {
            this.name = name;
            this.desc = desc;
            this.suffix = suffix;
            this.loads = loads;
            this.hook = hook;
            this.kind = kind;
            this.cast = cast;
            StringBuilder d = new StringBuilder("(");
            for (int i = 0; i < loads; i++) d.append("Ljava/lang/Object;");
            d.append(kind == Kind.VOID_BOOL ? ")Z" : ")Ljava/lang/Object;");
            this.hookDesc = d.toString();
        }

        boolean matches(String n, String d) {
            return name.equals(n) && (suffix ? d.endsWith(desc) : desc.equals(d));
        }
    }

    static final String HOOKS = "org/polyfrost/oneclient/agent/boot/Hooks";

    // ---- constant pool

    private final List<byte[]> pool = new ArrayList<byte[]>();
    private int major;

    private Patcher() {
        pool.add(null); // index 0 is unused
    }

    private String utf8At(int index) throws IOException {
        byte[] entry = pool.get(index);
        if (entry == null || entry[0] != 1) throw new IOException("not a Utf8 entry: " + index);
        return new DataInputStream(new ByteArrayInputStream(entry, 1, entry.length - 1)).readUTF();
    }

    private int add(byte[] entry) {
        for (int i = 1; i < pool.size(); i++) {
            if (java.util.Arrays.equals(pool.get(i), entry)) return i;
        }
        pool.add(entry);
        return pool.size() - 1;
    }

    private int utf8(String value) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        DataOutputStream d = new DataOutputStream(b);
        d.writeByte(1);
        d.writeUTF(value);
        return add(b.toByteArray());
    }

    private int ref(int tag, int a) {
        return add(new byte[] {(byte) tag, (byte) (a >> 8), (byte) a});
    }

    private int ref(int tag, int a, int b) {
        return add(new byte[] {(byte) tag, (byte) (a >> 8), (byte) a, (byte) (b >> 8), (byte) b});
    }

    private int classRef(String name) throws IOException {
        return ref(7, utf8(name));
    }

    private int member(int tag, String owner, String name, String desc) throws IOException {
        return ref(tag, classRef(owner), ref(12, utf8(name), utf8(desc)));
    }

    // ---- reading and writing the class

    static byte[] patch(byte[] classFile, List<Target> targets) throws IOException {
        return new Patcher().rewrite(classFile, targets);
    }

    private static final class Attribute {
        int name;
        byte[] data;
    }

    private static List<Attribute> readAttributes(DataInputStream in) throws IOException {
        int count = in.readUnsignedShort();
        List<Attribute> attributes = new ArrayList<Attribute>(count);
        for (int i = 0; i < count; i++) {
            Attribute a = new Attribute();
            a.name = in.readUnsignedShort();
            a.data = new byte[in.readInt()];
            in.readFully(a.data);
            attributes.add(a);
        }
        return attributes;
    }

    private static void writeAttributes(DataOutputStream out, List<Attribute> attributes) throws IOException {
        out.writeShort(attributes.size());
        for (Attribute a : attributes) {
            out.writeShort(a.name);
            out.writeInt(a.data.length);
            out.write(a.data);
        }
    }

    private byte[] rewrite(byte[] classFile, List<Target> targets) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(classFile));
        if (in.readInt() != 0xCAFEBABE) throw new IOException("not a class file");
        int minor = in.readUnsignedShort();
        major = in.readUnsignedShort();

        int count = in.readUnsignedShort();
        for (int i = 1; i < count; i++) {
            int tag = in.readUnsignedByte();
            int size;
            switch (tag) {
                case 1: size = in.readUnsignedShort(); {
                    byte[] e = new byte[3 + size];
                    e[0] = 1;
                    e[1] = (byte) (size >> 8);
                    e[2] = (byte) size;
                    in.readFully(e, 3, size);
                    pool.add(e);
                    continue;
                }
                case 3: case 4: size = 4; break;
                case 5: case 6: size = 8; break;
                case 7: case 8: case 16: case 19: case 20: size = 2; break;
                case 9: case 10: case 11: case 12: case 17: case 18: size = 4; break;
                case 15: size = 3; break;
                default: throw new IOException("unknown constant tag " + tag);
            }
            byte[] e = new byte[1 + size];
            e[0] = (byte) tag;
            in.readFully(e, 1, size);
            pool.add(e);
            if (tag == 5 || tag == 6) {
                pool.add(null); // longs and doubles take two slots
                i++;
            }
        }

        ByteArrayOutputStream middle = new ByteArrayOutputStream();
        DataOutputStream mid = new DataOutputStream(middle);
        mid.writeShort(in.readUnsignedShort()); // access
        mid.writeShort(in.readUnsignedShort()); // this
        mid.writeShort(in.readUnsignedShort()); // super
        int interfaces = in.readUnsignedShort();
        mid.writeShort(interfaces);
        for (int i = 0; i < interfaces; i++) mid.writeShort(in.readUnsignedShort());
        int fields = in.readUnsignedShort();
        mid.writeShort(fields);
        for (int i = 0; i < fields; i++) {
            mid.writeShort(in.readUnsignedShort());
            mid.writeShort(in.readUnsignedShort());
            mid.writeShort(in.readUnsignedShort());
            writeAttributes(mid, readAttributes(in));
        }

        int methods = in.readUnsignedShort();
        mid.writeShort(methods);
        boolean changed = false;
        for (int i = 0; i < methods; i++) {
            int access = in.readUnsignedShort();
            int name = in.readUnsignedShort();
            int desc = in.readUnsignedShort();
            List<Attribute> attributes = readAttributes(in);
            String n = utf8At(name);
            String d = utf8At(desc);
            for (Target target : targets) {
                if (!target.matches(n, d) || n.equals("<init>")) continue;
                for (Attribute a : attributes) {
                    if (utf8At(a.name).equals("Code")) {
                        a.data = patchCode(a.data, target);
                        changed = true;
                    }
                }
                break;
            }
            mid.writeShort(access);
            mid.writeShort(name);
            mid.writeShort(desc);
            writeAttributes(mid, attributes);
        }
        writeAttributes(mid, readAttributes(in));

        if (!changed) return null;

        ByteArrayOutputStream result = new ByteArrayOutputStream(classFile.length + 256);
        DataOutputStream out = new DataOutputStream(result);
        out.writeInt(0xCAFEBABE);
        out.writeShort(minor);
        out.writeShort(major);
        out.writeShort(pool.size());
        for (int i = 1; i < pool.size(); i++) {
            byte[] e = pool.get(i);
            if (e != null) out.write(e);
        }
        middle.writeTo(out);
        out.flush();
        return result.toByteArray();
    }

    private byte[] patchCode(byte[] data, Target target) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
        int maxStack = in.readUnsignedShort();
        int maxLocals = in.readUnsignedShort();
        byte[] code = new byte[in.readInt()];
        in.readFully(code);
        int exceptions = in.readUnsignedShort();
        int[] table = new int[exceptions * 4];
        for (int i = 0; i < table.length; i++) table[i] = in.readUnsignedShort();
        List<Attribute> attributes = readAttributes(in);

        // ---- prologue
        ByteArrayOutputStream p = new ByteArrayOutputStream();
        DataOutputStream pro = new DataOutputStream(p);
        for (int i = 0; i < target.loads; i++) {
            if (i <= 3) {
                pro.writeByte(0x2a + i); // aload_<i>
            } else {
                pro.writeByte(0x19); // aload
                pro.writeByte(i);
            }
        }
        pro.writeByte(0xb8); // invokestatic
        pro.writeShort(member(10, HOOKS, target.hook, target.hookDesc));
        int label;
        if (target.kind == Kind.VOID_BOOL) {
            pro.writeByte(0x99); // ifeq
            pro.writeShort(4);
            pro.writeByte(0xb1); // return
            label = p.size();
        } else {
            pro.writeByte(0x59); // dup
            pro.writeByte(0xb2); // getstatic PASS
            pro.writeShort(member(9, HOOKS, "PASS", "Ljava/lang/Object;"));
            int branchAt = p.size();
            ByteArrayOutputStream tail = new ByteArrayOutputStream();
            DataOutputStream t = new DataOutputStream(tail);
            if (target.kind == Kind.OBJECT) {
                t.writeByte(0xc0); // checkcast
                t.writeShort(classRef(target.cast));
                t.writeByte(0xb0); // areturn
            } else {
                t.writeByte(0xc0);
                t.writeShort(classRef("java/lang/Integer"));
                t.writeByte(0xb6); // invokevirtual
                t.writeShort(member(10, "java/lang/Integer", "intValue", "()I"));
                t.writeByte(0xac); // ireturn
            }
            pro.writeByte(0xa5); // if_acmpeq
            pro.writeShort(3 + tail.size());
            tail.writeTo(pro);
            label = p.size();
            if (label - branchAt != 3 + tail.size()) throw new IOException("prologue layout");
            pro.writeByte(0x57); // pop
        }
        while (p.size() % 4 != 0) pro.writeByte(0x00); // nop
        byte[] prologue = p.toByteArray();
        int shift = prologue.length;

        // ---- attributes
        int stackMapName = -1;
        List<Attribute> kept = new ArrayList<Attribute>();
        for (Attribute a : attributes) {
            String n = utf8At(a.name);
            if (n.equals("LineNumberTable")) {
                shiftEntries(a.data, 4, 0, shift);
            } else if (n.equals("LocalVariableTable") || n.equals("LocalVariableTypeTable")) {
                shiftEntries(a.data, 10, 0, shift);
            } else if (n.equals("StackMapTable")) {
                stackMapName = a.name;
                a.data = shiftFrames(a.data, target.kind, label, shift);
            } else if (n.startsWith("Runtime") && n.endsWith("TypeAnnotations")) {
                continue; // carry code offsets we don't rewrite; optional
            }
            kept.add(a);
        }
        if (stackMapName < 0 && major >= 50) {
            Attribute a = new Attribute();
            a.name = utf8("StackMapTable");
            a.data = shiftFrames(new byte[] {0, 0}, target.kind, label, shift);
            kept.add(a);
        }

        ByteArrayOutputStream result = new ByteArrayOutputStream(data.length + shift + 16);
        DataOutputStream out = new DataOutputStream(result);
        out.writeShort(Math.max(maxStack, Math.max(target.loads, 3) + 1));
        out.writeShort(Math.max(maxLocals, target.loads));
        out.writeInt(code.length + shift);
        out.write(prologue);
        out.write(code);
        out.writeShort(exceptions);
        for (int i = 0; i < table.length; i++) {
            out.writeShort(i % 4 == 3 ? table[i] : table[i] + shift);
        }
        writeAttributes(out, kept);
        out.flush();
        return result.toByteArray();
    }

    /** Adds {@code shift} to the u2 at {@code offset} of each fixed-size entry after a u2 count. */
    private static void shiftEntries(byte[] data, int entrySize, int offset, int shift) {
        int count = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
        for (int i = 0; i < count; i++) {
            int at = 2 + i * entrySize + offset;
            int value = (((data[at] & 0xff) << 8) | (data[at + 1] & 0xff)) + shift;
            data[at] = (byte) (value >> 8);
            data[at + 1] = (byte) value;
        }
    }

    private byte[] shiftFrames(byte[] data, Kind kind, int label, int shift) throws IOException {
        int count = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
        ByteArrayOutputStream b = new ByteArrayOutputStream(data.length + 8);
        DataOutputStream out = new DataOutputStream(b);
        out.writeShort(count + 1);

        // our frame at the label: the method's initial locals, plus the
        // hook's result on the stack for object hooks
        if (kind == Kind.VOID_BOOL) {
            if (label <= 63) {
                out.writeByte(label);
            } else {
                out.writeByte(251);
                out.writeShort(label);
            }
        } else {
            if (label <= 63) {
                out.writeByte(64 + label);
            } else {
                out.writeByte(247);
                out.writeShort(label);
            }
            out.writeByte(7); // Object_variable_info
            out.writeShort(classRef("java/lang/Object"));
        }

        if (count == 0) {
            out.flush();
            return b.toByteArray();
        }

        // the original first frame was relative to the implicit initial
        // frame; it is now relative to ours, which has the same locals
        int tag = data[2] & 0xff;
        int delta;
        int headerEnd;
        if (tag <= 63) {
            delta = tag;
            headerEnd = 3;
        } else if (tag <= 127) {
            delta = tag - 64;
            headerEnd = 3;
        } else if (tag >= 247) {
            delta = ((data[3] & 0xff) << 8) | (data[4] & 0xff);
            headerEnd = 5;
        } else {
            throw new IOException("reserved stack map frame type " + tag);
        }
        int moved = delta + shift - label - 1;
        if (tag <= 63) {
            if (moved <= 63) {
                out.writeByte(moved);
            } else {
                out.writeByte(251);
                out.writeShort(moved);
            }
        } else if (tag <= 127) {
            if (moved <= 63) {
                out.writeByte(64 + moved);
            } else {
                out.writeByte(247);
                out.writeShort(moved);
            }
        } else {
            out.writeByte(tag);
            out.writeShort(moved);
        }
        out.write(data, headerEnd, data.length - headerEnd);
        out.flush();
        return b.toByteArray();
    }
}
