package net.ischi.hl.serialization;

import java.io.*;
import java.util.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * This Object will be serialized
 */
class Demo implements java.io.Serializable {
    private static final long serialVersionUID = 1L;
    public String path;

    public Demo(String path) {
        this.path = path;
    }

    public String readFile() {
        String content = "";
        try {
            Path filePath = Paths.get(this.path);
            content = new String(Files.readAllBytes(filePath));
        } catch (Exception e) {
            System.out.println(e);
        }
        return content;
    }
}


public class Main {
    String toBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    byte[] createSerialization(Object object) {
        byte[] b = null;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(object);
            b = baos.toByteArray();
            oos.close();
            baos.close();
        } catch (Exception e) {
            System.out.println(e);
        }
        return b;
    }

    public static void main(String[] args) {
        Main m = new Main();

        Demo demo = new Demo("/etc/hosts");

        byte[] s = m.createSerialization(demo);

        String sB64 = m.toBase64(s);

        System.out.println(sB64);
    }
}
