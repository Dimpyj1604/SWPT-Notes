# Decompiling Java Archives (JAR Files)

When doing whitebox testing on a Java application without source code, the compiled JAR is often available. JAR files contain bytecode that can be decompiled back to readable Java source.

---

## Tools

### Fernflower (CLI, maintained by JetBrains)

```bash
git clone https://github.com/fesh0r/fernflower.git
cd fernflower
# If on JDK 17, pin to the compatible commit first:
git checkout c03cae7
./gradlew build
# Output: build/libs/fernflower.jar

mkdir out
java -jar fernflower.jar BlueBird-0.0.1-SNAPSHOT.jar out/
cd out
jar -xf BlueBird-0.0.1-SNAPSHOT.jar
# Source files land in BOOT-INF/classes/
```

**JDK version mismatch fix:**
```bash
sudo apt install openjdk-17-jdk
sudo update-java-alternatives --list          # find path for 1.17
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
```

### JD-GUI (GUI, older but quick for browsing)

```bash
java -jar jd-gui-1.6.6.jar BlueBird-0.0.1-SNAPSHOT.jar
# File > Save All Sources → extracts a ZIP of .java files
```

### Quick extraction (no decompile needed for config/resources)

JAR files are ZIP archives. For non-bytecode files (properties, templates, configs), just unzip directly:

```bash
unzip -p BlueBird-0.0.1-SNAPSHOT.jar BOOT-INF/classes/application.properties
unzip -l BlueBird-0.0.1-SNAPSHOT.jar | grep ".properties"
```

This is much faster than a full decompile when you only need config values.

---

## Spring Boot JAR Structure

```
BlueBird-0.0.1-SNAPSHOT.jar
└── BOOT-INF/
    ├── classes/
    │   ├── application.properties       ← DB creds, JWT secrets, config
    │   └── com/bmdyy/bluebird/
    │       ├── controller/              ← Route handlers (injection surface)
    │       ├── model/                   ← Data models
    │       └── security/
    │           └── jwt/                 ← JWT logic (JwtUtils.java)
    ├── lib/                             ← Dependency JARs
    └── layers.idx
```

### What to look for immediately after decompiling

1. **`application.properties`** — database URL/credentials, JWT secret, cookie name, any hardcoded keys
2. **Controller files** — route handlers where user input hits SQL queries
3. **`JwtUtils.java`** — JWT signing algorithm and secret source
4. **`WebSecurityConfig.java`** — which routes are protected vs. public

---

## Key Finding Pattern

`application.properties` in Spring Boot is the first place to check. It often contains:
```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/dbname
spring.datasource.username=dbuser
spring.datasource.password=dbpass

bluebird.app.jwtSecret=<secret>
bluebird.app.jwtCookieName=auth
```

A hardcoded `jwtSecret` means you can forge JWT tokens — same technique as the whitebox pentesting module.
