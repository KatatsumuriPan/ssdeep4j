# ssdeep4j

## Overview

A ssdeep fuzzy hashing algorithm implementation for Java.

## Acknowledgments

This project is heavily inspired by the original ssdeep library. We would like to express our gratitude to the ssdeep project team.

- **ssdeep:** [https://github.com/ssdeep-project/ssdeep/](https://github.com/ssdeep-project/ssdeep/)

## Installation

### Maven

```xml
<dependency>
    <groupId>net.k-pan</groupId>
    <artifactId>ssdeep4j</artifactId>
    <version>1.2.0</version>
</dependency>
```

### Gradle

```groovy
implementation 'net.k-pan:ssdeep4j:1.1.0'
```

## Usage

### Hashing a file

```java
import net.k_pan.ssdeep4j.FuzzyHasher;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class HashingExample {
    public static void main(String[] args) {
        try {
            Path filePath = Paths.get("path/to/your/file.txt");
            String hash = FuzzyHasher.hash(filePath);
            System.out.println("Fuzzy Hash: " + hash);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

### Hashing a byte array

```java
import net.k_pan.ssdeep4j.FuzzyHasher;
import java.io.IOException;

public class HashingExample {
    public static void main(String[] args) {
        try {
            byte[] data = "Hello, world!".getBytes();
            String hash = FuzzyHasher.hash(data);
            System.out.println("Fuzzy Hash: " + hash); // Fuzzy Hash: 3:a6/E:asE
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

### Comparing two hashes

```java
import net.k_pan.ssdeep4j.FuzzyComparator;

public class ComparisonExample {
    public static void main(String[] args) {
        String hash1 = "3:a62AVpAFVEpFZgMFMEFZL:aELAFurNFME3";
        String hash2 = "3:a62AVpAFVEjDgMFMEFZL:aELAFuXFME3";

        int score = FuzzyComparator.compare(hash1, hash2);
        System.out.println("Similarity Score: " + score); // Similarity Score: 20
    }
}
```

## Building

To build the project, run the following command:

```bash
mvn clean install
```

## License

This project is licensed under the Apache License 2.0. See the `LICENSE` file for details.
