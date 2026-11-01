#!/usr/bin/env bash
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

CLASSES_DIR="target/classes"
TEST_CLASSES_DIR="target/test-classes"
LIB_JAR="lib/junit-platform-console-standalone.jar"

if [ ! -f "$LIB_JAR" ]; then
    echo "Baixando dependência do JUnit 5 Standalone..."
    mkdir -p lib
    curl -sL https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.10.2/junit-platform-console-standalone-1.10.2.jar -o "$LIB_JAR"
fi

rm -rf "$CLASSES_DIR" "$TEST_CLASSES_DIR"
mkdir -p "$CLASSES_DIR" "$TEST_CLASSES_DIR"

find src/main/java -name "*.java" > /tmp/java-sec-sources.txt
javac -encoding UTF-8 -cp "$LIB_JAR:src/main/java" -d "$CLASSES_DIR" @/tmp/java-sec-sources.txt
rm /tmp/java-sec-sources.txt

find src/test/java -name "*.java" > /tmp/java-sec-test-sources.txt
javac -encoding UTF-8 -cp "$LIB_JAR:$CLASSES_DIR:src/test/java" -d "$TEST_CLASSES_DIR" @/tmp/java-sec-test-sources.txt
rm /tmp/java-sec-test-sources.txt

java -jar "$LIB_JAR" execute \
    --class-path "$CLASSES_DIR:$TEST_CLASSES_DIR" \
    --scan-class-path \
    --disable-banner \
    --details=tree
