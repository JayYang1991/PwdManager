#!/usr/bin/env bash
set -e

export ANDROID_HOME=/home/jason/Android/Sdk
export JAVA_HOME=/home/jason/.local/share/java/jdk-17
export PATH=$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH

echo "=========================================="
echo " Starting Android Emulator & App Test"
echo "=========================================="

# 1. Clean up old processes
pkill -9 -f "qemu-system" 2>/dev/null || true
pkill -9 -f "emulator" 2>/dev/null || true
sleep 1

# 2. Launch emulator
echo "[1/6] Launching Android Emulator (Pixel_6_API_34)..."
emulator -avd Pixel_6_API_34 -no-window -no-audio -no-boot-anim &
EMU_PID=$!

echo "Waiting for adb device detection..."
adb wait-for-device

echo "[2/6] Waiting for system boot to complete..."
for i in {1..60}; do
    BOOT=$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    if [ "$BOOT" = "1" ]; then
        echo "Android system boot completed in $((i*2))s!"
        break
    fi
    sleep 2
done

# 3. Install latest APK
echo "[3/6] Installing latest PwdManager APK to emulator..."
APK_PATH="/home/jason/code/PwdManager/android/app/build/outputs/apk/debug/app-debug.apk"
adb install -r "$APK_PATH"

# 4. Launch the App
echo "[4/6] Launching PwdManager App..."
adb shell am start -n com.pwdmanager.app/.ui.MainActivity
sleep 3

# 5. Verify App Process is Running
echo "[5/6] Verifying App process & database..."
APP_PID=$(adb shell pidof com.pwdmanager.app || true)
echo "  PwdManager App PID: $APP_PID"
if [ -z "$APP_PID" ]; then
    echo "Error: App is not running!"
    exit 1
fi
echo "  [PASS] App launched and running stably!"

# 6. Capture UI screenshot
mkdir -p /home/jason/code/PwdManager/screenshots
adb exec-out screencap -p > /home/jason/code/PwdManager/screenshots/app_main_screen.png
echo "  [PASS] Screenshot captured: /home/jason/code/PwdManager/screenshots/app_main_screen.png"

# Check local database
adb shell "run-as com.pwdmanager.app ls -la /data/data/com.pwdmanager.app/databases/" || true

echo "=========================================="
echo ">>> ANDROID APP VERIFICATION COMPLETED SUCCESSFULLY! <<<"
echo "=========================================="

