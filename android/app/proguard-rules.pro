# Keep native methods and JNI registration
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep all classes in our package
-keep class xyz.moonchan.echproxy.** { *; }

# Keep AndroidX core & notification classes
-keep class androidx.core.app.NotificationCompat** { *; }
