package xyz.moonchan.echproxy;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import java.net.InetAddress;

public class MainActivity extends AppCompatActivity {

    private TextView statusView;
    private Button btnToggle;
    private Button btnOpenBrowser;
    private TextView logView;
    private ScrollView scrollView;
    private Handler handler;

    private static boolean hasOpenedBrowser = false;
    private int currentPort = 0;
    private boolean isRunning = false;

    static {
        try {
            System.loadLibrary("jni-wrapper");
        } catch (Throwable ignored) {}
    }

    // JNI function names match Go //export via jni_wrapper.c
    public static native int StartProxy(String bootstrapIP);
    public static native void StopProxy();
    public static native int GetProxyPort();
    public static native int IsEchReady();
    public static native String GetLogs();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        handler = new Handler(Looper.getMainLooper());

        // Root vertical layout
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#1E1E1E"));

        // Top control panel
        LinearLayout controlPanel = new LinearLayout(this);
        controlPanel.setOrientation(LinearLayout.VERTICAL);
        controlPanel.setPadding(24, 24, 24, 16);
        controlPanel.setBackgroundColor(Color.parseColor("#252526"));

        // Title & Version
        String flavorTag = BuildConfig.ENABLE_FOREGROUND_SERVICE ? "" : " [Lite / No-Perm]";
        TextView titleView = new TextView(this);
        titleView.setText("ECH Proxy v" + BuildConfig.VERSION_NAME + flavorTag + " (build " + BuildConfig.VERSION_CODE + ")");
        titleView.setTextColor(Color.parseColor("#CCCCCC"));
        titleView.setTextSize(14);
        titleView.setTypeface(Typeface.DEFAULT_BOLD);
        controlPanel.addView(titleView);

        // Status line
        statusView = new TextView(this);
        statusView.setText("Status: Initializing...");
        statusView.setTextColor(Color.parseColor("#4EC9B0"));
        statusView.setTextSize(14);
        statusView.setPadding(0, 8, 0, 12);
        controlPanel.addView(statusView);

        // Buttons row
        LinearLayout buttonRow = new LinearLayout(this);
        buttonRow.setOrientation(LinearLayout.HORIZONTAL);

        btnToggle = new Button(this);
        btnToggle.setText("Stop Proxy");
        btnToggle.setOnClickListener(v -> {
            if (isRunning) {
                stopProxy();
            } else {
                startProxy();
            }
        });
        LinearLayout.LayoutParams btnToggleParams = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1.0f);
        btnToggleParams.setMargins(0, 0, 8, 0);
        buttonRow.addView(btnToggle, btnToggleParams);

        btnOpenBrowser = new Button(this);
        btnOpenBrowser.setText("Open Browser");
        btnOpenBrowser.setEnabled(false);
        btnOpenBrowser.setOnClickListener(v -> {
            int port = currentPort > 0 ? currentPort : GetProxyPort();
            if (port > 0) {
                openBrowser(port);
            }
        });
        LinearLayout.LayoutParams btnOpenParams = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1.0f);
        btnOpenParams.setMargins(8, 0, 0, 0);
        buttonRow.addView(btnOpenBrowser, btnOpenParams);

        controlPanel.addView(buttonRow);
        root.addView(controlPanel);

        // Fullscreen log UI below control panel
        scrollView = new ScrollView(this);
        logView = new TextView(this);
        logView.setPadding(20, 16, 20, 16);
        logView.setTextSize(12);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextColor(Color.parseColor("#D4D4D4"));
        scrollView.addView(logView);

        LinearLayout.LayoutParams scrollParams = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f
        );
        root.addView(scrollView, scrollParams);

        setContentView(root);

        if (BuildConfig.ENABLE_FOREGROUND_SERVICE) {
            appendLog("App started (Standard Mode: Foreground Service)");
            checkNotificationPermission();
            checkBatteryOptimizations();

            ProxyService.setStatusListener((running, port) -> {
                runOnUiThread(() -> {
                    this.isRunning = running;
                    this.currentPort = port;
                    updateUIState(running, port);
                    if (running && port > 0 && !hasOpenedBrowser) {
                        hasOpenedBrowser = true;
                        openBrowser(port);
                    }
                });
            });

            startProxy();
        } else {
            appendLog("App started (Lite Mode: No permissions required)");
            startProxy();
        }

        handler.postDelayed(this::updateLogs, 500);
    }

    private void updateUIState(boolean running, int port) {
        if (running && port > 0) {
            String modeStr = BuildConfig.ENABLE_FOREGROUND_SERVICE ? "Foreground Service active" : "Lite Mode (No permissions)";
            statusView.setText("Status: Running on port " + port + " (" + modeStr + ")");
            statusView.setTextColor(Color.parseColor("#4EC9B0"));
            btnToggle.setText("Stop Proxy");
            btnOpenBrowser.setEnabled(true);
        } else {
            statusView.setText("Status: Stopped");
            statusView.setTextColor(Color.parseColor("#F44747"));
            btnToggle.setText("Start Proxy");
            btnOpenBrowser.setEnabled(false);
        }
    }

    private void startProxy() {
        if (BuildConfig.ENABLE_FOREGROUND_SERVICE) {
            appendLog("Starting Foreground Service (anti-freeze)...");
            Intent intent = new Intent(this, ProxyService.class);
            intent.setAction(ProxyService.ACTION_START);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent);
            } else {
                startService(intent);
            }
        } else {
            // Lite Mode: runs directly in background thread with zero permissions
            new Thread(() -> {
                appendLog("Resolving bootstrap IP...");
                String bootstrapIP = resolveBootstrapIP();
                appendLog("Bootstrap IP: " + (bootstrapIP != null ? bootstrapIP : "null"));

                int port = GetProxyPort();
                if (port > 0) {
                    runOnUiThread(() -> {
                        this.isRunning = true;
                        this.currentPort = port;
                        updateUIState(true, port);
                        appendLog("Proxy already running on port " + port);
                        if (!hasOpenedBrowser) {
                            hasOpenedBrowser = true;
                            openBrowser(port);
                        }
                    });
                    return;
                }

                appendLog("Starting proxy (lite thread)...");
                int newPort = StartProxy(bootstrapIP);

                runOnUiThread(() -> {
                    if (newPort > 0) {
                        this.isRunning = true;
                        this.currentPort = newPort;
                        updateUIState(true, newPort);
                        appendLog("Proxy started on port " + newPort);
                        if (!hasOpenedBrowser) {
                            hasOpenedBrowser = true;
                            openBrowser(newPort);
                        }
                    } else {
                        this.isRunning = false;
                        this.currentPort = 0;
                        updateUIState(false, 0);
                        appendLog("ERROR: Failed to start proxy");
                    }
                });
            }).start();
        }
    }

    private void stopProxy() {
        if (BuildConfig.ENABLE_FOREGROUND_SERVICE) {
            appendLog("Stopping Proxy Service...");
            Intent intent = new Intent(this, ProxyService.class);
            intent.setAction(ProxyService.ACTION_STOP);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent);
            } else {
                startService(intent);
            }
        } else {
            appendLog("Stopping proxy...");
            new Thread(() -> {
                StopProxy();
                runOnUiThread(() -> {
                    this.isRunning = false;
                    this.currentPort = 0;
                    updateUIState(false, 0);
                    appendLog("Proxy stopped");
                });
            }).start();
        }
    }

    private String resolveBootstrapIP() {
        try {
            InetAddress[] addresses = InetAddress.getAllByName("moonchan.xyz");
            for (InetAddress addr : addresses) {
                String host = addr.getHostAddress();
                if (host != null && !host.contains(":")) {
                    return host;
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private void checkBatteryOptimizations() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
                if (pm != null && !pm.isIgnoringBatteryOptimizations(getPackageName())) {
                    appendLog("Prompting battery optimization exemption (prevents background sleep/freeze)...");
                    Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivity(intent);
                } else {
                    appendLog("Battery optimization exemption: Active");
                }
            } catch (Exception e) {
                appendLog("Battery optimization check: " + e.getMessage());
            }
        }
    }

    private void checkNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 101);
            }
        }
    }

    private void updateLogs() {
        if (isFinishing() || isDestroyed()) return;
        String logs = GetLogs();
        if (logs != null && !logs.equals(logView.getText().toString())) {
            logView.setText(logs);
            scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
        }
        handler.postDelayed(this::updateLogs, 500);
    }

    private void appendLog(String msg) {
        handler.post(() -> {
            logView.append(msg + "\n");
            scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }

    private void openBrowser(int port) {
        String url = "https://l.moonchan.xyz:" + port + "/";
        appendLog("Opening browser: " + url);
        appendLog("Note: DNS must resolve l.moonchan.xyz to 127.0.0.1");
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            startActivity(intent);
        } catch (Exception e) {
            appendLog("ERROR: " + e.getMessage());
        }
    }

    @Override
    protected void onDestroy() {
        if (BuildConfig.ENABLE_FOREGROUND_SERVICE) {
            ProxyService.setStatusListener(null);
        }
        super.onDestroy();
    }
}
