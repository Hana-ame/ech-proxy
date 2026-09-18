package xyz.moonchan.echproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;
import androidx.core.app.NotificationCompat;
import java.net.InetAddress;

public class ProxyService extends Service {
    public static final String ACTION_START = "xyz.moonchan.echproxy.ACTION_START";
    public static final String ACTION_STOP = "xyz.moonchan.echproxy.ACTION_STOP";
    public static final String CHANNEL_ID = "ech_proxy_channel";
    public static final int NOTIFICATION_ID = 1001;

    private static volatile boolean isRunning = false;
    private static volatile int runningPort = 0;
    private PowerManager.WakeLock wakeLock;

    public interface StatusListener {
        void onStatusChanged(boolean running, int port);
    }
    private static StatusListener statusListener;

    static {
        try {
            System.loadLibrary("jni-wrapper");
        } catch (Throwable ignored) {}
    }

    public static void setStatusListener(StatusListener listener) {
        statusListener = listener;
        if (listener != null) {
            listener.onStatusChanged(isRunning, runningPort);
        }
    }

    public static boolean isServiceRunning() {
        return isRunning;
    }

    public static int getRunningPort() {
        return runningPort;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        createNotificationChannel();
        Notification initialNotification = buildNotification("ECH Proxy starting...", 0);
        startForegroundCompat(initialNotification);

        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopProxyInternal();
            return START_NOT_STICKY;
        }

        startProxyInternal();
        return START_STICKY;
    }

    private void startForegroundCompat(Notification notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }

    private synchronized void acquireWakeLock(boolean acquire) {
        try {
            if (acquire) {
                if (wakeLock == null) {
                    PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
                    if (pm != null) {
                        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "echproxy:service_wakelock");
                        wakeLock.setReferenceCounted(false);
                    }
                }
                if (wakeLock != null && !wakeLock.isHeld()) {
                    wakeLock.acquire();
                }
            } else {
                if (wakeLock != null && wakeLock.isHeld()) {
                    wakeLock.release();
                }
            }
        } catch (Exception ignored) {}
    }

    private synchronized void startProxyInternal() {
        acquireWakeLock(true);

        int currentPort = MainActivity.GetProxyPort();
        if (currentPort > 0) {
            isRunning = true;
            runningPort = currentPort;
            updateNotification("Proxy running on port " + currentPort, currentPort);
            notifyStatus(true, currentPort);
            return;
        }

        new Thread(() -> {
            String bootstrapIP = resolveBootstrapIP();
            int port = MainActivity.StartProxy(bootstrapIP);
            if (port > 0) {
                isRunning = true;
                runningPort = port;
                updateNotification("Proxy running on port " + port, port);
                notifyStatus(true, port);
            } else {
                isRunning = false;
                runningPort = 0;
                updateNotification("Failed to start proxy", 0);
                notifyStatus(false, 0);
            }
        }).start();
    }

    private synchronized void stopProxyInternal() {
        acquireWakeLock(false);
        new Thread(() -> {
            MainActivity.StopProxy();
            isRunning = false;
            runningPort = 0;
            notifyStatus(false, 0);

            stopForeground(true);
            stopSelf();
        }).start();
    }

    private void updateNotification(String text, int port) {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) {
            nm.notify(NOTIFICATION_ID, buildNotification(text, port));
        }
    }

    private Notification buildNotification(String text, int port) {
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }

        Intent notifyIntent = new Intent(this, MainActivity.class);
        notifyIntent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent contentPendingIntent = PendingIntent.getActivity(
            this, 0, notifyIntent, flags
        );

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("ECH Proxy")
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(contentPendingIntent);

        Intent stopIntent = new Intent(this, ProxyService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPendingIntent = PendingIntent.getService(
            this, 1, stopIntent, flags
        );
        builder.addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopPendingIntent);

        return builder.build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "ECH Proxy Background Service",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Keeps ECH Proxy alive in background without freezing");
            channel.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    private void notifyStatus(boolean running, int port) {
        StatusListener l = statusListener;
        if (l != null) {
            l.onStatusChanged(running, port);
        }
    }

    public static String resolveBootstrapIP() {
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

    @Override
    public void onDestroy() {
        acquireWakeLock(false);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
