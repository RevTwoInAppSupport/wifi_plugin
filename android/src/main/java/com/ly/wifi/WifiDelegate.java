package com.ly.wifi;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.NetworkSpecifier;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.support.v4.app.ActivityCompat;
import android.util.Log;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.PluginRegistry;

public class WifiDelegate implements PluginRegistry.RequestPermissionsResultListener {
  private Activity activity;
  private WifiManager wifiManager;
  private PermissionManager permissionManager;
  private static final int REQUEST_ACCESS_FINE_LOCATION_PERMISSION = 1;
  private static final int REQUEST_CHANGE_WIFI_STATE_PERMISSION = 2;
  private static List<Integer> history = new ArrayList<>();
  NetworkChangeReceiver networkReceiver;

  interface PermissionManager {
    boolean isPermissionGranted(String permissionName);

    void askForPermission(String permissionName, int requestCode);
  }

  public WifiDelegate(final Activity activity, final WifiManager wifiManager) {
    this(activity, wifiManager, null, null, new PermissionManager() {

      @Override
      public boolean isPermissionGranted(String permissionName) {
        return ActivityCompat.checkSelfPermission(activity, permissionName)
            == PackageManager.PERMISSION_GRANTED;
      }

      @Override
      public void askForPermission(String permissionName, int requestCode) {
        ActivityCompat.requestPermissions(activity, new String[] {permissionName}, requestCode);
      }
    });
  }

  private MethodChannel.Result result;
  private MethodCall methodCall;

  WifiDelegate(
      Activity activity,
      WifiManager wifiManager,
      MethodChannel.Result result,
      MethodCall methodCall,
      PermissionManager permissionManager) {
    this.activity = activity;
    this.wifiManager = wifiManager;
    this.result = result;
    this.methodCall = methodCall;
    this.permissionManager = permissionManager;
    this.networkReceiver = new NetworkChangeReceiver();
  }

  public void getSSID(MethodCall methodCall, MethodChannel.Result result) {
    if (!setPendingMethodCallAndResult(methodCall, result)) {
      finishWithAlreadyActiveError();
      return;
    }
    launchSSID();
  }

  public void getLevel(MethodCall methodCall, MethodChannel.Result result) {
    if (!setPendingMethodCallAndResult(methodCall, result)) {
      finishWithAlreadyActiveError();
      return;
    }
    launchLevel();
  }

  private void launchSSID() {
    String wifiName =
        wifiManager != null ? wifiManager.getConnectionInfo().getSSID().replace("\"", "") : "";
    if (!wifiName.isEmpty()) {
      result.success(wifiName);
      clearMethodCallAndResult();
    } else {
      finishWithError("unavailable", "wifi name not available.");
    }
  }

  private void launchLevel() {
    int level = wifiManager != null ? wifiManager.getConnectionInfo().getRssi() : 0;
    if (level != 0) {
      if (level <= 0 && level >= -55) {
        result.success(3);
      } else if (level < -55 && level >= -80) {
        result.success(2);
      } else if (level < -80 && level >= -100) {
        result.success(1);
      } else {
        result.success(0);
      }
      clearMethodCallAndResult();
    } else {
      finishWithError("unavailable", "wifi level not available.");
    }
  }

  public void getIP(MethodCall methodCall, MethodChannel.Result result) {
    if (!setPendingMethodCallAndResult(methodCall, result)) {
      finishWithAlreadyActiveError();
      return;
    }
    //launchIP();
    launchIPWifi();
    //launchIPActiveWifi();
  }

  private void launchIPActiveWifi() {
    Log.v("launchIPActiveWifi", "launchIPActiveWifi");
    NetworkInfo info = ((ConnectivityManager) activity.getSystemService(Context.CONNECTIVITY_SERVICE)).getNetworkInfo(ConnectivityManager.TYPE_WIFI);
    if (info != null && info.isConnected()) {
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
        String ipAddress = intIP2StringIP(wifiInfo.getIpAddress());
        result.success(ipAddress);
        clearMethodCallAndResult();
    } else {
      finishWithError("unavailable", "ip not available.");
    }
  }

  private void launchIPWifi() {
    Log.v("launchIPWifi", "launchIPWifi");
    NetworkInfo[] infos = ((ConnectivityManager) activity.getSystemService(Context.CONNECTIVITY_SERVICE)).getAllNetworkInfo();
    for(NetworkInfo info : infos) {
      Log.v("wifiType", info.getTypeName() + ", Connected: " + String.valueOf(info.isConnected()));
      if (info != null && info.isConnected() && info.getType() == ConnectivityManager.TYPE_WIFI) {
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
        String ipAddress = intIP2StringIP(wifiInfo.getIpAddress());
        result.success(ipAddress);
        clearMethodCallAndResult();
        return;
      }
    }
    finishWithError("unavailable", "ip not available.");
  }

  private void launchIP() {
  	Log.v("launchIP", "launchIP");
    NetworkInfo info = ((ConnectivityManager) activity.getSystemService(
        Context.CONNECTIVITY_SERVICE)).getActiveNetworkInfo();
    if (info != null && info.isConnected()) {
      if (info.getType() == ConnectivityManager.TYPE_WIFI) {
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
        String ipAddress = intIP2StringIP(wifiInfo.getIpAddress());
        result.success(ipAddress);
        clearMethodCallAndResult();
      } else {
        String humanType = info.getTypeName();
        finishWithError("unavailable", humanType);
      }
    } else {
      finishWithError("unavailable", "ip not available.");
    }
  }

  private static String intIP2StringIP(int ip) {
    return (ip & 0xFF) + "." +
        ((ip >> 8) & 0xFF) + "." +
        ((ip >> 16) & 0xFF) + "." +
        (ip >> 24 & 0xFF);
  }

  public void getWifiList(MethodCall methodCall, MethodChannel.Result result) {
    if (!setPendingMethodCallAndResult(methodCall, result)) {
      finishWithAlreadyActiveError();
      return;
    }
    if (!permissionManager.isPermissionGranted(Manifest.permission.ACCESS_FINE_LOCATION)) {
      permissionManager.askForPermission(Manifest.permission.ACCESS_FINE_LOCATION,
          REQUEST_ACCESS_FINE_LOCATION_PERMISSION);
      return;
    }
    launchWifiList();
  }

  private void launchWifiList() {
    String key = methodCall.argument("key");
    List<HashMap> list = new ArrayList<>();
    if (wifiManager != null) {
      List<ScanResult> scanResultList = wifiManager.getScanResults();
      for (ScanResult scanResult : scanResultList) {
        int level;
        if (scanResult.level <= 0 && scanResult.level >= -55) {
          level = 3;
        } else if (scanResult.level < -55 && scanResult.level >= -80) {
          level = 2;
        } else if (scanResult.level < -80 && scanResult.level >= -100) {
          level = 1;
        } else {
          level = 0;
        }
        HashMap<String, Object> maps = new HashMap<>();
        if (key.isEmpty()) {
          maps.put("ssid", scanResult.SSID);
          maps.put("level", level);
          maps.put("capabilities", scanResult.capabilities);
          list.add(maps);
        } else {
          if (scanResult.SSID.contains(key)) {
            maps.put("ssid", scanResult.SSID);
            maps.put("level", level);
            list.add(maps);
          }
        }
      }
    }
    result.success(list);
    clearMethodCallAndResult();
  }

  public void removeNetwork(MethodCall methodCall, MethodChannel.Result result) {
    if (!history.isEmpty()) {
      wifiManager.enableNetwork(history.remove(history.size() - 1), true);
      wifiManager.removeNetwork(isExist(wifiManager,methodCall.argument("ssid")).networkId);
      result.success(true);
    } else {
      result.success(false);
    }
    clearMethodCallAndResult();
  }

  public void connection(MethodCall methodCall, MethodChannel.Result result) {
    if (!setPendingMethodCallAndResult(methodCall, result)) {
      finishWithAlreadyActiveError();
      return;
    }
    if (!permissionManager.isPermissionGranted(Manifest.permission.CHANGE_WIFI_STATE)) {
      permissionManager.askForPermission(Manifest.permission.CHANGE_WIFI_STATE,
          REQUEST_ACCESS_FINE_LOCATION_PERMISSION);
      return;
    }

    connection();
  }

  private void connection() {
    String ssid = methodCall.argument("ssid");
    String password = methodCall.argument("password");
    WifiConfiguration wifiConfig = isExist(wifiManager, ssid);
    int netId = -1;
    if (wifiConfig == null) {
      wifiConfig = createWifiConfig(ssid, password);
      netId = wifiManager.addNetwork(wifiConfig);
    } else {
      netId = wifiConfig.networkId;
    }
    if (wifiConfig == null) {
      finishWithError("unavailable", "wifi config is null!");
      return;
    }
    if (netId == -1) {
      result.success(0);
    } else {
      if (wifiManager.getConnectionInfo().getNetworkId() != -1) {
        history.add(wifiManager.getConnectionInfo().getNetworkId());
      }
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
        wifiManager.enableNetwork(netId, true);
        wifiManager.reconnect();
        result.success(1);
        clearMethodCallAndResult();
      } else {
        networkReceiver.connect(netId);
      }
    }
    clearMethodCallAndResult();
  }

  private WifiConfiguration createWifiConfig(String ssid, String Password) {
    WifiConfiguration config = new WifiConfiguration();
    config.SSID = "\"" + ssid + "\"";
    config.allowedAuthAlgorithms.clear();
    config.allowedGroupCiphers.clear();
    config.allowedKeyManagement.clear();
    config.allowedPairwiseCiphers.clear();
    config.allowedProtocols.clear();
    WifiConfiguration tempConfig = isExist(wifiManager, ssid);
    config.preSharedKey = "\"" + Password + "\"";
    config.hiddenSSID = true;
    config.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
    config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
    config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
    config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
    config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
    config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
    config.status = WifiConfiguration.Status.ENABLED;
    return config;
  }

  private WifiConfiguration isExist(WifiManager wifiManager, String ssid) {
    List<WifiConfiguration> existingConfigs = wifiManager.getConfiguredNetworks();
    for (WifiConfiguration existingConfig : existingConfigs) {
      if (existingConfig.SSID.equals("\"" + ssid + "\"")) {
        return existingConfig;
      }
    }
    return null;
  }

  private boolean setPendingMethodCallAndResult(MethodCall methodCall,
      MethodChannel.Result result) {
    if (this.result != null) {
      return false;
    }
    this.methodCall = methodCall;
    this.result = result;
    return true;
  }

  @Override
  public boolean onRequestPermissionsResult(int requestCode, String[] permissions,
      int[] grantResults) {
    boolean permissionGranted =
        grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED;
    switch (requestCode) {
      case REQUEST_ACCESS_FINE_LOCATION_PERMISSION:
        if (permissionGranted) {
          launchWifiList();
        }
        break;
      case REQUEST_CHANGE_WIFI_STATE_PERMISSION:
        if (permissionGranted) {
          connection();
        }
        break;
      default:
        return false;
    }
    if (!permissionGranted) {
      clearMethodCallAndResult();
    }
    return true;
  }

  private void finishWithAlreadyActiveError() {
    finishWithError("already_active", "wifi is already active");
  }

  private void finishWithError(String errorCode, String errorMessage) {
    result.error(errorCode, errorMessage, null);
    clearMethodCallAndResult();
  }

  private void clearMethodCallAndResult() {
    methodCall = null;
    result = null;
  }

  public class NetworkChangeReceiver extends BroadcastReceiver {
    private int netId;
    private boolean willLink = false;

    @Override
    public void onReceive(Context context, Intent intent) {
      NetworkInfo info = intent.getParcelableExtra(ConnectivityManager.EXTRA_NETWORK_INFO);
      if (info.getState() == NetworkInfo.State.DISCONNECTED && willLink) {
        wifiManager.enableNetwork(netId, true);
        wifiManager.reconnect();
        result.success(1);
        willLink = false;
        clearMethodCallAndResult();
      }
    }

    public void connect(int netId) {
      this.netId = netId;
      willLink = true;
      wifiManager.disconnect();
    }
  }
}
