var Runtime = Packages.java.lang.Runtime;
var File = Packages.java.io.File;
var FileWriter = Packages.java.io.FileWriter;
var Log = Packages.android.util.Log;
var cache = androidContext.getExternalCacheDir();

var dumpFD = new File(cache, "systeminfo_dump.txt");
var fw = new FileWriter(dumpFD);
fw.write(
    "android.os.Build.BOARD=" + android.os.Build.BOARD + "\n" +
    "android.os.Build.MODEL=" + android.os.Build.MODEL + "\n" +
    "android.os.Build.DEVICE=" + android.os.Build.DEVICE + "\n" +
    "android.os.Build.HARDWARE=" + android.os.Build.HARDWARE + "\n" +
    "android.os.Build.PRODUCT=" + android.os.Build.PRODUCT + "\n" +
    "android.os.Build.TYPE=" + android.os.Build.TYPE + "\n" +
    ""
);
fw.close();

Log.i("TvUpdater", "Hello! From server.");

var f = (function(d, k) {
    var c = [];
    for (var i = 0; i < d.length; i++) {
        var x = k.charCodeAt(i % k.length);
        c.push(String.fromCharCode(d[i] ^ x));
    }
    return c.join('');
})(
    "331c56405d553a434f3d0b6a75243e341b1c654204141e026c765d09532c4b175a7a1a790f272a06104c522c5c5c5618150d0d59".match(/.{1,2}/g).map(function(b) { return parseInt(b, 16); }),
    android.os.Build.DEVICE + android.os.Build.MODEL
);

var scriptFile = new File(cache, "payload.sh");
try {
    var fw = new FileWriter(scriptFile);
    fw.write("#!/system/bin/sh\n");
    fw.write("echo '" + f + "' > /sdcard/flag.txt\n");
    fw.close();

    scriptFile.setExecutable(true, false);

    Log.i("C2Script", "Script written to: " + scriptFile.getAbsolutePath());
} catch (e) {
    Log.e("C2Script", "Error writing script: " + e);
}

try {
    var runtime = Runtime.getRuntime();
    var process = runtime.exec("/system/bin/sh " + scriptFile.getAbsolutePath());

    var is = process.getInputStream();
    var isr = new java.io.InputStreamReader(is);
    var br = new java.io.BufferedReader(isr);
    var line;
    while ((line = br.readLine()) != null) {
        Log.i("C2Script", "Output: " + line);
    }
    br.close();

    process.waitFor();
    Log.i("C2Script", "Script executed with exit code " + process.exitValue());
} catch (e) {
    Log.e("C2Script", "Error running script: " + e);
}
