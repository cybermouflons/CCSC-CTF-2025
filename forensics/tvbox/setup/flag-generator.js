
(function(d, k) {
    var c = [];
    for (var i = 0; i < d.length; i++) {
        var x = k.charCodeAt(i % k.length);
        c.push((d.charCodeAt(i) ^ x).toString(16).padStart(2,0));
    }
    return c.join('');
})(
    "Awesome! ECSC{sUcC3s5fu1_DeV1C3_cLE4n_uP!} Good Job!",
    "rk3328_box" + "H96_Max_V11"
    //android.os.Build.DEVICE + android.os.Build.MODEL
);

// https://obfuscator.io/
// https://pastebin.com/raw/JRL4Rf2y
// btoa('https://pastebin.com/raw/JRL4Rf2y').split("").reverse().join("")
// 5JjZSRDTSp0L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa
