$code = @'
using System;
using System.Diagnostics;
public class P {
  public static void Main() {
    var psi = new ProcessStartInfo("wsl.exe", "-l -v");
    psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
    var p = Process.Start(psi);
    if (!p.WaitForExit(20000)) { p.Kill(); Console.WriteLine("TIMEOUT"); return; }
    Console.WriteLine("OUT:" + p.StandardOutput.ReadToEnd());
    Console.WriteLine("ERR:" + p.StandardError.ReadToEnd());
  }
}
'@
Add-Type -TypeDefinition $code -Language CSharp
[P]::Main()
