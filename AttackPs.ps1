Test with this script your proxy, EDR and NGFW detection capabilities.
Below domain is legitimate domain you can put any domain like or pdf file. The only thing you need to know when you run this
script you should saw pdf file status opened.

Invoke-WebRequest http://www.pdf995.com/samples/pdf.pdf -UserAgent $userAgent
$down = New-Object System.Net.WebClient
$url  = 'http://www.pdf995.com/samples/pdf.pdf';
$file = 'pdf.pdf';
$down.DownloadFile($url,$file);
$exec = New-Object -com shell.application
$exec.shellexecute($file);
